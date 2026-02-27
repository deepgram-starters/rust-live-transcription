/**
 * Rust Live Transcription Starter - Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Live Transcription API.
 * Forwards all messages (JSON and binary) bidirectionally between client and Deepgram.
 *
 * Routes:
 *   GET  /api/session              - Issue JWT session token
 *   WS   /api/live-transcription   - WebSocket proxy to Deepgram STT (auth required)
 *   GET  /api/metadata             - Project metadata from deepgram.toml
 *   GET  /health                   - Health check
 */

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use chrono::Utc;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Mutex;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite;
use tower_http::cors::{Any, CorsLayer};
use url::Url;

// ============================================================================
// CONFIGURATION
// ============================================================================

#[derive(Clone)]
struct Config {
    deepgram_api_key: String,
    deepgram_stt_url: String,
    port: u16,
    host: String,
    session_secret: Vec<u8>,
}

fn load_config() -> Config {
    let _ = dotenvy::dotenv();

    let api_key = env::var("DEEPGRAM_API_KEY").unwrap_or_else(|_| {
        eprintln!(
            "ERROR: DEEPGRAM_API_KEY environment variable is required\n\
             Please copy sample.env to .env and add your API key"
        );
        std::process::exit(1);
    });

    let port = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8081u16);

    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

    let secret = match env::var("SESSION_SECRET") {
        Ok(s) if !s.is_empty() => s.into_bytes(),
        _ => {
            let mut buf = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut buf);
            buf.to_vec()
        }
    };

    Config {
        deepgram_api_key: api_key,
        deepgram_stt_url: "wss://api.deepgram.com/v1/listen".to_string(),
        port,
        host,
        session_secret: secret,
    }
}

// ============================================================================
// APPLICATION STATE
// ============================================================================

struct AppState {
    config: Config,
    /// Tracks active client WebSocket connections for graceful shutdown.
    /// Each entry holds a sender half that can be used to close the connection.
    active_connections: Mutex<Vec<Arc<Mutex<SplitSink<WebSocket, Message>>>>>,
}

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

const JWT_EXPIRY_SECS: i64 = 3600; // 1 hour

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iat: i64,
    exp: i64,
}

/// Creates a signed JWT with a 1-hour expiry.
fn issue_token(secret: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        iat: now,
        exp: now + JWT_EXPIRY_SECS,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
}

/// Verifies a JWT token string and returns an error if invalid.
fn validate_token(token_str: &str, secret: &[u8]) -> Result<(), jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims = std::collections::HashSet::new();
    validation.validate_exp = true;
    decode::<Claims>(token_str, &DecodingKey::from_secret(secret), &validation)?;
    Ok(())
}

/// Extracts and validates a JWT from the `access_token.<jwt>` subprotocol.
/// Returns the full subprotocol string if valid, None if invalid.
fn validate_ws_token(protocols: &[String], secret: &[u8]) -> Option<String> {
    for proto in protocols {
        if let Some(token_str) = proto.strip_prefix("access_token.") {
            if validate_token(token_str, secret).is_ok() {
                return Some(proto.clone());
            }
        }
    }
    None
}

// ============================================================================
// METADATA - deepgram.toml parsing
// ============================================================================

#[derive(Deserialize)]
struct TomlConfig {
    meta: Option<toml::Value>,
}

/// Reads and parses the [meta] section from deepgram.toml.
fn load_metadata() -> Result<serde_json::Value, String> {
    let content =
        std::fs::read_to_string("deepgram.toml").map_err(|e| format!("Failed to read deepgram.toml: {e}"))?;
    let config: TomlConfig =
        toml::from_str(&content).map_err(|e| format!("Failed to parse deepgram.toml: {e}"))?;
    let meta = config
        .meta
        .ok_or_else(|| "Missing [meta] section in deepgram.toml".to_string())?;
    // Convert TOML value to JSON value
    let json_str =
        serde_json::to_string(&meta).map_err(|e| format!("Failed to serialize metadata: {e}"))?;
    serde_json::from_str(&json_str).map_err(|e| format!("Failed to parse metadata JSON: {e}"))
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

/// GET /api/session - Issues a JWT session token.
async fn handle_session(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match issue_token(&state.config.session_secret) {
        Ok(token) => {
            let body = serde_json::json!({ "token": token });
            (StatusCode::OK, Json(body))
        }
        Err(e) => {
            eprintln!("Failed to issue token: {e}");
            let body = serde_json::json!({
                "error": "INTERNAL_SERVER_ERROR",
                "message": "Failed to issue session token"
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(body))
        }
    }
}

/// GET /api/metadata - Returns the [meta] section from deepgram.toml.
async fn handle_metadata() -> impl IntoResponse {
    match load_metadata() {
        Ok(meta) => (StatusCode::OK, Json(meta)),
        Err(e) => {
            eprintln!("Error reading metadata: {e}");
            let body = serde_json::json!({
                "error": "INTERNAL_SERVER_ERROR",
                "message": format!("Failed to read metadata from deepgram.toml: {e}")
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(body))
        }
    }
}

/// GET /health - Returns a simple health check response.
async fn handle_health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

// ============================================================================
// WEBSOCKET PROXY
// ============================================================================

/// Builds the Deepgram WebSocket URL with query parameters forwarded from the client request.
fn build_deepgram_url(base_url: &str, params: &HashMap<String, String>) -> String {
    let mut url = Url::parse(base_url).expect("Invalid Deepgram base URL");

    let defaults: Vec<(&str, &str)> = vec![
        ("model", "nova-3"),
        ("language", "en"),
        ("smart_format", "true"),
        ("punctuate", "true"),
        ("diarize", "false"),
        ("filler_words", "false"),
        ("encoding", "linear16"),
        ("sample_rate", "16000"),
        ("channels", "1"),
    ];

    for (name, default_val) in &defaults {
        let val = params.get(*name).map(|s| s.as_str()).unwrap_or(default_val);
        url.query_pairs_mut().append_pair(name, val);
    }

    url.to_string()
}

/// Parses WebSocket subprotocols from the Sec-WebSocket-Protocol header.
fn parse_subprotocols(header_value: Option<&HeaderValue>) -> Vec<String> {
    match header_value {
        Some(val) => val
            .to_str()
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        None => vec![],
    }
}

/// WS /api/live-transcription - WebSocket proxy to Deepgram.
/// Authenticates via JWT subprotocol, then creates a bidirectional proxy to Deepgram.
async fn handle_live_transcription(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: axum::http::HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    println!("WebSocket upgrade request for: /api/live-transcription");

    // Extract and validate JWT from access_token.<jwt> subprotocol.
    let protocols = parse_subprotocols(headers.get("sec-websocket-protocol"));
    let valid_proto = match validate_ws_token(&protocols, &state.config.session_secret) {
        Some(proto) => proto,
        None => {
            println!("WebSocket auth failed: invalid or missing token");
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
    };

    println!("Backend handling /api/live-transcription WebSocket (authenticated)");

    // Accept the WebSocket connection, echoing back the validated subprotocol
    ws.protocols([valid_proto])
        .on_upgrade(move |socket| handle_ws_proxy(socket, state, params))
        .into_response()
}

/// Handles the bidirectional WebSocket proxy between client and Deepgram.
async fn handle_ws_proxy(
    client_ws: WebSocket,
    state: Arc<AppState>,
    params: HashMap<String, String>,
) {
    println!("Client connected to /api/live-transcription");

    // Split client WebSocket into sender and receiver
    let (client_sender, mut client_receiver) = client_ws.split();
    let client_sender = Arc::new(Mutex::new(client_sender));

    // Track the connection for graceful shutdown
    {
        let mut conns = state.active_connections.lock().await;
        conns.push(client_sender.clone());
    }

    // Build Deepgram URL with forwarded query parameters
    let deepgram_url = build_deepgram_url(&state.config.deepgram_stt_url, &params);

    let model = params.get("model").map(|s| s.as_str()).unwrap_or("nova-3");
    let language = params.get("language").map(|s| s.as_str()).unwrap_or("en");
    let encoding = params.get("encoding").map(|s| s.as_str()).unwrap_or("linear16");
    let sample_rate = params
        .get("sample_rate")
        .map(|s| s.as_str())
        .unwrap_or("16000");
    let channels = params.get("channels").map(|s| s.as_str()).unwrap_or("1");

    println!(
        "Connecting to Deepgram STT: model={}, language={}, encoding={}, sample_rate={}, channels={}",
        model, language, encoding, sample_rate, channels
    );

    // Connect to Deepgram with API key auth
    let mut request = tungstenite::http::Request::builder()
        .uri(&deepgram_url)
        .header("Authorization", format!("Token {}", state.config.deepgram_api_key))
        .header("Host", "api.deepgram.com")
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .expect("Failed to build Deepgram WebSocket request");

    // Workaround: tungstenite requires a valid URI
    *request.uri_mut() = deepgram_url.parse().expect("Failed to parse Deepgram URL");

    let dg_conn = match connect_async(request).await {
        Ok((ws_stream, _)) => ws_stream,
        Err(e) => {
            eprintln!("Failed to connect to Deepgram: {e}");
            let mut sender = client_sender.lock().await;
            let _ = sender
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 1011,
                    reason: "Failed to connect to Deepgram".into(),
                })))
                .await;
            // Remove from active connections
            remove_connection(&state, &client_sender).await;
            return;
        }
    };

    println!("Connected to Deepgram STT API");

    // Split Deepgram WebSocket into sender and receiver
    let (dg_sender, mut dg_receiver) = dg_conn.split();
    let dg_sender = Arc::new(Mutex::new(dg_sender));

    // Message counters for logging
    let dg_to_client_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let client_to_dg_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Task 1: Forward messages from Deepgram to client
    let client_sender_clone = client_sender.clone();
    let dg_to_client_count_clone = dg_to_client_count.clone();
    let dg_to_client = tokio::spawn(async move {
        while let Some(msg) = dg_receiver.next().await {
            match msg {
                Ok(tungstenite::Message::Text(text)) => {
                    let count = dg_to_client_count_clone
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        + 1;
                    println!(
                        "[deepgram->client] message #{} (binary: false, size: {})",
                        count,
                        text.len()
                    );
                    let mut sender = client_sender_clone.lock().await;
                    if sender.send(Message::Text(text.to_string().into())).await.is_err() {
                        eprintln!("[deepgram->client] write error");
                        break;
                    }
                }
                Ok(tungstenite::Message::Binary(data)) => {
                    let count = dg_to_client_count_clone
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        + 1;
                    if count % 10 == 0 {
                        println!(
                            "[deepgram->client] message #{} (binary: true, size: {})",
                            count,
                            data.len()
                        );
                    }
                    let mut sender = client_sender_clone.lock().await;
                    if sender.send(Message::Binary(data.to_vec().into())).await.is_err() {
                        eprintln!("[deepgram->client] write error");
                        break;
                    }
                }
                Ok(tungstenite::Message::Close(_)) => {
                    println!("[deepgram->client] Deepgram closed connection");
                    break;
                }
                Ok(tungstenite::Message::Ping(data)) => {
                    let mut sender = client_sender_clone.lock().await;
                    let _ = sender.send(Message::Ping(data.to_vec().into())).await;
                }
                Ok(tungstenite::Message::Pong(_)) => {}
                Ok(tungstenite::Message::Frame(_)) => {}
                Err(e) => {
                    eprintln!("[deepgram->client] read error: {e}");
                    break;
                }
            }
        }
    });

    // Task 2: Forward messages from client to Deepgram
    let dg_sender_clone = dg_sender.clone();
    let client_to_dg_count_clone = client_to_dg_count.clone();
    let client_to_dg = tokio::spawn(async move {
        while let Some(msg) = client_receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    let count = client_to_dg_count_clone
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        + 1;
                    println!(
                        "[client->deepgram] message #{} (binary: false, size: {})",
                        count,
                        text.len()
                    );
                    let mut sender = dg_sender_clone.lock().await;
                    if sender
                        .send(tungstenite::Message::Text(text.to_string().into()))
                        .await
                        .is_err()
                    {
                        eprintln!("[client->deepgram] write error");
                        break;
                    }
                }
                Ok(Message::Binary(data)) => {
                    let count = client_to_dg_count_clone
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                        + 1;
                    if count % 10 == 0 {
                        println!(
                            "[client->deepgram] message #{} (binary: true, size: {})",
                            count,
                            data.len()
                        );
                    }
                    let mut sender = dg_sender_clone.lock().await;
                    if sender
                        .send(tungstenite::Message::Binary(data.to_vec().into()))
                        .await
                        .is_err()
                    {
                        eprintln!("[client->deepgram] write error");
                        break;
                    }
                }
                Ok(Message::Close(_)) => {
                    println!("[client->deepgram] client closed connection");
                    break;
                }
                Ok(Message::Ping(data)) => {
                    let mut sender = dg_sender_clone.lock().await;
                    let _ = sender
                        .send(tungstenite::Message::Ping(data.to_vec().into()))
                        .await;
                }
                Ok(Message::Pong(_)) => {}
                Err(e) => {
                    eprintln!("[client->deepgram] read error: {e}");
                    break;
                }
            }
        }
    });

    // Wait for either direction to finish (indicates one side closed)
    tokio::select! {
        _ = dg_to_client => {},
        _ = client_to_dg => {},
    }

    // Clean up: close both connections
    println!("Proxy session ending, closing connections");

    {
        let mut sender = client_sender.lock().await;
        let _ = sender
            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                code: 1000,
                reason: "".into(),
            })))
            .await;
    }

    {
        let mut sender = dg_sender.lock().await;
        let _ = sender
            .send(tungstenite::Message::Close(Some(
                tungstenite::protocol::CloseFrame {
                    code: tungstenite::protocol::frame::coding::CloseCode::Normal,
                    reason: "Client disconnected".into(),
                },
            )))
            .await;
    }

    // Remove from active connections
    remove_connection(&state, &client_sender).await;
}

/// Removes a connection from the active connections list.
async fn remove_connection(
    state: &Arc<AppState>,
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
) {
    let mut conns = state.active_connections.lock().await;
    conns.retain(|s| !Arc::ptr_eq(s, sender));
}

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

/// Waits for SIGTERM or SIGINT, then closes all active WebSocket connections.
async fn shutdown_signal(state: Arc<AppState>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => println!("\nSIGINT signal received: starting graceful shutdown..."),
        _ = terminate => println!("\nSIGTERM signal received: starting graceful shutdown..."),
    }

    // Close all active WebSocket connections
    let conns = state.active_connections.lock().await;
    println!("Closing {} active WebSocket connection(s)...", conns.len());

    for sender in conns.iter() {
        let mut sender = sender.lock().await;
        let _ = sender
            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                code: 1001,
                reason: "Server shutting down".into(),
            })))
            .await;
    }

    println!("Shutdown complete");
}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() {
    let config = load_config();
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("Invalid host:port");

    let secret_hex = hex::encode(&config.session_secret[..8.min(config.session_secret.len())]);

    let state = Arc::new(AppState {
        config,
        active_connections: Mutex::new(Vec::new()),
    });

    // CORS middleware
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build the Axum router
    let app = Router::new()
        .route("/api/session", get(handle_session))
        .route("/api/metadata", get(handle_metadata))
        .route("/api/live-transcription", get(handle_live_transcription))
        .route("/health", get(handle_health))
        .layer(cors)
        .with_state(state.clone());

    // Bind to the address
    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    println!();
    println!("{}", "=".repeat(70));
    println!("Backend API Server running at http://localhost:{}", addr.port());
    println!();
    println!("  GET  /api/session");
    println!("  WS   /api/live-transcription (auth required)");
    println!("  GET  /api/metadata");
    println!("  GET  /health");
    println!();
    println!("Session secret: {}... (first 8 bytes)", secret_hex);
    println!("{}", "=".repeat(70));
    println!();

    // Start the server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state))
        .await
        .expect("Server failed");
}
