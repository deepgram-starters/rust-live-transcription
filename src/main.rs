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
use deepgram::{
    common::options::{Encoding, Language, Model, Options},
    Deepgram,
};
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

// ============================================================================
// CONFIGURATION
// ============================================================================

#[derive(Clone)]
struct Config {
    deepgram_api_key: String,
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

/// Maps an encoding query-parameter string to the SDK's [`Encoding`] enum,
/// falling back to a custom encoding for any value the SDK does not model.
fn map_encoding(value: &str) -> Encoding {
    match value {
        "linear16" => Encoding::Linear16,
        "linear32" => Encoding::Linear32,
        "flac" => Encoding::Flac,
        "mulaw" => Encoding::Mulaw,
        "amr-nb" => Encoding::AmrNb,
        "amr-wb" => Encoding::AmrWb,
        "opus" => Encoding::Opus,
        "speex" => Encoding::Speex,
        "g729" => Encoding::G729,
        other => Encoding::CustomEncoding(other.to_string()),
    }
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
///
/// The Deepgram side is driven entirely by the official `deepgram` crate's
/// live-transcription [`WebsocketHandle`](deepgram::listen::websocket). Audio
/// frames arriving from the browser are forwarded to Deepgram via
/// `send_data`, JSON control messages are mapped onto the handle's
/// `keep_alive` / `finalize` / `close_stream` helpers, and responses coming
/// back from Deepgram are decoded into the SDK's typed
/// [`StreamResponse`](deepgram::common::stream_response::StreamResponse) and
/// re-encoded as JSON before being forwarded to the browser.
///
/// Note this is a lossy round-trip, not a byte-for-shape passthrough:
/// `StreamResponse` is a partial, `#[non_exhaustive]`, `#[serde(untagged)]`
/// model (it only covers Results, Metadata, SpeechStarted and UtteranceEnd),
/// so fields it does not model are dropped and message types it cannot decode
/// are not preserved (see the receive loop below).
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

    // Resolve transcription options from the forwarded query parameters,
    // preserving the previous defaults.
    let model = params
        .get("model")
        .cloned()
        .unwrap_or_else(|| "nova-3".to_string());
    let language = params
        .get("language")
        .cloned()
        .unwrap_or_else(|| "en".to_string());
    let encoding = params
        .get("encoding")
        .cloned()
        .unwrap_or_else(|| "linear16".to_string());
    let sample_rate: u32 = params
        .get("sample_rate")
        .and_then(|s| s.parse().ok())
        .unwrap_or(16000);
    let channels: u16 = params
        .get("channels")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let smart_format = params.get("smart_format").map(|s| s == "true").unwrap_or(true);
    let punctuate = params.get("punctuate").map(|s| s == "true").unwrap_or(true);
    let diarize = params.get("diarize").map(|s| s == "true").unwrap_or(false);
    let filler_words = params.get("filler_words").map(|s| s == "true").unwrap_or(false);

    println!(
        "Connecting to Deepgram STT: model={}, language={}, encoding={}, sample_rate={}, channels={}",
        model, language, encoding, sample_rate, channels
    );

    let options = Options::builder()
        .model(Model::from(model))
        .language(Language::from(language))
        .smart_format(smart_format)
        .punctuate(punctuate)
        .diarize(diarize)
        .filler_words(filler_words)
        .build();

    // Establish the Deepgram live-transcription websocket via the SDK.
    let dg = match Deepgram::new(&state.config.deepgram_api_key) {
        Ok(dg) => dg,
        Err(e) => {
            eprintln!("Failed to initialize Deepgram client: {e}");
            close_client(&client_sender, 1011, "Failed to connect to Deepgram").await;
            remove_connection(&state, &client_sender).await;
            return;
        }
    };

    let mut dg_handle = match dg
        .transcription()
        .stream_request_with_options(options)
        .encoding(map_encoding(&encoding))
        .sample_rate(sample_rate)
        .channels(channels)
        .handle()
        .await
    {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("Failed to connect to Deepgram: {e}");
            close_client(&client_sender, 1011, "Failed to connect to Deepgram").await;
            remove_connection(&state, &client_sender).await;
            return;
        }
    };

    println!("Connected to Deepgram STT API");

    let mut client_to_dg_count: u64 = 0;
    let mut dg_to_client_count: u64 = 0;

    // Single-task proxy loop: select over incoming client messages and
    // Deepgram responses. The SDK handle is not splittable, so both
    // directions share one task via `tokio::select!`.
    loop {
        tokio::select! {
            client_msg = client_receiver.next() => {
                match client_msg {
                    Some(Ok(Message::Binary(data))) => {
                        client_to_dg_count += 1;
                        if client_to_dg_count % 10 == 0 {
                            println!(
                                "[client->deepgram] message #{} (binary: true, size: {})",
                                client_to_dg_count,
                                data.len()
                            );
                        }
                        if dg_handle.send_data(data.to_vec()).await.is_err() {
                            eprintln!("[client->deepgram] send error");
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => {
                        client_to_dg_count += 1;
                        println!(
                            "[client->deepgram] message #{} (binary: false, size: {})",
                            client_to_dg_count,
                            text.len()
                        );
                        // Map known control messages onto the SDK handle.
                        let text = text.to_string();
                        let kind = serde_json::from_str::<serde_json::Value>(&text)
                            .ok()
                            .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(String::from));
                        match kind.as_deref() {
                            Some("KeepAlive") => {
                                let _ = dg_handle.keep_alive().await;
                            }
                            Some("Finalize") => {
                                let _ = dg_handle.finalize().await;
                            }
                            Some("CloseStream") => {
                                let _ = dg_handle.close_stream().await;
                                break;
                            }
                            _ => {
                                // Unknown control message; nothing to forward.
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        println!("[client->deepgram] client closed connection");
                        break;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        eprintln!("[client->deepgram] read error: {e}");
                        break;
                    }
                }
            }
            dg_msg = dg_handle.receive() => {
                match dg_msg {
                    Some(Ok(response)) => {
                        dg_to_client_count += 1;
                        match serde_json::to_string(&response) {
                            Ok(json) => {
                                if dg_to_client_count % 10 == 0 {
                                    println!(
                                        "[deepgram->client] message #{} (size: {})",
                                        dg_to_client_count,
                                        json.len()
                                    );
                                }
                                let mut sender = client_sender.lock().await;
                                if sender.send(Message::Text(json.into())).await.is_err() {
                                    eprintln!("[deepgram->client] write error");
                                    break;
                                }
                            }
                            Err(e) => eprintln!("[deepgram->client] serialize error: {e}"),
                        }
                    }
                    Some(Err(e)) => {
                        // Known limitation: because StreamResponse is a closed,
                        // #[non_exhaustive] #[serde(untagged)] enum, a frame the
                        // SDK can't decode surfaces here as Some(Err(..)) — the
                        // same shape as a real transport error, which the opaque
                        // DeepgramError does not let us distinguish. We treat
                        // both as terminal and end the session. On the nova-3
                        // happy path this does not fire (Results and the final
                        // Metadata are both modeled); a newly added Deepgram
                        // message type would end the session until the SDK models
                        // it.
                        eprintln!("[deepgram->client] Deepgram error: {e}");
                        break;
                    }
                    None => {
                        println!("[deepgram->client] Deepgram closed connection");
                        break;
                    }
                }
            }
        }
    }

    // Clean up: close the Deepgram stream and the client connection.
    println!("Proxy session ending, closing connections");
    let _ = dg_handle.close_stream().await;
    close_client(&client_sender, 1000, "").await;

    // Remove from active connections
    remove_connection(&state, &client_sender).await;
}

/// Sends a close frame to the client connection, ignoring any send error.
async fn close_client(
    sender: &Arc<Mutex<SplitSink<WebSocket, Message>>>,
    code: u16,
    reason: &str,
) {
    let mut sender = sender.lock().await;
    let _ = sender
        .send(Message::Close(Some(axum::extract::ws::CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await;
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
