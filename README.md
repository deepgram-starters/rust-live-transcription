# Rust Live Transcription

Get started using Deepgram's Live Transcription with this Rust demo app

## Quick Start

Click the button below to fork the repo:

[![Fork on GitHub](https://img.shields.io/badge/Fork_on_GitHub-blue?logo=github)](https://github.com/deepgram-starters/rust-live-transcription/fork)

## Local Development

### Makefile (Recommended)

```bash
make init
cp sample.env .env  # Add your DEEPGRAM_API_KEY
make start
```

Open [http://localhost:8080](http://localhost:8080) in your browser.

## Custom Endpoint

`DEEPGRAM_BASE_URL` can point the starter at a Deepgram-compatible endpoint. It
must use `https://` or `wss://` so the API key remains encrypted in transit.
For a local test endpoint only, set `DEEPGRAM_ALLOW_INSECURE_BASE_URL=1` with
an `http://` or `ws://` URL. Never use that override outside local testing.

## License

MIT - See [LICENSE](./LICENSE)
