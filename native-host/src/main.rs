//! AutoDCR Chrome native messaging host (Rust replacement for the Node host).
//!
//! Wire contract: 4-byte little-endian length prefix + UTF-8 JSON envelope.
//! See `docs/CHROME_EXTENSION_SPEC.md` for the higher-level contract.

mod commands;
mod config;
mod framing;
mod logging;
mod pdf;
mod pin;
mod pkcs11;
mod protocol;
mod token_detection;

use std::io::{self, BufWriter, Write};

use commands::State;
use protocol::{error_code, HostEnvelope, HostResponse};

fn main() {
    let cfg = config::load().unwrap_or_else(|e| {
        eprintln!("[bridge] config load failed, using defaults: {e:?}");
        config::Config::default()
    });

    // Keep the file appender alive until process exit.
    let _log_guard = logging::init(&cfg).ok();

    if let Err(e) = run(cfg) {
        tracing::error!("fatal: {e:?}");
        eprintln!("[bridge] fatal: {e:?}");
        std::process::exit(1);
    }
}

fn run(cfg: config::Config) -> anyhow::Result<()> {
    let state = State::new(cfg);
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = BufWriter::new(stdout.lock());

    loop {
        let body = match framing::read_frame(&mut stdin) {
            Ok(Some(b)) => b,
            Ok(None) => {
                tracing::info!("port closed (EOF)");
                return Ok(());
            }
            Err(framing::FrameError::TooLarge { limit, actual }) => {
                tracing::warn!(
                    limit,
                    actual,
                    "received oversized native message; sending MSG_TOO_LARGE response"
                );
                let resp = HostResponse::failure(
                    "unknown",
                    error_code::MSG_TOO_LARGE,
                    format!("Message exceeded {limit} byte cap (got {actual})."),
                );
                write_response(&mut stdout, &resp)?;
                continue;
            }
            Err(e) => {
                tracing::error!("frame read failed: {e:?}");
                return Err(e.into());
            }
        };
        tracing::debug!(bytes = body.len(), "native frame received");

        let envelope: HostEnvelope = match serde_json::from_slice(&body) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(bytes = body.len(), error = %e, "invalid JSON envelope");
                let resp = HostResponse::failure(
                    "unknown",
                    error_code::INVALID_JSON,
                    format!("Could not parse incoming JSON envelope: {e}"),
                );
                write_response(&mut stdout, &resp)?;
                continue;
            }
        };
        tracing::info!(
            request_id = %envelope.id,
            cmd = ?envelope.cmd,
            payload_type = %payload_kind(&envelope.payload),
            "request accepted"
        );

        let responses = commands::handle(&state, envelope);
        tracing::debug!(
            response_count = responses.len(),
            "command handler produced responses"
        );
        for response in responses {
            if response.ok {
                tracing::info!(
                    request_id = %response.id,
                    ok = true,
                    "sending response"
                );
            } else if let Some(err) = response.error.as_ref() {
                tracing::warn!(
                    request_id = %response.id,
                    ok = false,
                    error_code = %err.code,
                    "sending error response"
                );
            } else {
                tracing::warn!(
                    request_id = %response.id,
                    ok = false,
                    "sending error response without explicit error payload"
                );
            }
            write_response(&mut stdout, &response)?;
        }
    }
}

fn write_response<W: Write>(writer: &mut W, response: &HostResponse) -> anyhow::Result<()> {
    let body = serde_json::to_vec(response)?;
    tracing::debug!(
        request_id = %response.id,
        bytes = body.len(),
        "response encoded"
    );
    framing::write_frame(writer, &body)?;
    Ok(())
}

fn payload_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
