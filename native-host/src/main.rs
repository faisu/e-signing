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
use protocol::{error_code, HostCmd, HostEnvelope, HostResponse};

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
            payload_summary = %summarize_request_payload(envelope.cmd, &envelope.payload),
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
                    response_payload = %summarize_response_payload(&response),
                    "sending response"
                );
            } else if let Some(err) = response.error.as_ref() {
                tracing::warn!(
                    request_id = %response.id,
                    ok = false,
                    error_code = %err.code,
                    error_message_len = err.message.len(),
                    error_message_preview = %preview_head_tail(&err.message, 24, 24),
                    response_payload = %summarize_response_payload(&response),
                    "sending error response"
                );
            } else {
                tracing::warn!(
                    request_id = %response.id,
                    ok = false,
                    response_payload = %summarize_response_payload(&response),
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

fn summarize_request_payload(cmd: HostCmd, payload: &serde_json::Value) -> String {
    match cmd {
        HostCmd::SignPdfStart => {
            let job_id = payload.get("jobId").and_then(serde_json::Value::as_str).unwrap_or("");
            let total_chunks = payload
                .get("totalChunks")
                .and_then(serde_json::Value::as_u64)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string());
            let slot_id = payload
                .get("slotId")
                .and_then(serde_json::Value::as_u64)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string());
            let cert_id = payload
                .get("certId")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            format!(
                "job_id={job_id},total_chunks={total_chunks},slot_id={slot_id},cert_id_present={},cert_id_len={},cert_id_preview={}",
                !cert_id.is_empty(),
                cert_id.len(),
                preview_head_tail(cert_id, 8, 8)
            )
        }
        HostCmd::SignPdfChunk => {
            let job_id = payload.get("jobId").and_then(serde_json::Value::as_str).unwrap_or("");
            let index = payload
                .get("index")
                .and_then(serde_json::Value::as_u64)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a".to_string());
            let chunk_base64 = payload
                .get("chunkBase64")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            format!(
                "job_id={job_id},index={index},chunk_base64_len={},chunk_base64_preview={}",
                chunk_base64.len(),
                preview_head_tail(chunk_base64, 8, 8)
            )
        }
        HostCmd::SignPdfEnd => {
            let job_id = payload.get("jobId").and_then(serde_json::Value::as_str).unwrap_or("");
            format!("job_id={job_id}")
        }
        _ => compact_json(payload, 280),
    }
}

fn summarize_response_payload(response: &HostResponse) -> String {
    if response.ok {
        match response.result.as_ref() {
            Some(result) => {
                let result_type = result
                    .get("resultType")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("none");
                let job_id = result
                    .get("jobId")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let chunk = result
                    .get("chunk")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let index = result
                    .get("index")
                    .and_then(serde_json::Value::as_u64)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "n/a".to_string());
                let total_chunks = result
                    .get("totalChunks")
                    .and_then(serde_json::Value::as_u64)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "n/a".to_string());
                format!(
                    "result_type={result_type},job_id={job_id},chunk_len={},chunk_preview={},index={index},total_chunks={total_chunks},json={}",
                    chunk.len(),
                    preview_head_tail(chunk, 8, 8),
                    compact_json(result, 220)
                )
            }
            None => "ok=true,result=none".to_string(),
        }
    } else {
        match response.error.as_ref() {
            Some(err) => format!(
                "ok=false,error_code={},error_message_len={},error_message_preview={}",
                err.code,
                err.message.len(),
                preview_head_tail(&err.message, 24, 24)
            ),
            None => "ok=false,error=none".to_string(),
        }
    }
}

fn compact_json(value: &serde_json::Value, max_len: usize) -> String {
    let encoded = serde_json::to_string(value).unwrap_or_else(|_| "\"<unserializable>\"".to_string());
    truncate_middle(&encoded, max_len)
}

fn preview_head_tail(value: &str, head: usize, tail: usize) -> String {
    truncate_middle(value, head + tail + 3)
}

fn truncate_middle(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }
    if max_len <= 3 {
        return "...".to_string();
    }
    let prefix_len = (max_len - 3) / 2;
    let suffix_len = max_len - 3 - prefix_len;
    let head: String = value.chars().take(prefix_len).collect();
    let tail_chars: Vec<char> = value.chars().rev().take(suffix_len).collect();
    let tail: String = tail_chars.into_iter().rev().collect();
    format!("{head}...{tail}")
}
