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

        let envelope: HostEnvelope = match serde_json::from_slice(&body) {
            Ok(e) => e,
            Err(e) => {
                let resp = HostResponse::failure(
                    "unknown",
                    error_code::INVALID_JSON,
                    format!("Could not parse incoming JSON envelope: {e}"),
                );
                write_response(&mut stdout, &resp)?;
                continue;
            }
        };

        let responses = commands::handle(&state, envelope);
        for response in responses {
            write_response(&mut stdout, &response)?;
        }
    }
}

fn write_response<W: Write>(writer: &mut W, response: &HostResponse) -> anyhow::Result<()> {
    let body = serde_json::to_vec(response)?;
    framing::write_frame(writer, &body)?;
    Ok(())
}
