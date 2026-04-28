//! Tracing setup. The host writes structured logs to a per-user file because
//! Chrome captures stderr but does not surface it to the user. stdout is
//! reserved exclusively for length-prefixed JSON frames.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::config::{log_dir, Config};

/// Initialise tracing. Returns a [`WorkerGuard`] that must be kept alive for
/// the lifetime of the process so the file appender flushes cleanly.
pub fn init(cfg: &Config) -> Result<WorkerGuard> {
    let dir: PathBuf = log_dir(cfg)?;
    fs::create_dir_all(&dir).with_context(|| format!("create log dir {}", dir.display()))?;

    let appender = tracing_appender::rolling::daily(&dir, "bridge.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);

    let filter = EnvFilter::try_from_env("AUTODCR_BRIDGE_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,cryptoki=warn"));

    tracing_subscriber::registry()
        .with(filter)
        .with(
            fmt::layer()
                .with_writer(writer)
                .with_ansi(false)
                .with_target(false),
        )
        .try_init()
        .ok();

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "bridge starting");
    Ok(guard)
}
