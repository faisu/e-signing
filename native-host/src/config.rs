//! Per-user configuration for the bridge.
//!
//! Resolved paths (created on first run if missing):
//!
//! - macOS:   `~/Library/Application Support/AutoDCR/bridge/config.toml`
//! - Linux:   `~/.config/autodcr/bridge/config.toml`
//! - Windows: `%APPDATA%\AutoDCR\bridge\config.toml`
//!
//! The installer seeds a sensible default; users can edit afterwards.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Absolute path to the vendor PKCS#11 module (.dylib / .dll / .so).
    pub pkcs11_module: Option<PathBuf>,

    /// If true, prompt for the token PIN via the OS-native dialog.
    /// Disable to require apps that already have a session-cached token.
    #[serde(default = "default_true")]
    pub prompt_pin: bool,

    /// Where the host writes its log file. Defaults to next to this config.
    pub log_dir: Option<PathBuf>,
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            pkcs11_module: None,
            prompt_pin: true,
            log_dir: None,
        }
    }
}

pub fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from("com", "AutoDCR", "bridge")
        .context("failed to resolve OS-specific project directories")
}

pub fn config_path() -> Result<PathBuf> {
    Ok(project_dirs()?.config_dir().join("config.toml"))
}

pub fn log_dir(cfg: &Config) -> Result<PathBuf> {
    if let Some(dir) = &cfg.log_dir {
        return Ok(dir.clone());
    }
    let dirs = project_dirs()?;
    Ok(dirs.data_local_dir().join("logs"))
}

pub fn load() -> Result<Config> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(Config::default());
    }
    let text =
        fs::read_to_string(&path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
    Ok(cfg)
}

/// Try several well-known vendor paths for the PKCS#11 module if the user did
/// not configure one explicitly. Returns the first existing path.
pub fn discover_default_module() -> Option<PathBuf> {
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib",
            "/usr/local/lib/libeps2003csp11.dylib",
            "/usr/local/lib/libProxKeyTokenEngine_3_5.dylib",
            "/Library/eMudhraSecureSign/libeMudhraSecureSign.dylib",
        ]
    } else if cfg!(target_os = "windows") {
        &[
            r"C:\Windows\System32\eps2003csp11.dll",
            r"C:\Windows\System32\eTPKCS11.dll",
            r"C:\Windows\System32\SignatureP11.dll",
            r"C:\Windows\System32\WDPKCS.dll",
        ]
    } else {
        &[
            "/usr/lib/x86_64-linux-gnu/libeps2003csp11.so",
            "/usr/lib/libeToken.so",
            "/usr/lib/libProxKeyTokenEngine_3_5.so",
            "/usr/lib/x86_64-linux-gnu/libeMudhraSecureSign.so",
        ]
    };

    for candidate in candidates {
        let path = Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    None
}
