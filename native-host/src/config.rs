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
            // Hypersecu / HYP2003
            "/usr/local/lib/libcastle_v2.1.0.0.dylib",
            "/usr/local/lib/libcastle.dylib",
            "/usr/lib/libcastle_v2.1.0.0.dylib",
            "/usr/lib/libcastle.dylib",
            "/opt/hypersecu/lib/libcastle.dylib",
            "/Library/Frameworks/HyperSecu.framework/libcastle.dylib",
            "/Volumes/HyperPKI_230404/libcastle.dylib",
            "/Volumes/HyperPKI_230404/libcastle_v2.1.0.0.dylib",
            "/usr/local/lib/libhypersecu_pkcs11.dylib",
            "/usr/lib/libhypersecu_pkcs11.dylib",
            "/opt/hypersecu/lib/libhypersecu_pkcs11.dylib",
            "/Library/Frameworks/HyperSecu.framework/libhypersecu_pkcs11.dylib",
            // eMudhra / eToken / Capricorn
            "/opt/eMudhra/eToken/lib/libeTPkcs11.dylib",
            "/usr/local/lib/libeTPkcs11.dylib",
            "/usr/lib/libeTPkcs11.dylib",
            "/usr/local/lib/libaetpkss.dylib",
            "/usr/lib/libaetpkss.dylib",
            "/Library/Frameworks/eToken.framework/Versions/Current/libeTPkcs11.dylib",
            "/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib",
            "/usr/local/lib/libeps2003csp11.dylib",
            "/usr/local/lib/libProxKeyTokenEngine_3_5.dylib",
            "/Library/eMudhraSecureSign/libeMudhraSecureSign.dylib",
            // Generic fallback
            "/usr/local/lib/pkcs11/libpkcs11.dylib",
            "/opt/homebrew/lib/libpkcs11.dylib",
        ]
    } else if cfg!(target_os = "windows") {
        &[
            // Hypersecu / HYP2003
            r"C:\Windows\System32\hypersecu_pkcs11.dll",
            r"C:\Program Files\Hypersecu\lib\hypersecu_pkcs11.dll",
            // eMudhra / eToken / Capricorn
            r"C:\Windows\System32\eps2003csp11.dll",
            r"C:\Windows\System32\eTPKCS11.dll",
            r"C:\Windows\System32\aetpkss.dll",
            r"C:\Windows\System32\SignatureP11.dll",
            r"C:\Windows\System32\WDPKCS.dll",
            r"C:\Program Files\eMudhra\eToken\lib\eTPKCS11.dll",
            r"C:\Program Files (x86)\eMudhra\eToken\lib\eTPKCS11.dll",
        ]
    } else {
        &[
            // Hypersecu / HYP2003
            "/usr/local/lib/libhypersecu_pkcs11.so",
            "/usr/lib/libhypersecu_pkcs11.so",
            // eMudhra / eToken / Capricorn
            "/opt/eMudhra/eToken/lib/libeTPkcs11.so",
            "/usr/lib/libaetpkss.so",
            "/usr/lib/x86_64-linux-gnu/libeps2003csp11.so",
            "/usr/lib/libeToken.so",
            "/usr/lib/libProxKeyTokenEngine_3_5.so",
            "/usr/lib/x86_64-linux-gnu/libeMudhraSecureSign.so",
            // Generic fallback
            "/usr/lib/pkcs11/libpkcs11.so",
            "/usr/lib/x86_64-linux-gnu/pkcs11/libpkcs11.so",
            "/usr/local/lib/pkcs11/libpkcs11.so",
            "/usr/lib/x86_64-linux-gnu/libpkcs11.so",
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
