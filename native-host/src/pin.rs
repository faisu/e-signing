//! OS-native PIN prompts. The host owns PIN entry per the extension spec; the
//! page never sees the secret.
//!
//! Behaviour:
//! - macOS: AppleScript dialog via `osascript` (always present on macOS).
//! - Linux: `pinentry`, falling back to `zenity --password`.
//! - Windows: `CredUIPromptForCredentialsW` from `credui.dll`.

#![allow(dead_code)]

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("user cancelled the PIN prompt")]
    Cancelled,
    #[error("no supported PIN dialog available")]
    NoDialog,
    #[error("dialog failed: {0}")]
    Other(#[from] anyhow::Error),
}

pub type PinResult = std::result::Result<String, PinError>;

pub fn prompt_pin(token_label: &str) -> PinResult {
    #[cfg(target_os = "macos")]
    {
        macos::prompt(token_label)
    }
    #[cfg(target_os = "linux")]
    {
        linux::prompt(token_label)
    }
    #[cfg(target_os = "windows")]
    {
        windows::prompt(token_label)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = token_label;
        Err(PinError::NoDialog)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    pub fn prompt(token_label: &str) -> PinResult {
        let safe_label = token_label.replace('"', "'");
        let script = format!(
            r#"set d to display dialog "Enter PIN for {0}" default answer "" with hidden answer with title "AutoDCR Bridge" buttons {{"Cancel", "OK"}} default button "OK"
return text returned of d"#,
            safe_label
        );

        let output = Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .map_err(|e| PinError::Other(anyhow::anyhow!("osascript spawn: {e}")))?;

        if !output.status.success() {
            // osascript exits non-zero when the user clicks Cancel.
            return Err(PinError::Cancelled);
        }
        let pin = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if pin.is_empty() {
            return Err(PinError::Cancelled);
        }
        Ok(pin)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    pub fn prompt(token_label: &str) -> PinResult {
        if let Some(pin) = try_pinentry(token_label)? {
            return Ok(pin);
        }
        if let Some(pin) = try_zenity(token_label)? {
            return Ok(pin);
        }
        Err(PinError::NoDialog)
    }

    fn try_pinentry(token_label: &str) -> Result<Option<String>, PinError> {
        let mut child = match Command::new("pinentry")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };

        let prompt = format!(
            "OPTION grab\nSETTITLE AutoDCR Bridge\nSETDESC Enter PIN for {token_label}\nSETPROMPT PIN:\nGETPIN\n"
        );

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(prompt.as_bytes())
                .map_err(|e| PinError::Other(anyhow::anyhow!("pinentry write: {e}")))?;
        }

        let out = child
            .wait_with_output()
            .map_err(|e| PinError::Other(anyhow::anyhow!("pinentry wait: {e}")))?;
        let text = String::from_utf8_lossy(&out.stdout);

        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("D ") {
                return Ok(Some(rest.to_string()));
            }
            if line.starts_with("ERR ") {
                return Err(PinError::Cancelled);
            }
        }
        Ok(None)
    }

    fn try_zenity(token_label: &str) -> Result<Option<String>, PinError> {
        let output = match Command::new("zenity")
            .args(["--password", "--title", "AutoDCR Bridge", "--text"])
            .arg(format!("Enter PIN for {token_label}"))
            .output()
        {
            Ok(o) => o,
            Err(_) => return Ok(None),
        };
        if !output.status.success() {
            return Err(PinError::Cancelled);
        }
        let pin = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if pin.is_empty() {
            return Err(PinError::Cancelled);
        }
        Ok(Some(pin))
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::{PinError, PinResult};
    use ::windows::core::PCWSTR;
    use ::windows::Win32::Foundation::{ERROR_CANCELLED, ERROR_SUCCESS, WIN32_ERROR};
    use ::windows::Win32::Security::Credentials::{
        CredUIPromptForCredentialsW, CREDUI_FLAGS, CREDUI_FLAGS_DO_NOT_PERSIST,
        CREDUI_FLAGS_GENERIC_CREDENTIALS, CREDUI_FLAGS_KEEP_USERNAME, CREDUI_INFOW,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn prompt(token_label: &str) -> PinResult {
        let caption = to_wide("AutoDCR Bridge");
        let message = to_wide(&format!("Enter PIN for {token_label}"));
        let target_name = to_wide("AutoDCRBridge");

        let info = CREDUI_INFOW {
            cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: Default::default(),
            pszMessageText: PCWSTR(message.as_ptr()),
            pszCaptionText: PCWSTR(caption.as_ptr()),
            hbmBanner: Default::default(),
        };

        let mut user = vec![0u16; 256];
        let mut pin = vec![0u16; 256];
        // Pre-seed username with the token label so the user only types the PIN.
        let label_w = to_wide(token_label);
        let copy_len = label_w.len().min(user.len() - 1);
        user[..copy_len].copy_from_slice(&label_w[..copy_len]);

        let mut save = false.into();

        let flags: CREDUI_FLAGS = CREDUI_FLAGS_GENERIC_CREDENTIALS
            | CREDUI_FLAGS_DO_NOT_PERSIST
            | CREDUI_FLAGS_KEEP_USERNAME;

        // SAFETY: All buffers outlive the call.
        let result = unsafe {
            CredUIPromptForCredentialsW(
                Some(&info),
                PCWSTR(target_name.as_ptr()),
                None,
                0,
                &mut user,
                &mut pin,
                Some(&mut save),
                flags,
            )
        };

        match result {
            ERROR_SUCCESS => {
                let len = pin.iter().position(|&c| c == 0).unwrap_or(pin.len());
                let s = String::from_utf16_lossy(&pin[..len]);
                if s.is_empty() {
                    Err(PinError::Cancelled)
                } else {
                    Ok(s)
                }
            }
            ERROR_CANCELLED => Err(PinError::Cancelled),
            err => Err(PinError::Other(anyhow::anyhow!("CredUI failed: {:?}", err))),
        }
    }
}
