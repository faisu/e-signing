//! OS-native PIN prompts. The host owns PIN entry per the extension spec; the
//! page never sees the secret.
//!
//! Behaviour:
//! - macOS: AppleScript dialog via `osascript` (always present on macOS).
//! - Linux: `pinentry`, falling back to `zenity --password`.
//! - Windows: PowerShell WinForms dialog (`TopMost`) so the prompt stays above Chrome.

#![allow(dead_code)]

use crate::pkcs11::LoginError;

#[derive(Debug, thiserror::Error)]
pub enum PinError {
    #[error("user cancelled the PIN prompt")]
    Cancelled,
    #[error("incorrect DSC PIN after maximum attempts")]
    Incorrect,
    #[error("DSC token PIN is locked")]
    Locked,
    #[error("no supported PIN dialog available")]
    NoDialog,
    #[error("dialog failed: {0}")]
    Other(#[from] anyhow::Error),
}

pub type PinResult = std::result::Result<String, PinError>;

pub fn prompt_pin(token_label: &str) -> PinResult {
    prompt_pin_with_message(token_label, None)
}

/// Prompt for a PIN and verify it against the token, retrying up to `max_attempts`
/// times when the PIN is incorrect.
pub fn prompt_and_verify_pin<F>(
    token_label: &str,
    max_attempts: u32,
    verify: F,
) -> PinResult
where
    F: Fn(&str) -> std::result::Result<(), LoginError>,
{
    let attempts = max_attempts.max(1);
    let mut error_message: Option<&str> = None;

    for attempt in 0..attempts {
        let pin = match prompt_pin_with_message(token_label, error_message) {
            Ok(p) => p,
            Err(e) => return Err(e),
        };

        match verify(&pin) {
            Ok(()) => return Ok(pin),
            Err(LoginError::Incorrect) => {
                if attempt + 1 >= attempts {
                    return Err(PinError::Incorrect);
                }
                error_message = Some("Incorrect PIN. Please try again.");
            }
            Err(LoginError::Locked) => return Err(PinError::Locked),
            Err(LoginError::Other(msg)) => {
                return Err(PinError::Other(anyhow::anyhow!(msg)));
            }
        }
    }

    Err(PinError::Incorrect)
}

fn prompt_pin_with_message(token_label: &str, error_message: Option<&str>) -> PinResult {
    #[cfg(target_os = "macos")]
    {
        macos::prompt(token_label, error_message)
    }
    #[cfg(target_os = "linux")]
    {
        linux::prompt(token_label, error_message)
    }
    #[cfg(target_os = "windows")]
    {
        windows::prompt(token_label, error_message)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = token_label;
        let _ = error_message;
        Err(PinError::NoDialog)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::Command;

    pub fn prompt(token_label: &str, error_message: Option<&str>) -> PinResult {
        let safe_label = token_label.replace('"', "'");
        let dialog_text = match error_message {
            Some(err) => format!("{err}\n\nEnter PIN for {safe_label}"),
            None => format!("Enter PIN for {safe_label}"),
        };
        let safe_text = dialog_text.replace('"', "'");
        let script = format!(
            r#"set d to display dialog "{safe_text}" default answer "" with hidden answer with title "AutoDCR Bridge" buttons {{"Cancel", "OK"}} default button "OK"
return text returned of d"#
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

    pub fn prompt(token_label: &str, error_message: Option<&str>) -> PinResult {
        if let Some(pin) = try_pinentry(token_label, error_message)? {
            return Ok(pin);
        }
        if let Some(pin) = try_zenity(token_label, error_message)? {
            return Ok(pin);
        }
        Err(PinError::NoDialog)
    }

    fn try_pinentry(token_label: &str, error_message: Option<&str>) -> Result<Option<String>, PinError> {
        let mut child = match Command::new("pinentry")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(_) => return Ok(None),
        };

        let mut prompt = format!(
            "OPTION grab\nSETTITLE AutoDCR Bridge\nSETDESC Enter PIN for {token_label}\n"
        );
        if let Some(err) = error_message {
            prompt.push_str(&format!("SETERROR {err}\n"));
        }
        prompt.push_str("SETPROMPT PIN:\nGETPIN\n");

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

    fn try_zenity(token_label: &str, error_message: Option<&str>) -> Result<Option<String>, PinError> {
        let text = match error_message {
            Some(err) => format!("{err}\n\nEnter PIN for {token_label}"),
            None => format!("Enter PIN for {token_label}"),
        };
        let output = match Command::new("zenity")
            .args(["--password", "--title", "AutoDCR Bridge", "--text"])
            .arg(text)
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
    use std::process::Command;

    fn ps_single_quote(value: &str) -> String {
        value.replace('\'', "''")
    }

    pub fn prompt(token_label: &str, error_message: Option<&str>) -> PinResult {
        let body = match error_message {
            Some(err) => format!("{err}\n\nEnter PIN for {token_label}"),
            None => format!("Enter PIN for {token_label}"),
        };
        let body_q = ps_single_quote(&body);
        let label_q = ps_single_quote(token_label);

        // WinForms TopMost dialog — stays above Chrome unlike CredUI child windows.
        let script = format!(
            r#"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$form = New-Object System.Windows.Forms.Form
$form.Text = 'AutoDCR Bridge'
$form.TopMost = $true
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.ShowInTaskbar = $true
$form.Width = 460
$form.Height = 200
$label = New-Object System.Windows.Forms.Label
$label.Text = '{body_q}'
$label.AutoSize = $false
$label.Width = 420
$label.Height = 50
$label.Location = New-Object System.Drawing.Point(12, 12)
$box = New-Object System.Windows.Forms.TextBox
$box.UseSystemPasswordChar = $true
$box.Width = 420
$box.Location = New-Object System.Drawing.Point(12, 72)
$ok = New-Object System.Windows.Forms.Button
$ok.Text = 'OK'
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$ok.Location = New-Object System.Drawing.Point(260, 115)
$ok.Width = 80
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'Cancel'
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$cancel.Location = New-Object System.Drawing.Point(350, 115)
$cancel.Width = 80
$form.Controls.AddRange(@($label, $box, $ok, $cancel))
$form.AcceptButton = $ok
$form.CancelButton = $cancel
$form.Add_Shown({{ $form.Activate(); $box.Focus() | Out-Null }})
$result = $form.ShowDialog()
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {{
  if ([string]::IsNullOrWhiteSpace($box.Text)) {{ exit 2 }}
  Write-Output $box.Text
}} else {{
  exit 1
}}
"#
        );

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-STA",
                "-Command",
                &script,
            ])
            .output()
            .map_err(|e| PinError::Other(anyhow::anyhow!("PowerShell PIN dialog spawn: {e}")))?;

        if output.status.code() == Some(1) {
            return Err(PinError::Cancelled);
        }
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PinError::Other(anyhow::anyhow!(
                "PowerShell PIN dialog failed (token={label_q}): {stderr}"
            )));
        }

        let pin = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if pin.is_empty() {
            return Err(PinError::Cancelled);
        }
        Ok(pin)
    }
}
