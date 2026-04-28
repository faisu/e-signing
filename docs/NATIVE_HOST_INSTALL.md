# Installing the AutoDCR Bridge

The bridge is a small native helper (~1 MB) that the AutoDCR browser
extension uses to talk to your signing token. There is no Node, npm, or
Xcode requirement — just download the installer for your OS and double-click.

Host name (don't change): `com.example.autodcr.signer`

## macOS

1. Download `AutoDCR-Bridge-<version>.pkg` from the latest GitHub release.
2. Double-click and follow the prompts.
3. Restart Chrome (or Edge / Brave / Chromium / Vivaldi).

The installer drops:

- Binary: `/Library/Application Support/AutoDCR/bridge/autodcr-bridge`
- Per-user manifest: `~/Library/Application Support/<browser>/NativeMessagingHosts/com.example.autodcr.signer.json`

If macOS Gatekeeper warns about an unidentified developer (only on unsigned
builds), right-click the `.pkg` → **Open** to override.

## Windows

1. Download `AutoDCR-Bridge-<version>.msi` from the latest GitHub release.
2. Double-click and follow the prompts. No admin rights required (per-user install).
3. Restart Chrome (or Edge / Brave / Chromium).

The installer drops:

- Binary: `%LOCALAPPDATA%\AutoDCR\bridge\autodcr-bridge.exe`
- Manifest: `%LOCALAPPDATA%\AutoDCR\bridge\com.example.autodcr.signer.json`
- Registry: `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.example.autodcr.signer` (and Edge / Brave / Chromium equivalents)

## Linux

Pick the package that matches your distribution:

```bash
# Debian / Ubuntu
sudo dpkg -i autodcr-bridge_<version>_amd64.deb

# Fedora / RHEL
sudo rpm -i autodcr-bridge-<version>-1.x86_64.rpm
```

Drops:

- Binary: `/usr/bin/autodcr-bridge`
- System manifest: `/etc/opt/chrome/native-messaging-hosts/com.example.autodcr.signer.json` (and Chromium / Edge / Brave / Vivaldi equivalents)

## Configure your signing token (all OSes)

The bridge auto-detects common vendor PKCS#11 modules (ProxKey, eToken,
SafeNet, eMudhra). If yours isn't detected, create a config file at:

| OS      | Path                                                                         |
| ------- | ---------------------------------------------------------------------------- |
| macOS   | `~/Library/Application Support/com.AutoDCR.bridge/config.toml`               |
| Linux   | `~/.config/autodcr/bridge/config.toml`                                       |
| Windows | `%APPDATA%\AutoDCR\bridge\config\config.toml`                                |

Contents:

```toml
pkcs11_module = "/absolute/path/to/your/vendor.dylib"
prompt_pin = true
```

## Verify

1. Plug in your token.
2. Load the AutoDCR extension and open an allowed origin.
3. The page sends a `PING`; you should see `ok: true` and `hostVersion`.

## Logs

The bridge writes a daily-rotated log file:

| OS      | Path                                                                                |
| ------- | ----------------------------------------------------------------------------------- |
| macOS   | `~/Library/Application Support/com.AutoDCR.bridge/logs/bridge.log.<date>`           |
| Linux   | `~/.local/share/autodcr/bridge/logs/bridge.log.<date>`                              |
| Windows | `%LOCALAPPDATA%\AutoDCR\bridge\data\logs\bridge.log.<date>`                         |

Set `AUTODCR_BRIDGE_LOG=debug` in the environment of your browser to get
verbose logs.

## Uninstall

- macOS: `sudo rm -rf "/Library/Application Support/AutoDCR"` and per-user
  manifests under `~/Library/Application Support/<browser>/NativeMessagingHosts/`.
- Windows: Settings → Apps → AutoDCR Bridge → Uninstall.
- Linux: `sudo apt remove autodcr-bridge` or `sudo rpm -e autodcr-bridge`.
