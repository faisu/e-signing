# AutoDCR Chrome Native Bridge

This repository provides:

- A Chrome MV3 extension that bridges a trusted web origin to a native messaging host.
- A native host written in Rust that implements Chrome native messaging framing and PKCS#11-backed signing. Single statically-linked binary (~1 MB) — no Node, npm, or Xcode needed on client machines.
- OS-native installers (`.pkg` / `.msi` / `.deb` / `.rpm`) that drop the manifest and registry/keychain entries automatically.
- Shared protocol/types for consistent request and response envelopes.

## What this repo does not include

- PKCS#11 library loading in extension code (kept in the native host by design).
- Full Next.js app or server-side PDF signing pipeline.
- Code signing / notarization (hooks are in place; supply your certs to enable).

## Architecture

1. Web app posts bridge requests via `window.postMessage`.
2. Content script validates source and origin against allowlist.
3. Service worker forwards validated commands to native host with `chrome.runtime.connectNative`.
4. Native host returns framed responses over stdio.

## Quick start

### End users

Download the installer for your OS from the latest GitHub release and double-click. See [docs/NATIVE_HOST_INSTALL.md](docs/NATIVE_HOST_INSTALL.md).

### Developers

```bash
# Extension
npm install
npm run build       # outputs to dist/

# Native host (requires Rust toolchain)
cd native-host
cargo build --release
cargo test --all-targets
```

Wire a locally built host to a locally loaded extension using the steps in [docs/NATIVE_HOST_DEV.md](docs/NATIVE_HOST_DEV.md).

### Cut a release

```bash
AUTODCR_EXTENSION_ID=<your-extension-id> npm run build:release
```

Produces `release/<basename>/extension.zip`, `autodcr-bridge-macos-arm64`, `autodcr-bridge-macos-x64`, `autodcr-bridge-macos-universal`, and (on macOS with `AUTODCR_EXTENSION_ID` set) `AutoDCR-Bridge-<version>.pkg`, plus `checksums.txt`. The full multi-OS release pipeline (`.pkg` + `.msi` + `.deb` + `.rpm` + checksums) is at `.github/workflows/release.yml` and runs on tag push.

## Protocol summary

Bridge source id: `AUTODCR_SIGN_BRIDGE`  
Native host name: `com.example.autodcr.signer`  
Version: `v: 1`

Request envelope:

```json
{
  "v": 1,
  "id": "<uuid>",
  "cmd": "<command>",
  "payload": {}
}
```

Response envelope:

```json
{
  "v": 1,
  "id": "<uuid>",
  "ok": true,
  "result": {},
  "error": null
}
```

Implemented commands:

- `PING`
- `LIST_SLOTS`
- `LIST_CERTS`
- `SIGN_PDF_START`
- `SIGN_PDF_CHUNK`
- `SIGN_PDF_END`

## Security notes

- Strict allowlist for bridge origins:
  - `https://app.example.com`
  - `http://localhost:3000`
- Content script ignores unknown `source`, non-window events, and disallowed origins.
- Service worker is the only extension context that calls `connectNative`.
- No PIN logging. PIN must be handled inside native host UX in production implementation.
- No PKCS#11 dependencies in extension bundle (vendor module loaded by the native host at runtime).

## Web app integration

- Use `window.postMessage` only; do not call `chrome.*` APIs from the page.
- Optional feature detect from content script:
  - `document.documentElement.dataset.autodcrExtension === "1"`
- When `PING` fails, show install instructions / store link.

## Testing checklist

- `npm test` for framing and origin allowlist tests.
- Confirm `PING` returns host version.
- Send chunked `SIGN_PDF_*` flow and verify response roundtrip.
- Kill native host and verify extension returns `NATIVE_DISCONNECTED`.

## References

- [Chrome Native Messaging](https://developer.chrome.com/docs/apps/nativeMessaging/)
- [Chrome Manifest V3](https://developer.chrome.com/docs/extensions/mv3/intro/)
