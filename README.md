# AutoDCR Chrome Native Bridge

This repository provides:

- A Chrome MV3 extension that bridges a trusted web origin to a native messaging host.
- A reference native host (Node.js) that implements Chrome native messaging framing and stub token commands.
- Shared protocol/types for consistent request and response envelopes.

## What this repo does not include

- PKCS#11 library loading in extension code.
- Full Next.js app or server-side PDF signing pipeline.
- Production token UX and PIN prompts (stub-only in host for now).

## Architecture

1. Web app posts bridge requests via `window.postMessage`.
2. Content script validates source and origin against allowlist.
3. Service worker forwards validated commands to native host with `chrome.runtime.connectNative`.
4. Native host returns framed responses over stdio.

## Quick start

### 1) Install dependencies

```bash
npm install
cd native-host && npm install
```

### 2) Build native host

```bash
cd native-host
npm run build
```

### 3) Configure native messaging host manifest

1. Copy `native-host/manifests/com.example.autodcr.signer.json` to your platform-specific Chrome NativeMessagingHosts directory.
2. Replace:
   - `<ABSOLUTE_PATH_TO_LAUNCHER>` with the absolute path to your launcher script.
   - `<EXTENSION_ID_PLACEHOLDER>` with your installed extension id.
3. Ensure launchers are executable on macOS/Linux:

```bash
chmod +x native-host/launchers/macos.sh native-host/launchers/linux.sh
```

See `docs/NATIVE_HOST_INSTALL.md` for exact OS paths and Windows registry steps.

### 4) Build/load extension

```bash
npm run build
```

Then open `chrome://extensions`, enable Developer mode, and load unpacked extension from `dist/`.

### 5) Development mode

```bash
npm run dev
```

This watches extension assets; reload extension in Chrome after rebuilds.

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
- No PKCS#11 dependencies in extension bundle.

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
