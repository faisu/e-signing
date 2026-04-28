# Chrome Extension Specification

## Scope

This extension is a trusted bridge between the web app and the native messaging host.

- Manifest version: MV3
- Native messaging permission: required
- Content script: explicit origin matches only
- No `<all_urls>` usage

## Manifest contract

- `permissions`: `["nativeMessaging"]`
- `background.service_worker`: `src/background/service-worker.ts` (module)
- `content_scripts.matches`:
  - `https://app.example.com/*`
  - `http://localhost:3000/*`
- `content_scripts.run_at`: `document_idle`

## Page bridge contract

All page messages use `source: "AUTODCR_SIGN_BRIDGE"`.

Page to extension:

```json
{
  "source": "AUTODCR_SIGN_BRIDGE",
  "type": "REQUEST",
  "requestId": "<uuid>",
  "cmd": "PING",
  "payload": {}
}
```

Extension to page:

```json
{
  "source": "AUTODCR_SIGN_BRIDGE",
  "type": "RESPONSE",
  "requestId": "<uuid>",
  "ok": true,
  "result": {},
  "error": null
}
```

## Validation requirements

The content script must:

- require `event.source === window`
- require known bridge source + request type
- require exact match against allowlisted origin
- post responses only to `event.origin` (never `*`)

## Native host forwarding

The service worker:

- opens native port via `chrome.runtime.connectNative("com.example.autodcr.signer")`
- tracks pending requests by id with timeout
- maps native disconnect into structured error
- forwards all `SIGN_PDF_*` chunk commands

## PDF chunking strategy

This implementation uses Option A chunk transfer:

1. `SIGN_PDF_START` with metadata (`jobId`, `totalChunks`)
2. `SIGN_PDF_CHUNK` repeated with indexed base64 chunks
3. `SIGN_PDF_END` completes request and returns signed result

Chunk cap is `256 * 1024` bytes.

## Security requirements

- do not expose `chrome.*` assumptions to page code
- do not include PKCS#11 libs in extension
- do not pass or log secrets unnecessarily
- pin/credential prompts should be native-host owned in real implementation
