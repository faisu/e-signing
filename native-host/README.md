# Native Host (Reference Stub)

This host implements Chrome native messaging framing and protocol stubs for local E2E development.

## Commands implemented

- `PING` -> returns host version and `tokenPresent: false`
- `LIST_SLOTS` -> returns empty slots array
- `LIST_CERTS` -> returns empty cert list
- `SIGN_PDF_START`, `SIGN_PDF_CHUNK`, `SIGN_PDF_END` -> stores chunks and echoes them back as chunked "signed" output

## Notes

- Message framing uses 4-byte little-endian length prefix + UTF-8 JSON.
- Incoming messages above 1 MB are rejected.
- Output is written only to stdout frames.
- Logs/errors should go to stderr.

## Build

```bash
npm install
npm run build
```

## Run directly (debug)

```bash
npm run dev
```

Use Chrome native messaging registration for actual extension integration.
