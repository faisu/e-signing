# AutoDCR Bridge (Rust)

Chrome native messaging host for the AutoDCR signing extension.
Single statically-linked binary (~1 MB), no runtime dependencies on the
client machine.

## Quick start

```bash
cargo build --release
cargo test --all-targets
```

## Commands implemented

| Command          | Behaviour                                                          |
| ---------------- | ------------------------------------------------------------------ |
| `PING`           | Returns host version + protocol version                            |
| `LIST_SLOTS`     | Enumerates PKCS#11 slots with present tokens                       |
| `LIST_CERTS`     | Returns certificates on the requested slot                         |
| `SIGN_PDF_START` | Begins a chunked PDF upload                                        |
| `SIGN_PDF_CHUNK` | Stores a base64 chunk by index                                     |
| `SIGN_PDF_END`   | Locates `/ByteRange` + `/Contents` placeholder, signs via PKCS#11, returns the signed PDF as base64 chunks |

## Wire format

- 4-byte little-endian length prefix + UTF-8 JSON envelope
- Per-message cap: 1 MB (Chrome's documented limit)
- Per-chunk cap on responses: 256 KB

## Where to look next

- High-level user install: [docs/NATIVE_HOST_INSTALL.md](../docs/NATIVE_HOST_INSTALL.md)
- Developer guide / wire contract: [docs/NATIVE_HOST_DEV.md](../docs/NATIVE_HOST_DEV.md)
- Extension contract: [docs/CHROME_EXTENSION_SPEC.md](../docs/CHROME_EXTENSION_SPEC.md)
