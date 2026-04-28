# Native Host — Developer Guide

The native host is a Rust binary that implements Chrome Native Messaging
framing and dispatches commands to a PKCS#11 module.

Source layout (`native-host/`):

```
src/
  main.rs        entry point, stdio loop
  framing.rs     4-byte little-endian length-prefix framing
  protocol.rs    envelope/response types, error codes, command enum
  commands.rs    dispatch + handlers for PING / LIST_SLOTS / LIST_CERTS / SIGN_PDF_*
  pkcs11.rs      cryptoki wrapper (slots, certs, signing)
  pdf.rs         PDF /ByteRange + /Contents placeholder handling, CMS assembly
  pin.rs         OS-native PIN dialog (osascript / pinentry / CredUI)
  config.rs      config.toml loader
  logging.rs     tracing → daily-rotated file appender
manifests/       Chrome native messaging manifest template
tests/           integration tests
```

## Build

```bash
cd native-host
cargo build --release
# binary at native-host/target/release/autodcr-bridge
```

## Test

```bash
cd native-host
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Wire format

Every message between the extension and the host is:

```
[ 4-byte little-endian length ] [ UTF-8 JSON envelope ]
```

Request envelope:

```json
{ "v": 1, "id": "<uuid>", "cmd": "PING", "payload": {} }
```

Response envelope:

```json
{ "v": 1, "id": "<uuid>", "ok": true, "result": { ... }, "error": null }
```

Maximum frame size: 1 MB (matches Chrome's documented native messaging cap,
see `MAX_NATIVE_MESSAGE_BYTES` in [src/protocol.rs](../native-host/src/protocol.rs)).

## Run locally without the extension

The host reads framed JSON from stdin and writes framed JSON to stdout, so
you can drive it from a script:

```python
import struct, json, subprocess
env = {"v": 1, "id": "1", "cmd": "PING", "payload": {}}
body = json.dumps(env).encode()
proc = subprocess.Popen(
    ["./target/release/autodcr-bridge"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
)
out, _ = proc.communicate(struct.pack("<I", len(body)) + body, timeout=5)
length = struct.unpack("<I", out[:4])[0]
print(json.loads(out[4:4+length]))
```

## Wire to a locally-loaded extension

1. Build the host: `cargo build --release` (in `native-host/`).
2. Build the extension: `npm run build` (in repo root). Note its extension
   ID after loading `dist/` unpacked in `chrome://extensions`.
3. Render the manifest with absolute paths and your extension id, e.g.:

   ```bash
   sed \
     -e "s|<ABSOLUTE_PATH_TO_LAUNCHER>|$(pwd)/native-host/target/release/autodcr-bridge|g" \
     -e "s|<EXTENSION_ID_PLACEHOLDER>|<your-extension-id>|g" \
     native-host/manifests/com.example.autodcr.signer.json \
     > ~/Library/Application\ Support/Google/Chrome/NativeMessagingHosts/com.example.autodcr.signer.json
   ```

4. Reload the extension. The service worker's
   `chrome.runtime.connectNative("com.example.autodcr.signer")` should now
   succeed.

## Adding a new command

1. Add the variant to `HostCmd` in [src/protocol.rs](../native-host/src/protocol.rs).
2. Add a payload struct with `#[serde(rename_all = "camelCase")]`.
3. Add a handler in [src/commands.rs](../native-host/src/commands.rs).
4. Add a test in the same file.

The TypeScript content script will need a matching message contract — see
[CHROME_EXTENSION_SPEC.md](CHROME_EXTENSION_SPEC.md).

## CI / release

Per-OS installers are produced by `.github/workflows/release.yml` on tag push.
The matrix builds `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`x86_64-pc-windows-msvc`, and `x86_64-unknown-linux-gnu`, then runs:

- `installer/macos/build-pkg.sh` (lipos x64 + arm64 into a universal binary,
  then pkgbuild + productbuild)
- `installer/windows/build-msi.ps1` (WiX v4)
- `installer/linux/build-pkgs.sh` (`dpkg-deb` and `rpmbuild`)

The release job collects everything, computes SHA-256 checksums, and creates
a GitHub release. See `release.yml` for required repository variables
(`AUTODCR_EXTENSION_ID`).

## Smoke test

```bash
bash scripts/smoke-test.sh
```

Builds the host, runs a PING round-trip, exercises the chunked `SIGN_PDF_*`
flow, and (on macOS) verifies the `.pkg` builds with the expected payload
and postinstall script. Used by `.github/workflows/ci.yml`.

## Manual end-to-end (clean macOS VM)

The smoke test script exercises everything that doesn't need a token. The
token side has to be verified by hand:

1. Spin up a clean macOS VM (UTM / Parallels / OrbStack).
2. Install Chrome and your dev token vendor's PKCS#11 module.
3. Copy `release/<basename>/AutoDCR-Bridge-<version>.pkg` to the VM and double-click.
4. Confirm `/Library/Application Support/AutoDCR/bridge/autodcr-bridge` exists
   and the manifest landed in
   `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`.
5. Load the extension unpacked from `dist/`.
6. Open an allowed origin and send a `PING`. Expect `ok: true`.
7. Send `LIST_SLOTS` and `LIST_CERTS`. Expect your token's certs.
8. Send a `SIGN_PDF_*` flow with a PDF that contains a `/ByteRange [0 ********** ********** **********]` placeholder and a `/Contents <000...0>` placeholder.
9. Open the signed PDF in Adobe Acrobat and verify the signature.

Repeat on a clean Windows 11 VM with the `.msi` and on Ubuntu 22.04 with the `.deb`.

## Code signing (out of scope for the initial port)

The release pipeline is structured so signing is purely a config addition,
not a code change:

- macOS: set `AUTODCR_SIGNING_IDENTITY` env var and the build script will
  call `productsign`. Notarization (`xcrun notarytool submit ... --wait`)
  needs to be added as a separate step before `softprops/action-gh-release`.
- Windows: set `AUTODCR_PFX_PATH` + `AUTODCR_PFX_PASSWORD` env vars; the
  PowerShell builder will call `signtool`.
- Linux: typically not needed; users trust the distro repo.
