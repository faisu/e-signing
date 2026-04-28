#!/usr/bin/env bash
#
# Smoke test for the native host. Builds the binary, exercises the wire
# protocol against it (PING + a SIGN_PDF chunked round-trip), and on macOS
# additionally verifies the .pkg expands cleanly with the expected payload.
#
# Run from the repo root:
#   bash scripts/smoke-test.sh

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PASS="\033[1;32mPASS\033[0m"
FAIL="\033[1;31mFAIL\033[0m"

step() {
  echo
  echo "==> $1"
}

require() {
  local cond=$1
  local msg=$2
  if eval "${cond}"; then
    echo -e "  ${PASS}  ${msg}"
  else
    echo -e "  ${FAIL}  ${msg}"
    exit 1
  fi
}

step "Build native host (release)"
(cd native-host && cargo build --release --quiet)

BIN="${ROOT_DIR}/native-host/target/release/autodcr-bridge"
require "[[ -x '${BIN}' ]]" "binary present at ${BIN}"

step "PING round-trip"
PING_RESP="$(python3 - <<EOF
import json, struct, subprocess
env = {"v": 1, "id": "smoke-ping", "cmd": "PING", "payload": {}}
body = json.dumps(env).encode()
proc = subprocess.Popen(["${BIN}"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
out, _ = proc.communicate(struct.pack("<I", len(body)) + body, timeout=5)
length = struct.unpack("<I", out[:4])[0]
print(json.dumps(json.loads(out[4:4+length])))
EOF
)"
require "echo '${PING_RESP}' | python3 -c 'import sys,json;d=json.loads(sys.stdin.read());sys.exit(0 if d[\"ok\"] and d[\"id\"]==\"smoke-ping\" else 1)'" \
  "PING returned ok=true with matching id"

step "Chunked SIGN_PDF round-trip (no token, expects PDF_INVALID error)"
# Without a real token we can't actually sign, but we can exercise the chunked
# protocol path and confirm the host fails gracefully on a non-PDF payload
# rather than crashing.
SIGN_RESP="$(python3 - <<'EOF'
import json, struct, subprocess, base64, sys
proc = subprocess.Popen(["./native-host/target/release/autodcr-bridge"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

def send(env):
    body = json.dumps(env).encode()
    proc.stdin.write(struct.pack("<I", len(body)) + body)
    proc.stdin.flush()

def recv():
    header = proc.stdout.read(4)
    length = struct.unpack("<I", header)[0]
    return json.loads(proc.stdout.read(length))

send({"v":1,"id":"s1","cmd":"SIGN_PDF_START","payload":{
    "jobId":"j1","totalChunks":1,"slotId":0,"certId":"00"}})
print(json.dumps(recv()))
send({"v":1,"id":"s2","cmd":"SIGN_PDF_CHUNK","payload":{
    "jobId":"j1","index":0,"chunkBase64":base64.b64encode(b"not a pdf").decode()}})
print(json.dumps(recv()))
send({"v":1,"id":"s3","cmd":"SIGN_PDF_END","payload":{"jobId":"j1"}})
final = recv()
print(json.dumps(final))
proc.stdin.close()
EOF
)"
require "[[ -n '${SIGN_RESP}' ]]" "host responded to all three SIGN_PDF_* messages"
require "echo '${SIGN_RESP}' | tail -n1 | python3 -c 'import sys,json;d=json.loads(sys.stdin.read());sys.exit(0 if not d[\"ok\"] and d[\"error\"][\"code\"] in (\"PDF_INVALID\",\"PKCS11_INIT_FAILED\",\"CMS_BUILD_FAILED\",\"PKCS11_SIGN_FAILED\",\"PIN_CANCELLED\") else 1)'" \
  "SIGN_PDF_END failed cleanly with a structured error code"

if [[ "$(uname -s)" == "Darwin" ]] && command -v pkgbuild >/dev/null; then
  step "macOS .pkg payload check"
  # Build a one-off pkg using the smoke-test binary.
  rm -rf installer/macos/payload installer/macos/dist
  mkdir -p installer/macos/payload
  cp "${BIN}" installer/macos/payload/autodcr-bridge

  AUTODCR_VERSION=0.0.0-smoke \
  AUTODCR_EXTENSION_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    bash installer/macos/build-pkg.sh > /dev/null

  PKG="${ROOT_DIR}/installer/macos/dist/AutoDCR-Bridge-0.0.0-smoke.pkg"
  require "[[ -f '${PKG}' ]]" ".pkg built"

  EXPAND="$(mktemp -d)"
  pkgutil --expand "${PKG}" "${EXPAND}/expanded" >/dev/null
  require "[[ -f '${EXPAND}/expanded/component.pkg/Scripts/postinstall' ]]" \
    "postinstall script present"
  require "lsbom '${EXPAND}/expanded/component.pkg/Bom' | grep -q 'Library/Application Support/AutoDCR/bridge/autodcr-bridge'" \
    "binary installed to /Library/Application Support/AutoDCR/bridge/"
  require "lsbom '${EXPAND}/expanded/component.pkg/Bom' | grep -q 'com.example.autodcr.signer.json'" \
    "manifest staged inside the pkg payload"

  rm -rf "${EXPAND}" installer/macos/payload installer/macos/dist
fi

step "All smoke checks passed"
