#!/usr/bin/env bash
#
# Local release build. Produces:
#
#   release/<basename>/extension.zip
#   release/<basename>/autodcr-bridge-macos-arm64             (macOS only)
#   release/<basename>/autodcr-bridge-macos-x64               (macOS only)
#   release/<basename>/autodcr-bridge-macos-universal         (macOS only)
#   release/<basename>/AutoDCR-Bridge-<version>.pkg          (macOS only, if pkgbuild is available)
#   release/<basename>/checksums.txt
#
# Cross-OS installers (.msi, .deb, .rpm) are produced by the GitHub Actions
# release workflow at .github/workflows/release.yml. This script only handles
# what's reproducible from a developer machine.
#
# Required env (only when building the .pkg):
#   AUTODCR_EXTENSION_ID   Chrome extension id baked into allowed_origins.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

APP_VERSION="$(node -p "require('./package.json').version")"
STAMP="$(date +%Y%m%d-%H%M%S)"
RELEASE_ROOT="${ROOT_DIR}/release"
RELEASE_BASENAME="autodcr-bridge-v${APP_VERSION}-${STAMP}"
RELEASE_DIR="${RELEASE_ROOT}/${RELEASE_BASENAME}"
LATEST_DIR="${RELEASE_ROOT}/latest"

echo "==> Building Chrome extension"
npm run build

mkdir -p "${RELEASE_DIR}"

echo "==> Packaging extension"
(cd dist && zip -rq "${RELEASE_DIR}/extension.zip" .)

if [[ "$(uname -s)" == "Darwin" ]]; then
  echo "==> Ensuring Rust targets are installed"
  rustup target add aarch64-apple-darwin x86_64-apple-darwin

  echo "==> Building native host (release) for macOS arm64 + x64"
  (cd native-host && cargo build --release --target aarch64-apple-darwin)
  (cd native-host && cargo build --release --target x86_64-apple-darwin)

  cp "native-host/target/aarch64-apple-darwin/release/autodcr-bridge" \
    "${RELEASE_DIR}/autodcr-bridge-macos-arm64"
  cp "native-host/target/x86_64-apple-darwin/release/autodcr-bridge" \
    "${RELEASE_DIR}/autodcr-bridge-macos-x64"

  echo "==> Creating universal macOS native host binary"
  lipo -create \
    "${RELEASE_DIR}/autodcr-bridge-macos-arm64" \
    "${RELEASE_DIR}/autodcr-bridge-macos-x64" \
    -output "${RELEASE_DIR}/autodcr-bridge-macos-universal"
else
  echo "==> Building native host (release)"
  (cd native-host && cargo build --release)
fi

if [[ "$(uname -s)" == "Darwin" ]] && command -v pkgbuild >/dev/null; then
  if [[ -z "${AUTODCR_EXTENSION_ID:-}" ]]; then
    echo "Skipping macOS .pkg build: AUTODCR_EXTENSION_ID not set"
  else
    echo "==> Building macOS .pkg from universal local binary"
    PAYLOAD_DIR="${ROOT_DIR}/installer/macos/payload"
    rm -rf "${PAYLOAD_DIR}"
    mkdir -p "${PAYLOAD_DIR}"
    cp "${RELEASE_DIR}/autodcr-bridge-macos-universal" "${PAYLOAD_DIR}/autodcr-bridge"

    AUTODCR_VERSION="${APP_VERSION}" bash installer/macos/build-pkg.sh
    cp installer/macos/dist/AutoDCR-Bridge-${APP_VERSION}.pkg "${RELEASE_DIR}/"

    rm -rf "${PAYLOAD_DIR}" "${ROOT_DIR}/installer/macos/dist"
  fi
fi

echo "==> Computing checksums"
(cd "${RELEASE_DIR}" && shasum -a 256 * > checksums.txt)

echo "==> Updating latest release copy"
rm -rf "${LATEST_DIR}"
cp -R "${RELEASE_DIR}" "${LATEST_DIR}"

echo
echo "Release created:"
echo "  Folder: ${RELEASE_DIR}"
echo "  Latest: ${LATEST_DIR}"
ls -la "${RELEASE_DIR}"
