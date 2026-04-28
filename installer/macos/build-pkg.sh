#!/usr/bin/env bash
#
# Build a flat .pkg installer for macOS that:
#   - drops the universal autodcr-bridge binary into
#     /Library/Application Support/AutoDCR/bridge/
#   - on first launch / postinstall writes the native messaging manifest into
#     each Chromium-family browser's NativeMessagingHosts dir for every user
#
# Inputs (env):
#   AUTODCR_VERSION         (required)  semver string, e.g. "0.1.0" or "v0.1.0"
#   AUTODCR_EXTENSION_ID    (required)  Chrome extension ID (substituted into
#                                       allowed_origins)
#   AUTODCR_SIGNING_IDENTITY (optional) Developer ID Installer cert common name
#                                       used by `productsign`; if unset the .pkg
#                                       is built unsigned.
#
# Inputs (filesystem):
#   installer/macos/payload/autodcr-bridge   universal binary built upstream
#
# Output:
#   installer/macos/dist/AutoDCR-Bridge-<version>.pkg

set -euo pipefail

if [[ -z "${AUTODCR_VERSION:-}" ]]; then
  echo "AUTODCR_VERSION is required" >&2
  exit 1
fi
if [[ -z "${AUTODCR_EXTENSION_ID:-}" ]]; then
  echo "AUTODCR_EXTENSION_ID is required" >&2
  exit 1
fi

VERSION="${AUTODCR_VERSION#v}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PAYLOAD_BIN="${SCRIPT_DIR}/payload/autodcr-bridge"
DIST_DIR="${SCRIPT_DIR}/dist"
WORK_DIR="$(mktemp -d)"
PKG_ROOT="${WORK_DIR}/pkg-root"
SCRIPTS_DIR="${WORK_DIR}/scripts"

if [[ ! -x "${PAYLOAD_BIN}" ]]; then
  echo "Universal binary missing at ${PAYLOAD_BIN}" >&2
  echo "Build aarch64 + x86_64 release binaries first and lipo them in." >&2
  exit 1
fi

mkdir -p "${PKG_ROOT}/Library/Application Support/AutoDCR/bridge"
mkdir -p "${SCRIPTS_DIR}"
mkdir -p "${DIST_DIR}"

cp "${PAYLOAD_BIN}" "${PKG_ROOT}/Library/Application Support/AutoDCR/bridge/autodcr-bridge"
chmod 755 "${PKG_ROOT}/Library/Application Support/AutoDCR/bridge/autodcr-bridge"

# Generate the manifest to be written by postinstall.  We render it once at
# build time so allowed_origins is baked with the extension id.
MANIFEST_TEMPLATE="${REPO_ROOT}/native-host/manifests/com.example.autodcr.signer.json"
RENDERED_MANIFEST="${PKG_ROOT}/Library/Application Support/AutoDCR/bridge/com.example.autodcr.signer.json"
sed \
  -e "s|<ABSOLUTE_PATH_TO_LAUNCHER>|/Library/Application Support/AutoDCR/bridge/autodcr-bridge|g" \
  -e "s|<EXTENSION_ID_PLACEHOLDER>|${AUTODCR_EXTENSION_ID}|g" \
  "${MANIFEST_TEMPLATE}" > "${RENDERED_MANIFEST}"

cat > "${SCRIPTS_DIR}/postinstall" <<'POSTINSTALL'
#!/bin/bash
set -euo pipefail

MANIFEST_SRC="/Library/Application Support/AutoDCR/bridge/com.example.autodcr.signer.json"
MANIFEST_NAME="com.example.autodcr.signer.json"

# Each entry: ":-separated" relative path under the user's Library.
BROWSERS=(
  "Google/Chrome/NativeMessagingHosts"
  "Google/Chrome Beta/NativeMessagingHosts"
  "Google/Chrome Dev/NativeMessagingHosts"
  "Google/Chrome Canary/NativeMessagingHosts"
  "Chromium/NativeMessagingHosts"
  "Microsoft Edge/NativeMessagingHosts"
  "BraveSoftware/Brave-Browser/NativeMessagingHosts"
  "BraveSoftware/Brave-Browser-Beta/NativeMessagingHosts"
  "Vivaldi/NativeMessagingHosts"
)

install_for_user() {
  local user_home="$1"
  local user_name="$2"
  local lib="${user_home}/Library/Application Support"
  if [ ! -d "${lib}" ]; then
    return 0
  fi
  for rel in "${BROWSERS[@]}"; do
    local dest_dir="${lib}/${rel}"
    mkdir -p "${dest_dir}"
    cp "${MANIFEST_SRC}" "${dest_dir}/${MANIFEST_NAME}"
    chown "${user_name}" "${dest_dir}/${MANIFEST_NAME}" 2>/dev/null || true
    chmod 644 "${dest_dir}/${MANIFEST_NAME}"
  done
}

# Iterate every real /Users/<name> with a Library directory.
for user_home in /Users/*; do
  user_name="$(basename "${user_home}")"
  case "${user_name}" in
    Shared|Guest|.*) continue ;;
  esac
  if [ -d "${user_home}/Library" ]; then
    install_for_user "${user_home}" "${user_name}" || true
  fi
done

exit 0
POSTINSTALL
chmod 755 "${SCRIPTS_DIR}/postinstall"

PKG_ID="com.autodcr.bridge"
COMPONENT_PKG="${WORK_DIR}/component.pkg"
PRODUCT_PKG="${DIST_DIR}/AutoDCR-Bridge-${VERSION}.pkg"

pkgbuild \
  --root "${PKG_ROOT}" \
  --identifier "${PKG_ID}" \
  --version "${VERSION}" \
  --scripts "${SCRIPTS_DIR}" \
  --install-location "/" \
  "${COMPONENT_PKG}"

cat > "${WORK_DIR}/distribution.xml" <<DISTXML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
  <title>AutoDCR Bridge</title>
  <organization>com.autodcr</organization>
  <domains enable_localSystem="true"/>
  <options customize="never" rootVolumeOnly="true"/>
  <choices-outline>
    <line choice="default">
      <line choice="${PKG_ID}"/>
    </line>
  </choices-outline>
  <choice id="default"/>
  <choice id="${PKG_ID}" visible="false">
    <pkg-ref id="${PKG_ID}"/>
  </choice>
  <pkg-ref id="${PKG_ID}" version="${VERSION}" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
DISTXML

productbuild \
  --distribution "${WORK_DIR}/distribution.xml" \
  --package-path "${WORK_DIR}" \
  "${PRODUCT_PKG}"

if [[ -n "${AUTODCR_SIGNING_IDENTITY:-}" ]]; then
  SIGNED_PKG="${PRODUCT_PKG%.pkg}-signed.pkg"
  productsign --sign "${AUTODCR_SIGNING_IDENTITY}" "${PRODUCT_PKG}" "${SIGNED_PKG}"
  mv "${SIGNED_PKG}" "${PRODUCT_PKG}"
fi

echo "Built ${PRODUCT_PKG}"
