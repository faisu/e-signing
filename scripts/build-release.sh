#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

APP_VERSION="$(node -p "require('./package.json').version")"
STAMP="$(date +%Y%m%d-%H%M%S)"
RELEASE_ROOT="${ROOT_DIR}/release"
RELEASE_BASENAME="autodcr-bridge-v${APP_VERSION}-${STAMP}"
RELEASE_DIR="${RELEASE_ROOT}/${RELEASE_BASENAME}"
LATEST_DIR="${RELEASE_ROOT}/latest"
ZIP_PATH="${RELEASE_ROOT}/${RELEASE_BASENAME}.zip"

echo "==> Building Chrome extension"
npm run build

echo "==> Building native host"
npm --prefix native-host run build

echo "==> Preparing release directories"
mkdir -p "${RELEASE_DIR}/extension" "${RELEASE_DIR}/native-host"

cp -R dist "${RELEASE_DIR}/extension/"
cp README.md "${RELEASE_DIR}/"
cp -R docs "${RELEASE_DIR}/"

cp native-host/README.md "${RELEASE_DIR}/native-host/"
cp native-host/package.json "${RELEASE_DIR}/native-host/"
cp -R native-host/dist "${RELEASE_DIR}/native-host/"
cp -R native-host/manifests "${RELEASE_DIR}/native-host/"
cp -R native-host/launchers "${RELEASE_DIR}/native-host/"

echo "==> Updating latest release copy"
rm -rf "${LATEST_DIR}"
cp -R "${RELEASE_DIR}" "${LATEST_DIR}"

echo "==> Creating zip artifact"
(
  cd "${RELEASE_ROOT}"
  zip -rq "$(basename "${ZIP_PATH}")" "$(basename "${RELEASE_DIR}")"
)

echo
echo "Release created:"
echo "  Folder: ${RELEASE_DIR}"
echo "  Latest: ${LATEST_DIR}"
echo "  Zip:    ${ZIP_PATH}"
