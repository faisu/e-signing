#!/usr/bin/env bash
#
# Build .deb and .rpm packages for the AutoDCR Bridge.
#
# Inputs (env):
#   AUTODCR_VERSION       (required)  semver
#   AUTODCR_EXTENSION_ID  (required)  Chrome extension id
#
# Inputs (filesystem):
#   artifacts/linux-x64/autodcr-bridge
#
# Outputs:
#   installer/linux/dist/autodcr-bridge_<version>_amd64.deb
#   installer/linux/dist/autodcr-bridge-<version>-1.x86_64.rpm

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
DIST_DIR="${SCRIPT_DIR}/dist"
WORK_DIR="$(mktemp -d)"

BIN_SRC="${REPO_ROOT}/artifacts/linux-x64/autodcr-bridge"
if [[ ! -x "${BIN_SRC}" ]]; then
  chmod +x "${BIN_SRC}" 2>/dev/null || true
fi
if [[ ! -f "${BIN_SRC}" ]]; then
  echo "Linux binary missing at ${BIN_SRC}" >&2
  exit 1
fi

mkdir -p "${DIST_DIR}"

# System-wide native messaging host directories per browser.
BROWSER_DIRS=(
  "/etc/opt/chrome/native-messaging-hosts"
  "/etc/chromium/native-messaging-hosts"
  "/etc/opt/edge/native-messaging-hosts"
  "/etc/opt/brave/native-messaging-hosts"
  "/etc/opt/vivaldi/native-messaging-hosts"
)

# Render manifest with the extension id baked in.
RENDERED_MANIFEST="${WORK_DIR}/com.example.autodcr.signer.json"
sed \
  -e "s|<ABSOLUTE_PATH_TO_LAUNCHER>|/usr/bin/autodcr-bridge|g" \
  -e "s|<EXTENSION_ID_PLACEHOLDER>|${AUTODCR_EXTENSION_ID}|g" \
  "${REPO_ROOT}/native-host/manifests/com.example.autodcr.signer.json" \
  > "${RENDERED_MANIFEST}"

stage_payload() {
  local stage="$1"
  install -Dm755 "${BIN_SRC}" "${stage}/usr/bin/autodcr-bridge"
  for dir in "${BROWSER_DIRS[@]}"; do
    install -Dm644 "${RENDERED_MANIFEST}" \
      "${stage}${dir}/com.example.autodcr.signer.json"
  done
}

# ---------------------------------------------------------------------------
# .deb
# ---------------------------------------------------------------------------
DEB_STAGE="${WORK_DIR}/deb"
mkdir -p "${DEB_STAGE}/DEBIAN"
stage_payload "${DEB_STAGE}"

cat > "${DEB_STAGE}/DEBIAN/control" <<DEBCONTROL
Package: autodcr-bridge
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: AutoDCR <support@autodcr.example>
Description: AutoDCR Chrome native messaging host
 Local helper that proxies signing requests from the AutoDCR browser
 extension to a PKCS#11 module on the user's machine.
DEBCONTROL

DEB_OUT="${DIST_DIR}/autodcr-bridge_${VERSION}_amd64.deb"
fakeroot dpkg-deb --build --root-owner-group "${DEB_STAGE}" "${DEB_OUT}"

# ---------------------------------------------------------------------------
# .rpm
# ---------------------------------------------------------------------------
RPM_BUILDROOT="${WORK_DIR}/rpm-buildroot"
RPM_TOPDIR="${WORK_DIR}/rpmbuild"
mkdir -p "${RPM_TOPDIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
stage_payload "${RPM_BUILDROOT}"

SPEC_FILE="${RPM_TOPDIR}/SPECS/autodcr-bridge.spec"
cat > "${SPEC_FILE}" <<SPEC
Name:           autodcr-bridge
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        AutoDCR Chrome native messaging host
License:        Proprietary
URL:            https://autodcr.example
BuildArch:      x86_64
AutoReqProv:    no

%description
Local helper that proxies signing requests from the AutoDCR browser extension
to a PKCS#11 module on the user's machine.

%install
mkdir -p %{buildroot}
cp -r ${RPM_BUILDROOT}/* %{buildroot}/

%files
/usr/bin/autodcr-bridge
$(for d in "${BROWSER_DIRS[@]}"; do printf '%s/com.example.autodcr.signer.json\n' "${d}"; done)
SPEC

rpmbuild --define "_topdir ${RPM_TOPDIR}" -bb "${SPEC_FILE}"

RPM_BUILT="$(ls "${RPM_TOPDIR}"/RPMS/x86_64/autodcr-bridge-${VERSION}-1*.x86_64.rpm | head -n1)"
RPM_OUT="${DIST_DIR}/$(basename "${RPM_BUILT}")"
cp "${RPM_BUILT}" "${RPM_OUT}"

echo "Built:"
echo "  ${DEB_OUT}"
echo "  ${RPM_OUT}"
