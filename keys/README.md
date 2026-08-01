# Stable Chrome extension ID for AutoDCR signer
#
# Public key is pinned in `src/manifest.json` (`key` field) so every Load
# unpacked / zip install gets the same extension ID:
#
#   hgpcemglhcgkblfnnejacallfmfipddl
#
# Bake that ID into native-host installers:
#
#   AUTODCR_EXTENSION_ID=hgpcemglhcgkblfnnejacallfmfipddl npm run build:release
#
# Or set GitHub Actions repo variable `AUTODCR_EXTENSION_ID` to the same value.
#
# `extension.pem` is the private key (gitignored). Keep a secure backup if you
# later pack a signed `.crx` or publish to the Chrome Web Store with this ID.
# `extension-public-key.b64` / `extension-id.txt` are derived references only.

See also: docs/NATIVE_HOST_INSTALL.md, docs/NATIVE_HOST_DEV.md
