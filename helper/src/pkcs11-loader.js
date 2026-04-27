'use strict';
/**
 * PKCS#11 module loader.
 *
 * Tries vendor-specific library paths in order, returns the first
 * one that loads without throwing. Add your token's library path here.
 *
 * Finding your library:
 *   Windows: usually C:\Windows\System32\<vendor>.dll
 *   macOS:   /Library/Security/tokend/<vendor>.tokend/Contents/MacOS/<lib>.dylib
 *            or /usr/local/lib/<lib>.dylib
 *   Linux:   /usr/lib/<lib>.so or /usr/local/lib/<lib>.so
 */

const os = require('os');
const path = require('path');

const KNOWN_LIBS = {
  win32: [
    // ePass2003 (eMudhra, most common)
    'C:\\Windows\\System32\\eps2003csp11.dll',
    // ProxKey (WatchData)
    'C:\\Windows\\System32\\ngp11v211.dll',
    // HYP2003 (Hyper)
    'C:\\Windows\\System32\\HYPIDFV.dll',
    // mToken / TrustKey
    'C:\\Windows\\System32\\eTPKCS11.dll',
    // SafeNet eToken (Gemalto / Thales)
    'C:\\Windows\\System32\\eToken.dll',
    // OpenSC generic
    'C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll',
  ],
  darwin: [
    '/usr/local/lib/opensc-pkcs11.so',
    '/usr/lib/opensc-pkcs11.so',
    // Safenet eToken
    '/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib',
    // eMudhra
    '/usr/local/lib/eps2003csp11.dylib',
  ],
  linux: [
    '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
    '/usr/lib/opensc-pkcs11.so',
    '/usr/local/lib/opensc-pkcs11.so',
    '/usr/lib/eps2003csp11.so',
    '/usr/local/lib/eps2003csp11.so',
  ],
};

/**
 * @returns {{ lib: import('graphene-pk11').Module, path: string } | null}
 */
function loadPkcs11Module(customPath) {
  // When running as a pkg binary, graphene.node is pre-extracted and its path
  // stored in _GRAPHENE_NODE_PATH. Otherwise fall back to the npm module.
  const { Module } = process.env._GRAPHENE_NODE_PATH
    ? require(process.env._GRAPHENE_NODE_PATH)
    : require('graphene-pk11');
  const platform = os.platform();
  const candidates = customPath
    ? [customPath, ...(KNOWN_LIBS[platform] ?? [])]
    : (KNOWN_LIBS[platform] ?? []);

  for (const libPath of candidates) {
    try {
      const lib = Module.load(libPath);
      lib.initialize();
      console.log(`[pkcs11] Loaded: ${libPath}`);
      return { lib, path: libPath };
    } catch {
      // Not installed or wrong arch — try next
    }
  }
  return null;
}

module.exports = { loadPkcs11Module };
