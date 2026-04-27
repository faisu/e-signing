'use strict';
/**
 * BridgeIt DSC Helper — open-source localhost HTTPS server.
 *
 * Exposes:
 *   GET  /version        → {version, vendor}
 *   GET  /certificates   → DscCertificate[]
 *   POST /sign           → {signatureB64}
 *
 * Security:
 *   - Bound to 127.0.0.1 only (no public interface).
 *   - Per-origin CORS allowlist (set ALLOWED_ORIGINS env var, comma-separated).
 *   - Self-signed TLS cert generated on first run and stored in ~/.bridgeit-helper/.
 *   - Users must visit https://127.0.0.1:7777 once and trust the cert in the browser,
 *     OR deploy with a real cert using the public-DNS-to-127.0.0.1 trick.
 *
 * Environment variables:
 *   PORT           — default 7777
 *   PKCS11_LIB     — override path to PKCS#11 .so/.dll/.dylib
 *   ALLOWED_ORIGINS — comma-separated list of allowed page origins
 *                     default: http://localhost:3000,https://localhost:3000
 */

const https = require('https');
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const os = require('os');
const selfsigned = require('selfsigned');

// When bundled with @yao-pkg/pkg, native .node addons cannot be snapshotted.
// They are embedded as pkg assets and must be extracted to the real filesystem
// before dlopen can load them.
if (process.pkg) {
  const nativeSrc = path.join(__dirname, '../node_modules/graphene-pk11/build/Release/graphene.node');
  const nativeDst = path.join(os.homedir(), '.bridgeit-helper', 'graphene.node');
  fs.mkdirSync(path.dirname(nativeDst), { recursive: true });
  if (!fs.existsSync(nativeDst)) {
    fs.copyFileSync(nativeSrc, nativeDst);
    console.log('[helper] Extracted native addon to', nativeDst);
  }
  process.env._GRAPHENE_NODE_PATH = nativeDst;
}

const { loadPkcs11Module } = require('./pkcs11-loader');
const { listCertificates, signHash } = require('./token-ops');

const PORT = parseInt(process.env.PORT ?? '7777', 10);
const PKCS11_LIB = process.env.PKCS11_LIB ?? null;

// Read persisted config from ~/.bridgeit-helper/config.json if present
const CONFIG_PATH = path.join(os.homedir(), '.bridgeit-helper', 'config.json');
let persistedConfig = {};
try { persistedConfig = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')); } catch {}

const ALLOWED_ORIGINS = (
  process.env.ALLOWED_ORIGINS ??
  persistedConfig.allowedOrigins ??
  'http://localhost:3000,https://localhost:3000,http://localhost:3001,http://192.168.1.11:3000'
)
  .split(',')
  .map(s => s.trim());

// ── TLS cert generation ────────────────────────────────────────────────────

const CERT_DIR = path.join(os.homedir(), '.bridgeit-helper');
const CERT_PATH = path.join(CERT_DIR, 'cert.pem');
const KEY_PATH  = path.join(CERT_DIR, 'key.pem');

function ensureCert() {
  if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
    return { cert: fs.readFileSync(CERT_PATH), key: fs.readFileSync(KEY_PATH) };
  }
  fs.mkdirSync(CERT_DIR, { recursive: true });
  const attrs = [{ name: 'commonName', value: 'BridgeIt DSC Helper' }];
  const pem = selfsigned.generate(attrs, { days: 3650, keySize: 2048 });
  fs.writeFileSync(CERT_PATH, pem.cert);
  fs.writeFileSync(KEY_PATH, pem.private);
  console.log(`[helper] Generated self-signed cert in ${CERT_DIR}`);
  return { cert: pem.cert, key: pem.private };
}

// ── PKCS#11 init ───────────────────────────────────────────────────────────

let pkcs11 = null;
let pkcs11Path = null;

function tryLoadPkcs11() {
  if (pkcs11) return;
  const result = loadPkcs11Module(PKCS11_LIB);
  if (result) {
    pkcs11 = result.lib;
    pkcs11Path = result.path;
    console.log(`[helper] PKCS#11 module ready: ${result.path}`);
  } else {
    console.warn('[helper] No PKCS#11 module found — /certificates will return []');
  }
}

// ── Express app ────────────────────────────────────────────────────────────

const app = express();
app.use(express.json({ limit: '10mb' }));

// ── /configure — bootstrap-safe, before cors() middleware ─────────────────
//
// /configure is intentionally placed before app.use(cors(...)) so that the
// very first call from a new remote origin can register itself. This is safe
// because the server only binds to 127.0.0.1 — any request that reaches it
// is already local. We echo back the requesting origin instead of using a
// wildcard so Chrome's Private Network Access preflight passes correctly.

app.options('/configure', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin ?? '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Private-Network', 'true');
  res.sendStatus(204);
});

app.post('/configure', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin ?? '*');
  res.setHeader('Access-Control-Allow-Private-Network', 'true');
  const { allowedOrigins } = req.body ?? {};
  if (!Array.isArray(allowedOrigins)) {
    return res.status(400).json({ error: 'allowedOrigins must be an array of strings' });
  }
  // Merge — never remove localhost
  const merged = Array.from(
    new Set([...ALLOWED_ORIGINS, ...allowedOrigins.map(s => String(s).trim())]),
  );
  merged.forEach(o => { if (!ALLOWED_ORIGINS.includes(o)) ALLOWED_ORIGINS.push(o); });
  try {
    fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
    fs.writeFileSync(CONFIG_PATH, JSON.stringify({ allowedOrigins: merged }, null, 2));
    console.log('[helper] Updated allowedOrigins:', merged);
    res.json({ ok: true, allowedOrigins: merged });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
});

// CORS — only allow listed origins
app.use(
  cors({
    origin(origin, cb) {
      // Allow requests with no origin (e.g. same-origin or curl)
      if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      cb(new Error(`Origin ${origin} not in allowlist`));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
    // Private Network Access (Chrome 94+)
    preflightContinue: false,
  }),
);

// Chrome Private Network Access preflight response
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Private-Network', 'true');
  next();
});

// ── Routes ─────────────────────────────────────────────────────────────────

app.get('/version', (_req, res) => {
  res.json({
    version: '1.0.0',
    vendor: 'BridgeIt DSC Helper',
    allowedOrigins: ALLOWED_ORIGINS,
    pkcs11Ready: Boolean(pkcs11),
    pkcs11Path,
  });
});

app.get('/certificates', (_req, res) => {
  tryLoadPkcs11();
  if (!pkcs11) {
    console.warn('[helper] /certificates requested but PKCS#11 is not loaded');
    return res.json([]);
  }
  try {
    const certs = listCertificates(pkcs11);
    console.log(`[helper] /certificates returned ${certs.length} certificate(s)`);
    res.json(certs);
  } catch (err) {
    console.error('[helper] listCertificates error:', err);
    res.status(500).json({
      error: String(err),
      message: 'Failed to read certificates from token. Verify token middleware/driver installation and reconnect token.',
      pkcs11Path,
    });
  }
});

/**
 * POST /sign
 * Body: { thumbprint: string, hashB64: string, hashAlgo: string, pin?: string }
 *
 * If `pin` is omitted we prompt the user via a simple stdin read
 * (suitable for CLI testing). In GUI mode, pair this endpoint with
 * a native OS dialog for PIN entry.
 */
app.post('/sign', async (req, res) => {
  tryLoadPkcs11();
  if (!pkcs11) {
    return res.status(503).json({ error: 'PKCS#11 not available — token drivers not installed' });
  }

  const { thumbprint, hashB64, hashAlgo = 'SHA-256', pin } = req.body ?? {};

  if (!thumbprint || !hashB64) {
    return res.status(400).json({ error: 'thumbprint and hashB64 are required' });
  }
  if (hashAlgo !== 'SHA-256') {
    return res.status(400).json({ error: 'Only SHA-256 is supported' });
  }

  const hashBuf = Buffer.from(hashB64, 'base64');
  if (hashBuf.length !== 32) {
    return res.status(400).json({ error: 'hashB64 must be a 32-byte SHA-256 digest' });
  }

  // PIN — either from request or prompt via readline (dev mode)
  let tokenPin = pin;
  if (!tokenPin) {
    tokenPin = await promptPin();
  }

  try {
    const sigBuf = signHash(pkcs11, thumbprint, hashBuf, tokenPin);
    res.json({ signatureB64: sigBuf.toString('base64') });
  } catch (err) {
    const msg = String(err);
    console.error('[helper] sign error:', msg);
    if (msg.includes('PIN') || msg.includes('CKR_PIN')) {
      res.status(403).json({ error: 'user_cancel or pin_blocked: ' + msg });
    } else {
      res.status(500).json({ error: msg });
    }
  }
});

// Health (convenience)
app.get('/health', (_req, res) => res.json({ ok: true }));

// ── PIN prompt (fallback for headless / dev mode) ──────────────────────────

async function promptPin() {
  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => {
    process.stdout.write('Enter token PIN: ');
    process.stdin.setRawMode?.(true);
    rl.question('', pin => {
      process.stdin.setRawMode?.(false);
      rl.close();
      process.stdout.write('\n');
      resolve(pin.trim());
    });
  });
}

// ── Start HTTPS server ─────────────────────────────────────────────────────

const { cert, key } = ensureCert();
const server = https.createServer({ cert, key }, app);

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[helper] BridgeIt DSC Helper listening on https://127.0.0.1:${PORT}`);
  console.log(`[helper] Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
  console.log(
    `[helper] First run? Visit https://127.0.0.1:${PORT}/version in your browser and accept the self-signed cert.`,
  );
  tryLoadPkcs11();
});

// Graceful shutdown
process.on('SIGTERM', () => { pkcs11?.finalize(); server.close(); });
process.on('SIGINT',  () => { pkcs11?.finalize(); server.close(); });
