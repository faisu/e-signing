'use client';
/**
 * One-time setup page — each client visits this after installing the helper.
 * It registers the app's origin with the local helper so CORS is allowed.
 */

import { useState, useEffect } from 'react';

type Step = 'detect' | 'register' | 'trust' | 'done' | 'error';

const HELPER_URL = 'https://127.0.0.1:7777';

const DOWNLOAD_BASE = 'https://bridgeit-global.github.io/dsc-helper/artifacts';

function detectDownloadUrl(): { url: string; label: string; instructions: string } {
  if (typeof window === 'undefined') return { url: '#', label: 'Download installer', instructions: '' };
  const p = (navigator.userAgentData?.platform ?? navigator.platform ?? '').toLowerCase();
  if (p.includes('win')) {
    return {
      url: `${DOWNLOAD_BASE}/bridgeit-helper-win.exe`,
      label: 'Download for Windows (.exe)',
      instructions: 'Run the installer as Administrator. It installs the helper and registers it as a Windows service.',
    };
  }
  if (p.includes('mac') || p.includes('iphone') || p.includes('ipad')) {
    return {
      url: `${DOWNLOAD_BASE}/bridgeit-helper-mac-arm64`,
      label: 'Download for macOS (Apple Silicon)',
      instructions: 'Double-click the .pkg file and follow the installer. The helper starts automatically at login.',
    };
  }
  return {
    url: `${DOWNLOAD_BASE}/bridgeit-helper-linux`,
    label: 'Download for Linux',
    instructions: 'Extract the archive and run install.sh. It registers a systemd user service that starts at login.',
  };
}

export default function SetupPage() {
  const [step, setStep]     = useState<Step>('detect');
  const [error, setError]   = useState('');
  const [helperVer, setHelperVer] = useState('');
  const download = detectDownloadUrl();

  const appOrigin = typeof window !== 'undefined' ? window.location.origin : '';

  async function detect() {
    setStep('detect');
    setError('');
    try {
      const r = await fetch(`${HELPER_URL}/version`, { mode: 'cors', cache: 'no-store', signal: AbortSignal.timeout(2000) });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = await r.json();
      setHelperVer(data.version ?? '');
      // Check if this origin is already registered
      const origins: string[] = data.allowedOrigins ?? [];
      if (origins.includes(appOrigin)) {
        setStep('done');
      } else {
        setStep('register');
      }
    } catch {
      setStep('trust');
    }
  }

  useEffect(() => { detect(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function register() {
    setError('');
    try {
      const r = await fetch(`${HELPER_URL}/configure`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ allowedOrigins: [appOrigin] }),
        mode: 'cors',
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setStep('done');
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <main className="mx-auto max-w-lg px-4 py-12 space-y-8">
      <div>
        <h1 className="text-2xl font-bold">DSC Helper Setup</h1>
        <p className="text-sm text-gray-500 mt-1">
          One-time setup — run this once on each computer that will sign documents.
        </p>
      </div>

      {/* Step: trust the cert */}
      {step === 'trust' && (
        <div className="rounded-xl border bg-white p-6 space-y-4 shadow-sm">
          <h2 className="font-semibold text-amber-700">Step 1 — Install and trust the helper</h2>
          <ol className="list-decimal pl-5 space-y-3 text-sm">
            <li>
              <a
                href={download.url}
                className="inline-block rounded-lg bg-blue-600 text-white px-4 py-2 text-sm font-semibold"
              >
                {download.label}
              </a>
              <p className="mt-1 text-gray-500">{download.instructions}</p>
            </li>
            <li>
              Once installed, open{' '}
              <a
                href={`${HELPER_URL}/version`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 underline font-mono text-xs"
              >
                {HELPER_URL}/version
              </a>{' '}
              in a new tab and click <strong>&ldquo;Advanced → Proceed&rdquo;</strong> to trust the
              self-signed certificate. (Chrome: &ldquo;Proceed to 127.0.0.1 (unsafe)&rdquo; — this
              is a local-only certificate and is safe to accept.)
            </li>
            <li>Return here and click <strong>Re-check</strong>.</li>
          </ol>
          <button
            onClick={detect}
            className="w-full rounded-lg bg-blue-600 text-white py-2 text-sm font-semibold"
          >
            Re-check helper
          </button>
        </div>
      )}

      {/* Step: register origin */}
      {step === 'register' && (
        <div className="rounded-xl border bg-white p-6 space-y-4 shadow-sm">
          <h2 className="font-semibold">Step 2 — Allow this site</h2>
          <p className="text-sm text-gray-600">
            Helper v{helperVer} detected. Register{' '}
            <code className="font-mono bg-gray-100 px-1 rounded">{appOrigin}</code>{' '}
            so the helper accepts requests from this page.
          </p>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <button
            onClick={register}
            className="w-full rounded-lg bg-green-600 text-white py-2 text-sm font-semibold"
          >
            Register this site with the helper
          </button>
        </div>
      )}

      {/* Done */}
      {step === 'done' && (
        <div className="rounded-xl border border-green-300 bg-green-50 p-6 space-y-3">
          <h2 className="font-semibold text-green-800">Setup complete</h2>
          <p className="text-sm text-green-700">
            The helper is running and this site is registered.
            You can now sign documents from any page on this site.
          </p>
          <a
            href="/"
            className="block w-full text-center rounded-lg bg-green-600 text-white py-2 text-sm font-semibold"
          >
            Go to signing page
          </a>
        </div>
      )}

      {/* Detecting */}
      {step === 'detect' && (
        <p className="text-sm text-gray-500 animate-pulse">Checking helper…</p>
      )}

      {/* Error */}
      {step === 'error' && (
        <div className="text-sm text-red-600 bg-red-50 border border-red-300 rounded p-4">
          {error}
        </div>
      )}

      {/* Instructions for remote deployment */}
      <details className="text-xs text-gray-500">
        <summary className="cursor-pointer font-medium">Using a remote server?</summary>
        <div className="mt-2 space-y-2 leading-relaxed">
          <p>
            The Next.js app can run on any server (Vercel, AWS, VPS, etc.).
            Each client computer only needs the <strong>BridgeIt DSC Helper</strong> running locally —
            it listens on <code className="font-mono">127.0.0.1:7777</code> and is only
            reachable by the browser on that machine.
          </p>
          <p>
            The signing flow: server computes the hash → browser sends it to the local helper →
            helper signs with the USB token → browser sends signature back to server →
            server assembles the final signed PDF. The private key never leaves the token.
          </p>
          <p>
            To allow your domain automatically, start the helper with:
          </p>
          <pre className="bg-gray-100 rounded px-3 py-2 text-xs overflow-x-auto">
            {`ALLOWED_ORIGINS=https://yourapp.com node src/server.js`}
          </pre>
        </div>
      </details>
    </main>
  );
}
