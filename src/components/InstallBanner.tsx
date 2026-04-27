'use client';

export default function InstallBanner() {
  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50 p-5 text-sm text-amber-900">
      <h3 className="mb-2 font-semibold text-base">DSC Helper Not Detected</h3>
      <p className="mb-3">
        To sign with your USB DSC token this browser tab needs to talk to a small
        local helper application. Install one of the following:
      </p>
      <p className="mb-2">
        <a href="/setup" className="font-semibold underline text-amber-800">
          Open the setup guide →
        </a>
        {' '}(one-time, per computer)
      </p>
      <ol className="list-decimal space-y-2 pl-5">
        <li>
          <strong>emBridge</strong> (eMudhra) — recommended for eMudhra tokens.
          Works with all major tokens via PKCS#11. No self-signed-cert friction.
          <br />
          <a
            href="https://emudhra.com/en/embridge-trust-platform"
            target="_blank"
            rel="noopener noreferrer"
            className="underline text-amber-700"
          >
            Download emBridge →
          </a>
        </li>
        <li>
          <strong>BridgeIt DSC Helper</strong> — open-source, works with any CCA
          Class 3 token (ePass2003, ProxKey, HYP2003, mToken, etc.) via OpenSC /
          vendor PKCS#11.
          <br />
          <span className="text-amber-700 italic">
            Download from the project&apos;s Releases page.
          </span>
        </li>
      </ol>
      <p className="mt-3 text-xs text-amber-700">
        After installation, reload this page. On Chrome, if you installed
        emSigner, visit{' '}
        <code className="font-mono bg-amber-100 px-1 rounded">
          https://127.0.0.1:1585/
        </code>{' '}
        once and click &ldquo;Proceed&rdquo; to trust the self-signed certificate.
      </p>
    </div>
  );
}
