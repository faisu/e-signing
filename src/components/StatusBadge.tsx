'use client';

import type { SigningStatus, SigningError } from '@/types/signing';

const LABELS: Record<SigningStatus, string> = {
  idle: '',
  detecting: 'Detecting DSC helper…',
  enumerating: 'Reading certificates from token…',
  preparing: 'Preparing PDF…',
  signing: 'Waiting for token PIN — approve on the helper dialog',
  embedding: 'Embedding signature…',
  timestamping: 'Adding RFC 3161 timestamp…',
  done: 'Document signed successfully',
  error: '',
};

interface Props {
  status: SigningStatus;
  error: SigningError | null;
}

export default function StatusBadge({ status, error }: Props) {
  if (status === 'idle') return null;

  if (status === 'error' && error) {
    return (
      <div className="rounded-md bg-red-50 border border-red-300 px-4 py-3 text-sm text-red-800">
        <span className="font-semibold">Error: </span>
        {error.message}
        {error.code === 'helper_not_found' && (
          <span className="block mt-1 text-xs text-red-600">
            Make sure emBridge or the BridgeIt DSC Helper is running.
          </span>
        )}
      </div>
    );
  }

  if (status === 'done') {
    return (
      <div className="rounded-md bg-green-50 border border-green-300 px-4 py-3 text-sm text-green-800 font-medium">
        ✓ {LABELS.done}
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 text-sm text-gray-600">
      <svg className="animate-spin h-4 w-4 text-blue-500" viewBox="0 0 24 24" fill="none">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
      </svg>
      {LABELS[status]}
    </div>
  );
}
