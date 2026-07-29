'use client';

import { ScrubbedValue } from '@akasecurity/dashboard-ui';
import { Button, Input } from '@akasecurity/ui-kit';
import { useState, useTransition } from 'react';

import type { RevealResult } from './actions';
import { revealPointer } from './actions';

export function VaultLookupClient() {
  const [pointer, setPointer] = useState('');
  const [result, setResult] = useState<RevealResult | null>(null);
  const [busy, startTransition] = useTransition();

  const submit = () => {
    if (pointer.trim() === '') return;
    startTransition(async () => {
      setResult(await revealPointer({ pointer }));
    });
  };

  return (
    <div className="flex max-w-xl flex-col gap-4">
      <div className="rounded-xl border border-border bg-surface p-5">
        <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
          Pointer to resolve
        </div>
        <p className="mb-3 text-xs text-text-3">
          Paste the [[aka:...]] token that replaced a detected value. Each successful reveal is
          recorded in the vault&apos;s audit trail.
        </p>
        <div className="flex items-center gap-2">
          <Input
            value={pointer}
            onChange={(e) => {
              setPointer(e.target.value);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !busy) submit();
            }}
            placeholder="[[aka:secret:...]]"
            className="font-mono"
          />
          <Button variant="solid" tone="primary" size="sm" disabled={busy} onClick={submit}>
            {busy ? 'Resolving…' : 'Reveal'}
          </Button>
        </div>

        {result && !result.ok && <p className="mt-3 text-xs text-sev-critical">{result.error}</p>}
        {result?.ok && (
          <div className="mt-3 rounded-lg border border-border bg-surface-2 px-3 py-2">
            <ScrubbedValue value={result.value} descriptor={result.descriptor} />
          </div>
        )}
      </div>
    </div>
  );
}
