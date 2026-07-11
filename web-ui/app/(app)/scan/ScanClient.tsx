'use client';

import { Button, Input } from '@akasecurity/ui-kit';
import Link from 'next/link';
import { useState, useTransition } from 'react';

import type { ScanResult } from './actions';
import { runScan } from './actions';
import { DirectoryBrowser } from './DirectoryBrowser';

export function ScanClient({ enabledRuleCount }: { enabledRuleCount: number }) {
  const [path, setPath] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [busy, startTransition] = useTransition();

  const submit = () => {
    startTransition(async () => {
      setResult(await runScan(path));
    });
  };

  return (
    <div className="flex max-w-xl flex-col gap-4">
      <div className="rounded-xl border border-border bg-surface p-5">
        <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
          File or directory to scan
        </div>
        <p className="mb-3 text-xs text-text-3">
          Walked recursively (node_modules, dotdirs, build output and files over 1 MB are skipped).
          The raw match never lands on disk — findings store only a masked preview and the event
          keeps a redacted copy. {String(enabledRuleCount)} rule
          {enabledRuleCount === 1 ? '' : 's'} enabled.
        </p>
        <div className="flex items-center gap-2">
          <Input
            value={path}
            onChange={(e) => {
              setPath(e.target.value);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !busy) submit();
            }}
            placeholder="/path/to/project"
            className="font-mono"
          />
          <Button variant="solid" tone="primary" size="sm" disabled={busy} onClick={submit}>
            {busy ? 'Scanning…' : 'Scan'}
          </Button>
          <DirectoryBrowser
            onSelect={(selected) => {
              setPath(selected);
            }}
          />
        </div>

        {result && !result.ok && <p className="mt-3 text-xs text-sev-critical">{result.error}</p>}
        {result?.ok && (
          <div className="mt-3 rounded-lg border border-ok-fill bg-ok-fill px-3 py-2 text-xs text-text">
            Scanned {String(result.scanned)} file{result.scanned === 1 ? '' : 's'} ·{' '}
            {String(result.findings)} finding{result.findings === 1 ? '' : 's'} recorded.{' '}
            {result.findings !== undefined && result.findings > 0 && (
              <Link href="/findings" className="font-semibold text-primary underline">
                View findings
              </Link>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
