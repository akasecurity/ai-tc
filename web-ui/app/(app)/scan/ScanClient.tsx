'use client';

import { Button, Input } from '@akasecurity/ui-kit';
import Link from 'next/link';
import { useState, useTransition } from 'react';

import type { ScanResult } from './actions';
import { runScan } from './actions';
import { DirectoryBrowser } from './DirectoryBrowser';

export function ScanClient({
  enabledRuleCount,
  attachedTo,
}: {
  enabledRuleCount: number;
  /** The attached deployment's display name, or null on a standalone install. */
  attachedTo: string | null;
}) {
  const [path, setPath] = useState('');
  // Whether THIS scan sends the register it records. Default on: an attached
  // machine forwards, and the box is how one scan of a tree that should stay
  // local opts out without detaching the whole machine.
  const [forward, setForward] = useState(true);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [busy, startTransition] = useTransition();

  // What became of the register on an attached machine, or null on one that is
  // attached to nothing — which renders no line at all, so a standalone
  // install's page is what it always was. Wording and tone were both decided
  // on the server by the copy module; nothing here re-reads the status.
  const forwarded = result?.forwardLine ?? null;

  const submit = () => {
    startTransition(async () => {
      setResult(await runScan(path, { forward }));
    });
  };

  return (
    <div className="flex max-w-3xl flex-col gap-4">
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
        {/* Said BEFORE the click, on the surface that starts the send: an attached
            machine forwards what this scan records, and the box is the per-scan
            way to keep one tree local without detaching. */}
        {attachedTo !== null && (
          <div className="mb-3 rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs text-text-2">
            <p>
              This machine is attached to {attachedTo}. The Data Shares register this scan records —
              destinations and call sites, never source text — is sent there.
            </p>
            <label className="mt-1.5 flex items-center gap-2">
              <input
                type="checkbox"
                checked={forward}
                onChange={(e) => {
                  setForward(e.target.checked);
                }}
              />
              <span>Send the Data Shares register to {attachedTo}</span>
            </label>
          </div>
        )}
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

        {result && !result.ok && (
          <p className="mt-3 text-xs text-sev-critical-ink">{result.error}</p>
        )}
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
        {/* Also outside the ok/error branches: a scan that finished with a
            smaller ruleset than the Detections page lists has to say so, and a
            scan that failed on pack state may still have dropped rules on top
            of that. */}
        {result?.droppedRules && (
          <p className="mt-2 text-xs text-sev-medium-ink">{result.droppedRules}</p>
        )}
        {/* Outside the ok/error branches above: egress extraction does not read
            the ruleset, so destinations are recorded — and worth surfacing —
            even when the scan had no usable packs to run. */}
        {result?.egress && (
          <p className="mt-2 text-xs text-text-2">
            Data shares: {String(result.egress.destinations)} destination
            {result.egress.destinations === 1 ? '' : 's'} · {String(result.egress.endpoints)}{' '}
            endpoint{result.egress.endpoints === 1 ? '' : 's'} · {String(result.egress.callSites)}{' '}
            call site{result.egress.callSites === 1 ? '' : 's'} recorded
            {result.egress.truncated ? ' (capped)' : ''}.{' '}
            <Link href="/data-shares" className="font-semibold text-primary underline">
              View data shares
            </Link>
          </p>
        )}
        {/* Under the recorded counts, because it is about the same register: a
            machine attached to a deployment sends it there too, and a refusal is
            the only place the user would learn that the fleet's view of this
            project is now behind their own. */}
        {forwarded && (
          <p
            className={`mt-1 text-xs ${
              forwarded.tone === 'warning' ? 'text-sev-medium-ink' : 'text-text-2'
            }`}
          >
            {forwarded.text}
          </p>
        )}
      </div>
    </div>
  );
}
