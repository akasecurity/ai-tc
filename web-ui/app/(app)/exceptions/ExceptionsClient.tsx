'use client';

import type { ApproveSubmission, BlockedWindow } from '@akasecurity/dashboard-ui';
import {
  ApproveExceptionDialog,
  BlockedLedgerView,
  ExceptionsTableView,
  PageHead,
  RotateKeyDialog,
} from '@akasecurity/dashboard-ui';
import type { BlockedDetection, DetectionException } from '@akasecurity/schema';
import { Button } from '@akasecurity/ui-kit';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, useTransition } from 'react';

import { approveBlocked, rotateKey } from './actions';

export function ExceptionsClient({
  items,
  blocked,
  includeTerminal,
  blockedWindow,
  keyVersion,
  activePermanent,
}: {
  items: DetectionException[];
  blocked: BlockedDetection[];
  includeTerminal: boolean;
  blockedWindow: BlockedWindow;
  keyVersion: number | null;
  activePermanent: DetectionException[];
}) {
  const router = useRouter();
  const [approving, setApproving] = useState<BlockedDetection | null>(null);
  const [rotating, setRotating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, startTransition] = useTransition();

  const setBlockedWindow = (next: BlockedWindow) => {
    const sp = new URLSearchParams();
    sp.set('window', next);
    if (includeTerminal) sp.set('all', '1');
    router.push(`/exceptions?${sp.toString()}`);
  };

  const submitApprove = (submission: ApproveSubmission) => {
    startTransition(async () => {
      const result = await approveBlocked(submission);
      if (result.ok) {
        setApproving(null);
        setError(null);
      } else {
        setError(result.error ?? 'Could not grant the exception.');
      }
    });
  };

  const submitRotate = (confirmation: string) => {
    startTransition(async () => {
      const result = await rotateKey(confirmation);
      if (result.ok) {
        setRotating(false);
        setError(null);
      } else {
        setError(result.error ?? 'Could not rotate the key.');
      }
    });
  };

  return (
    <div className="px-8 pb-10 pt-7">
      <PageHead
        title="Exceptions"
        sub="Explicit, audited bypasses — one exact value each, never a rule-wide suppression"
        actions={
          <>
            <Button asChild variant="ghost" tone="neutral" size="sm">
              <Link href={includeTerminal ? '/exceptions' : '/exceptions?all=1'}>
                {includeTerminal ? 'Active only' : 'Show all (audit)'}
              </Link>
            </Button>
            <Button
              variant="outline"
              tone="neutral"
              size="sm"
              onClick={() => {
                setError(null);
                setRotating(true);
              }}
            >
              Rotate key{keyVersion !== null && ` (v${String(keyVersion)})`}
            </Button>
            <Button asChild variant="solid" tone="primary" size="sm">
              <Link href="/exceptions/new">Pre-authorize a value</Link>
            </Button>
          </>
        }
      />

      <BlockedLedgerView
        items={blocked}
        onApprove={(reference) => {
          setError(null);
          setApproving(blocked.find((b) => b.reference === reference) ?? null);
        }}
        blockedWindow={blockedWindow}
        onBlockedWindowChange={setBlockedWindow}
      />

      <ExceptionsTableView
        items={items}
        includeTerminal={includeTerminal}
        onSelect={(id) => {
          router.push(`/exceptions/${id.slice(0, 8)}`);
        }}
      />

      <ApproveExceptionDialog
        entry={approving}
        open={approving !== null}
        onOpenChange={(open) => {
          if (!open) {
            setApproving(null);
            setError(null);
          }
        }}
        onSubmit={submitApprove}
        busy={busy}
        error={error}
      />

      <RotateKeyDialog
        open={rotating}
        onOpenChange={(open) => {
          setRotating(open);
          if (!open) setError(null);
        }}
        activePermanent={activePermanent}
        keyVersion={keyVersion}
        onConfirm={submitRotate}
        busy={busy}
        error={error}
      />
    </div>
  );
}
