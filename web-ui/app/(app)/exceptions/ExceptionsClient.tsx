'use client';

import type { ApproveSubmission, BlockedWindow } from '@akasecurity/dashboard-ui';
import {
  ApproveExceptionDialog,
  BlockedLedgerView,
  ExceptionsTableView,
  PageHead,
  RotateKeyDialog,
} from '@akasecurity/dashboard-ui';
import type {
  BlockedDetectionDescriptor,
  ExceptionDescriptor,
  FingerprintKeyState,
} from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';
import Link from 'next/link';
import { useState, useTransition } from 'react';

import { useNavigationTransition } from '../../components/NavigationTransition';
import { approveBlocked, rotateKey } from './actions';

export function ExceptionsClient({
  items,
  blocked,
  includeTerminal,
  blockedWindow,
  keyState,
  activePermanent,
  approvableBlocked,
}: {
  items: ExceptionDescriptor[];
  blocked: BlockedDetectionDescriptor[];
  includeTerminal: boolean;
  blockedWindow: BlockedWindow;
  keyState: FingerprintKeyState;
  activePermanent: ExceptionDescriptor[];
  approvableBlocked: number;
}) {
  // Navigation transition (the blocked-window filter, the audit toggle and row
  // navigation) — distinct from the write transition below, which tracks the
  // approve/rotate Server Actions.
  const { isPending: navPending, push: pushUrl } = useNavigationTransition();
  // Dim wrapper for a region whose data a pending navigation is replacing. The
  // page has two independently-driven regions, so it is applied per region
  // rather than around the page.
  const dim = cn('transition-opacity duration-150', navPending && 'opacity-60');
  const [approving, setApproving] = useState<BlockedDetectionDescriptor | null>(null);
  const [rotating, setRotating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, startTransition] = useTransition();

  // The rotate button and dialog only label WHICH version is being replaced, so
  // "absent" and "unreadable" both correctly read as unknown there. The strip
  // gets the full state, because for it the two mean different things.
  const keyVersion = keyState.status === 'present' ? keyState.version : null;

  const auditHref = includeTerminal ? '/exceptions' : '/exceptions?all=1';

  const setBlockedWindow = (next: BlockedWindow) => {
    const sp = new URLSearchParams();
    sp.set('window', next);
    if (includeTerminal) sp.set('all', '1');
    pushUrl(`/exceptions?${sp.toString()}`);
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
              {/* A same-route ?all= change, so no loading boundary re-shows for
                  it — a plain left-click is routed through the shared
                  transition instead, which is what dims the table below and
                  raises the shell's progress bar. The href stays real and the
                  modifier/secondary-button cases fall through to the browser,
                  so open-in-new-tab and copy-link still behave as links. */}
              <Link
                href={auditHref}
                onClick={(e) => {
                  if (
                    e.defaultPrevented ||
                    e.button !== 0 ||
                    e.metaKey ||
                    e.ctrlKey ||
                    e.shiftKey ||
                    e.altKey
                  ) {
                    return;
                  }
                  e.preventDefault();
                  pushUrl(auditHref);
                }}
              >
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

      {/* `?window=` re-queries recentBlocked, which is this region's data. */}
      <div aria-busy={navPending} className={dim}>
        <BlockedLedgerView
          items={blocked}
          onApprove={(reference) => {
            setError(null);
            setApproving(blocked.find((b) => b.reference === reference) ?? null);
          }}
          blockedWindow={blockedWindow}
          onBlockedWindowChange={setBlockedWindow}
          keyState={keyState}
        />
      </div>

      {/* `?all=` re-queries exceptions.list, which is this region's data. */}
      <div aria-busy={navPending} className={dim}>
        <ExceptionsTableView
          items={items}
          includeTerminal={includeTerminal}
          onSelect={(id) => {
            pushUrl(`/exceptions/${id.slice(0, 8)}`);
          }}
        />
      </div>

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
        approvableBlocked={approvableBlocked}
        keyVersion={keyVersion}
        onConfirm={submitRotate}
        busy={busy}
        error={error}
      />
    </div>
  );
}
