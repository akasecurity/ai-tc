'use client';
import type { BlockedDetection } from '@akasecurity/schema';
import {
  Button,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
} from '@akasecurity/ui-kit';
import { useState } from 'react';

import { ScopePicker } from './atoms.tsx';
import type { ScopeAnswer } from './meta.ts';

export interface ApproveSubmission {
  reference: string;
  scope: ScopeAnswer;
  reason: string;
  // Present when scope is permanent: the retyped masked value. The server
  // action re-checks it (the client gate is a convenience, not the control).
  confirmation?: string;
}

export interface ApproveExceptionDialogProps {
  entry: BlockedDetection | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (submission: ApproveSubmission) => void;
  busy?: boolean;
  error?: string | null;
}

/**
 * Grant an exception from a blocked-ledger entry — the web twin of
 * `aka exception approve`. Scope is an explicit choice (never defaulted), a
 * reason is mandatory, and a permanent grant requires retyping the masked
 * value, mirroring the CLI's typed confirmation.
 */
export function ApproveExceptionDialog({
  entry,
  open,
  onOpenChange,
  onSubmit,
  busy,
  error,
}: ApproveExceptionDialogProps) {
  const [scope, setScope] = useState<ScopeAnswer | null>(null);
  const [reason, setReason] = useState('');
  const [confirmation, setConfirmation] = useState('');

  const needsConfirmation = scope === 'permanent';
  const ready =
    entry !== null &&
    scope !== null &&
    reason.trim() !== '' &&
    (!needsConfirmation || confirmation === entry.maskedValue);

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) {
          setScope(null);
          setReason('');
          setConfirmation('');
        }
        onOpenChange(next);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Approve blocked detection</DialogTitle>
          <DialogDescription>
            Grant an explicit, audited bypass for this exact value. Enforcement continues for every
            other value.
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          {entry && (
            <div className="flex flex-col gap-4">
              <div className="rounded-lg border border-border bg-surface-2 p-3 text-xs">
                <div className="font-mono font-semibold text-text">{entry.ruleId}</div>
                <div className="mt-1 font-mono text-text-2">{entry.maskedValue}</div>
              </div>

              <div>
                <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
                  Scope — pick one
                </div>
                <ScopePicker value={scope} onChange={setScope} />
              </div>

              <div>
                <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
                  Reason (required — the audit trail)
                </div>
                <Input
                  value={reason}
                  onChange={(e) => {
                    setReason(e.target.value);
                  }}
                  placeholder="Why this value may pass"
                />
              </div>

              {needsConfirmation && (
                <div>
                  <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
                    Type the masked value to confirm a permanent grant
                  </div>
                  <Input
                    value={confirmation}
                    onChange={(e) => {
                      setConfirmation(e.target.value);
                    }}
                    placeholder={entry.maskedValue}
                    autoComplete="off"
                    className="font-mono"
                  />
                </div>
              )}

              {error && <p className="text-xs text-sev-critical">{error}</p>}
            </div>
          )}
        </DialogBody>

        <DialogFooter>
          <Button
            variant="ghost"
            tone="neutral"
            size="sm"
            onClick={() => {
              onOpenChange(false);
            }}
          >
            Cancel
          </Button>
          <Button
            variant="solid"
            tone="primary"
            size="sm"
            disabled={!ready || busy}
            onClick={() => {
              if (!entry || !scope) return;
              onSubmit({
                reference: entry.reference,
                scope,
                reason: reason.trim(),
                ...(needsConfirmation ? { confirmation } : {}),
              });
            }}
          >
            {busy ? 'Granting…' : 'Grant exception'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
