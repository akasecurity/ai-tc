'use client';
import type { DetectionException } from '@akasecurity/schema';
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

// The token the user must type to arm the confirm button; re-checked
// server-side by the rotate action.
export const ROTATE_CONFIRMATION = 'rotate';

export interface RotateKeyDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  // Active permanent grants that rotation will orphan — listed so the user
  // sees exactly what stops applying.
  activePermanent: DetectionException[];
  keyVersion: number | null;
  onConfirm: (confirmation: string) => void;
  busy?: boolean;
  error?: string | null;
}

/**
 * Rotate the exception fingerprint key — the web twin of
 * `aka exception rotate-key`. Rotation is INVALIDATION: every existing grant
 * stops matching (rows remain for audit) because fingerprints cannot be
 * re-keyed without the raw values, which are never stored.
 */
export function RotateKeyDialog({
  open,
  onOpenChange,
  activePermanent,
  keyVersion,
  onConfirm,
  busy,
  error,
}: RotateKeyDialogProps) {
  const [typed, setTyped] = useState('');

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) setTyped('');
        onOpenChange(next);
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Rotate the fingerprint key</DialogTitle>
          <DialogDescription>
            Rotation mints a fresh key
            {keyVersion !== null &&
              ` (v${String(keyVersion)} → v${String(keyVersion + 1)})`} and{' '}
            <strong>invalidates every existing exception</strong> — grants cannot be re-keyed and
            simply stop matching. They remain listed for audit.
          </DialogDescription>
        </DialogHeader>

        <DialogBody>
          {activePermanent.length > 0 && (
            <div className="rounded-lg border border-sev-high-fill bg-sev-high-fill p-3">
              <div className="mb-2 text-label font-semibold uppercase tracking-wider text-sev-high">
                Active permanent grants that will stop applying
              </div>
              <ul className="flex flex-col gap-1">
                {activePermanent.map((ex) => (
                  <li key={ex.id} className="font-mono text-xs text-text-2">
                    {ex.ruleId} · {ex.maskedValue}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div>
            <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
              Type “{ROTATE_CONFIRMATION}” to confirm
            </div>
            <Input
              value={typed}
              onChange={(e) => {
                setTyped(e.target.value);
              }}
              autoComplete="off"
            />
          </div>

          {error && <p className="text-xs text-sev-critical">{error}</p>}
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
            tone="danger"
            size="sm"
            disabled={typed !== ROTATE_CONFIRMATION || busy}
            onClick={() => {
              onConfirm(typed);
            }}
          >
            {busy ? 'Rotating…' : 'Rotate key'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
