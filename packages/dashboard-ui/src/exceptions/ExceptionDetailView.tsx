'use client';
import type { DetectionException } from '@akasecurity/schema';
import { Button, Input } from '@akasecurity/ui-kit';
import { useState } from 'react';

import { relativeTime } from '../lib/relativeTime.ts';
import { MetaItem, SectionLabel } from '../shared/DetailFields.tsx';
import { StateTagFor } from './atoms.tsx';
import { exceptionState, SCOPE_LABEL, VIA_LABEL } from './meta.ts';

export interface ExceptionDetailViewProps {
  exception: DetectionException;
  // Provided by the connected layer (a server action in the web-ui); omitted →
  // read-only detail. Only rendered while the grant is still active.
  onRevoke?: ((reason: string) => void) | undefined;
  busy?: boolean;
  error?: string | null;
}

/** Full grant detail — the web twin of `aka exception show <id>`. */
export function ExceptionDetailView({
  exception,
  onRevoke,
  busy,
  error,
}: ExceptionDetailViewProps) {
  const [reason, setReason] = useState('');
  const state = exceptionState(exception);

  return (
    <div className="flex flex-col gap-6 rounded-xl border border-border bg-surface p-5">
      <div className="flex items-center gap-3">
        <span className="font-mono text-sm font-semibold text-text">
          {exception.id.slice(0, 8)}
        </span>
        <StateTagFor exception={exception} />
      </div>

      <div className="grid grid-cols-2 gap-x-6 gap-y-4 md:grid-cols-3">
        <MetaItem label="Rule">
          <span className="font-mono text-xs">{exception.ruleId}</span>
        </MetaItem>
        <MetaItem label="Category">{exception.category}</MetaItem>
        <MetaItem label="Approved value">
          <span className="font-mono text-xs">{exception.maskedValue}</span>
        </MetaItem>
        <MetaItem label="Scope">
          {SCOPE_LABEL[exception.scope]}
          {exception.scope === 'permanent' && ' — until revoked'}
        </MetaItem>
        <MetaItem label="Expires">
          {exception.expiresAt === null ? '—' : relativeTime(exception.expiresAt)}
        </MetaItem>
        <MetaItem label="Uses">
          {exception.maxUses === null
            ? String(exception.useCount)
            : `${String(exception.useCount)}/${String(exception.maxUses)}`}
          {exception.lastUsedAt && ` · last ${relativeTime(exception.lastUsedAt)}`}
        </MetaItem>
        <MetaItem label="Created">
          {relativeTime(exception.createdAt)} by {exception.createdBy} via{' '}
          {VIA_LABEL[exception.createdVia]}
        </MetaItem>
        <MetaItem label="Key version">{String(exception.keyVersion)}</MetaItem>
        <MetaItem label="Fingerprint">
          <span className="font-mono text-xs text-text-3">
            {exception.valueFingerprint.slice(0, 16)}…
          </span>
        </MetaItem>
      </div>

      <div>
        <SectionLabel>Justification</SectionLabel>
        <p className="text-sm text-text-2">{exception.justification}</p>
      </div>

      {exception.revokedAt !== null && (
        <div className="rounded-lg border border-sev-critical-fill bg-sev-critical-fill p-3">
          <SectionLabel className="text-sev-critical">Revoked</SectionLabel>
          <p className="text-sm text-text-2">
            {relativeTime(exception.revokedAt)} by {exception.revokedBy ?? 'unknown'}
            {exception.revokeReason ? ` — ${exception.revokeReason}` : ''}
          </p>
        </div>
      )}

      {onRevoke && state === 'active' && (
        <div className="border-t border-border pt-4">
          <SectionLabel>Revoke this grant</SectionLabel>
          <p className="mb-2 text-xs text-text-3">
            Revocation is immediate and terminal; the row is retained as audit evidence.
          </p>
          <div className="flex items-center gap-2">
            <Input
              value={reason}
              onChange={(e) => {
                setReason(e.target.value);
              }}
              placeholder="Reason (recorded in the audit trail)"
              className="max-w-sm"
            />
            <Button
              variant="solid"
              tone="danger"
              size="sm"
              disabled={busy}
              onClick={() => {
                onRevoke(reason.trim());
              }}
            >
              Revoke
            </Button>
          </div>
          {error && <p className="mt-2 text-xs text-sev-critical">{error}</p>}
        </div>
      )}
    </div>
  );
}
