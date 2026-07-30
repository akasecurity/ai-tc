'use client';

import {
  DerefAuditTableView,
  ScrubbedValue,
  VaultInventoryView,
  VaultReuseView,
} from '@akasecurity/dashboard-ui';
import type { VaultDeref, VaultInventoryEntry } from '@akasecurity/schema';
import { Button, Input } from '@akasecurity/ui-kit';
import { useState, useTransition } from 'react';

import type { PurgeVaultResult, RotateVaultKeyResult } from './actions';
import { purgeVault, revealEntry, revokeRevealGrant, rotateVaultKey } from './actions';

interface VaultDashboardClientProps {
  inventory: VaultInventoryEntry[];
  // The audit trail with the batched render reasons hidden (the default), plus
  // the unfiltered variant so the toggle needs no round-trip.
  derefRows: VaultDeref[];
  hiddenBatched: number;
  allDerefRows: VaultDeref[];
}

function SectionHead({ title, sub }: { title: string; sub: string }) {
  return (
    <div>
      <h2 className="text-sm font-semibold text-text">{title}</h2>
      <p className="mt-0.5 text-xs text-text-3">{sub}</p>
    </div>
  );
}

/**
 * The interactive half of the vault page: the inventory with its reveal and
 * revoke actions, the reuse and audit views, and the maintenance panel (key
 * rotation and the purge). Revealed values live in component state only —
 * never persisted, gone when the strip is hidden or the page unmounts.
 */
export function VaultDashboardClient({
  inventory,
  derefRows,
  hiddenBatched,
  allDerefRows,
}: VaultDashboardClientProps) {
  // pointerId → revealed value; null means the vault could not resolve it.
  const [revealed, setRevealed] = useState<Record<string, string | null>>({});
  const [actionError, setActionError] = useState<string | null>(null);
  const [rowBusy, startRowTransition] = useTransition();

  const [showBatched, setShowBatched] = useState(false);

  const [purgeText, setPurgeText] = useState('');
  const [purgeResult, setPurgeResult] = useState<PurgeVaultResult | null>(null);
  const [purgeBusy, startPurgeTransition] = useTransition();

  const [rotateResult, setRotateResult] = useState<RotateVaultKeyResult | null>(null);
  const [rotateBusy, startRotateTransition] = useTransition();

  const onReveal = (pointerId: string) => {
    startRowTransition(async () => {
      const result = await revealEntry({ pointerId });
      if (result.ok) {
        setActionError(null);
        setRevealed((prev) => ({ ...prev, [pointerId]: result.value }));
      } else {
        setActionError(result.error);
      }
    });
  };

  const onRevoke = (grantId: string) => {
    if (
      !window.confirm(
        'Revoke this reveal-to-model grant? The model stops receiving the raw value at the next tool boundary.',
      )
    ) {
      return;
    }
    startRowTransition(async () => {
      const result = await revokeRevealGrant({ grantId });
      setActionError(result.ok ? null : result.error);
    });
  };

  const hide = (pointerId: string) => {
    setRevealed((prev) =>
      Object.fromEntries(Object.entries(prev).filter(([id]) => id !== pointerId)),
    );
  };

  const submitPurge = () => {
    startPurgeTransition(async () => {
      const result = await purgeVault({ confirmation: purgeText });
      setPurgeResult(result);
      if (result.ok) {
        setPurgeText('');
        // The values behind these are gone; drop them from the page too.
        setRevealed({});
      }
    });
  };

  const submitRotate = () => {
    startRotateTransition(async () => {
      setRotateResult(await rotateVaultKey());
    });
  };

  // Rows the user revealed, in inventory order. After a purge revalidates the
  // page the inventory empties, and the strip disappears with it.
  const revealedEntries = inventory.filter((entry) => entry.pointerId in revealed);

  return (
    <div className="flex flex-col gap-8">
      <section className="flex flex-col gap-3">
        <SectionHead
          title="Vaulted values"
          sub="Every value this machine holds, masked, with everywhere its pointer has been written. Each reveal is audited."
        />
        {actionError !== null && <p className="text-xs text-sev-critical">{actionError}</p>}
        <VaultInventoryView entries={inventory} onReveal={onReveal} onRevoke={onRevoke} />
        {revealedEntries.length > 0 && (
          <div className="rounded-xl border border-border bg-surface p-4">
            <div className="mb-2 text-label font-semibold uppercase tracking-wider text-text-3">
              Revealed on this page only — hidden again on refresh
            </div>
            <ul className="space-y-2">
              {revealedEntries.map((entry) => {
                const value = revealed[entry.pointerId] ?? null;
                return (
                  <li
                    key={entry.pointerId}
                    className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-surface-2 px-3 py-2"
                  >
                    <ScrubbedValue value={value} descriptor={entry} />
                    {value === null && (
                      <span className="text-xs text-text-3">
                        could not be resolved — purged or key material unavailable
                      </span>
                    )}
                    <Button
                      variant="ghost"
                      tone="neutral"
                      size="sm"
                      disabled={rowBusy}
                      onClick={() => {
                        hide(entry.pointerId);
                      }}
                    >
                      Hide
                    </Button>
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <SectionHead
          title="Reuse on this machine"
          sub="Values detected in more than one place. Reuse widens the blast radius of a single leak."
        />
        <VaultReuseView entries={inventory} />
      </section>

      <section className="flex flex-col gap-3">
        <SectionHead
          title="De-reference audit"
          sub="Every resolution of a vaulted value — never the value itself. Model crossings render loud."
        />
        <DerefAuditTableView
          rows={showBatched ? allDerefRows : derefRows}
          hiddenBatched={hiddenBatched}
          showBatched={showBatched}
          onToggleBatched={setShowBatched}
        />
      </section>

      <section className="flex flex-col gap-3">
        <SectionHead title="Vault maintenance" sub="Key rotation is routine; the purge is not." />
        <div className="rounded-xl border border-border bg-surface p-5">
          <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
            Rotate vault key
          </div>
          <p className="mb-3 text-xs text-text-3">
            Mints the next key epoch and re-encrypts every stored value under it. Existing pointers
            keep working — only the ciphertext changes.
          </p>
          {rotateResult?.ok === true && (
            <p className="mb-3 text-xs text-ok">
              Key rotated to version {rotateResult.version} —{' '}
              {rotateResult.reEncrypted === 1
                ? '1 entry re-encrypted'
                : `${String(rotateResult.reEncrypted)} entries re-encrypted`}{' '}
              under it.
            </p>
          )}
          {rotateResult?.ok === false && (
            <p className="mb-3 text-xs text-sev-critical">{rotateResult.error}</p>
          )}
          <Button
            variant="outline"
            tone="neutral"
            size="sm"
            disabled={rotateBusy}
            onClick={submitRotate}
          >
            {rotateBusy ? 'Rotating…' : 'Rotate key'}
          </Button>
        </div>

        <div className="rounded-xl border border-sev-critical-fill bg-surface p-5">
          <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-sev-critical">
            Purge vault
          </div>
          <p className="mb-3 text-xs text-text-3">
            Destroys every stored value. Every pointer everywhere — in files, transcripts, and
            prompts — becomes permanently unresolvable. The audit trail survives. This cannot be
            undone.
          </p>
          {purgeResult?.ok === true && (
            <p className="mb-3 text-xs text-text-2">
              Vault purged —{' '}
              {purgeResult.destroyed === 1
                ? '1 value destroyed'
                : `${String(purgeResult.destroyed)} values destroyed`}
              . The audit trail below is retained.
            </p>
          )}
          {purgeResult?.ok === false && (
            <p className="mb-3 text-xs text-sev-critical">{purgeResult.error}</p>
          )}
          <div className="flex items-center gap-2">
            <Input
              value={purgeText}
              onChange={(e) => {
                setPurgeText(e.target.value);
              }}
              placeholder="Type 'purge' to confirm"
              className="max-w-56 font-mono"
            />
            <Button
              variant="solid"
              tone="danger"
              size="sm"
              disabled={purgeText !== 'purge' || purgeBusy}
              onClick={submitPurge}
            >
              {purgeBusy ? 'Purging…' : 'Purge vault'}
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}
