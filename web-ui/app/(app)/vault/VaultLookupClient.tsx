'use client';

import type { ScopeAnswer } from '@akasecurity/dashboard-ui';
import { ScopePicker, ScrubbedValue } from '@akasecurity/dashboard-ui';
import { Button, Input } from '@akasecurity/ui-kit';
import { useState, useTransition } from 'react';

import type { RevealGrantResult } from '../exceptions/actions';
import { grantRevealFromPointer } from '../exceptions/actions';
import type { RevealResult } from './actions';
import { revealPointer } from './actions';

export function VaultLookupClient() {
  const [pointer, setPointer] = useState('');
  const [result, setResult] = useState<RevealResult | null>(null);
  // The pointer the current result was resolved from — the grant form submits
  // this, not the editable input, so editing the field cannot desync the two.
  const [resolvedPointer, setResolvedPointer] = useState('');
  const [busy, startTransition] = useTransition();

  const [scope, setScope] = useState<ScopeAnswer | null>(null);
  const [justification, setJustification] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [grantResult, setGrantResult] = useState<RevealGrantResult | null>(null);
  const [grantBusy, startGrantTransition] = useTransition();

  const submit = () => {
    const candidate = pointer.trim();
    if (candidate === '') return;
    startTransition(async () => {
      setResult(await revealPointer({ pointer: candidate }));
      setResolvedPointer(candidate);
      // A fresh resolution starts a fresh grant form.
      setScope(null);
      setJustification('');
      setGrantResult(null);
    });
  };

  const submitGrant = () => {
    if (scope === null || justification.trim() === '') return;
    startGrantTransition(async () => {
      setGrantResult(
        await grantRevealFromPointer({
          pointer: resolvedPointer,
          scope,
          justification,
          confirmation,
        }),
      );
    });
  };

  const resolved = result?.ok === true && result.value !== null;

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

        {result && !result.ok && (
          <p className="mt-3 text-xs text-sev-critical-ink">{result.error}</p>
        )}
        {result?.ok && (
          <div className="mt-3 rounded-lg border border-border bg-surface-2 px-3 py-2">
            <ScrubbedValue value={result.value} descriptor={result.descriptor} />
          </div>
        )}
      </div>

      {resolved && (
        <div className="rounded-xl border border-border bg-surface p-5">
          <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
            Grant reveal to model
          </div>
          <p className="mb-3 text-xs text-text-3">
            Authorize the model to receive this value&apos;s raw form at tool boundaries while the
            grant is active. Strictly stronger than a suppression — grant it deliberately.
          </p>

          {grantResult?.ok === true ? (
            <div className="rounded-lg border border-sev-critical-fill bg-sev-critical-fill p-3">
              <p className="text-sm font-semibold text-sev-critical-ink">
                Reveal grant {grantResult.grantIdPrefix} created
              </p>
              <p className="mt-1 text-xs text-text-2">
                While it is active, the model can receive this value&apos;s raw form at tool
                boundaries. Every crossing is audited in the vault&apos;s de-reference trail. Revoke
                it any time on the Exceptions page.
              </p>
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              <div>
                <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
                  Scope — pick one
                </div>
                <ScopePicker value={scope} onChange={setScope} />
                {scope === 'permanent' ? (
                  <label className="flex flex-col gap-1 text-xs text-text-2">
                    A permanent reveal never expires. Retype the masked value shown above to
                    confirm.
                    <input
                      className="rounded border border-border bg-surface px-2 py-1 font-mono"
                      data-slot="permanent-confirmation"
                      value={confirmation}
                      onChange={(e) => {
                        setConfirmation(e.target.value);
                      }}
                      placeholder="masked value"
                    />
                  </label>
                ) : null}
              </div>
              <div>
                <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
                  Justification (required — the audit trail)
                </div>
                <textarea
                  value={justification}
                  onChange={(e) => {
                    setJustification(e.target.value);
                  }}
                  placeholder="Why the model may receive this value raw"
                  rows={3}
                  className="w-full rounded-lg border border-border bg-surface-2 px-3 py-2 text-sm text-text placeholder:text-text-3"
                />
              </div>
              {grantResult && <p className="text-xs text-sev-critical-ink">{grantResult.error}</p>}
              <div>
                <Button
                  variant="solid"
                  tone="danger"
                  size="sm"
                  disabled={scope === null || justification.trim() === '' || grantBusy}
                  onClick={submitGrant}
                >
                  {grantBusy ? 'Granting…' : 'Grant reveal to model'}
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
