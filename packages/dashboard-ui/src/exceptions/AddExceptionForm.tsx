'use client';
import {
  Button,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@akasecurity/ui-kit';
import { useState } from 'react';

import { ScopePicker } from './atoms.tsx';
import type { ScopeAnswer } from './meta.ts';

export interface AddExceptionRuleOption {
  id: string;
  name: string;
}

export interface AddExceptionSubmission {
  ruleId: string;
  value: string;
  scope: ScopeAnswer;
  reason: string;
  // Present when scope is permanent: the value retyped. The server action
  // compares them — a permanent grant is a deliberate, double-entered choice.
  confirmation?: string;
}

export interface AddExceptionFormProps {
  rules: AddExceptionRuleOption[];
  onSubmit: (submission: AddExceptionSubmission) => void;
  busy?: boolean;
  error?: string | null;
}

/**
 * Pre-authorize a value that has never been blocked — the web twin of
 * `aka exception add`. The value is sent once over the loopback-only server
 * action, fingerprinted + masked server-side, and never stored raw; the
 * password-type input keeps it out of autofill and shoulder view.
 */
export function AddExceptionForm({ rules, onSubmit, busy, error }: AddExceptionFormProps) {
  const [ruleId, setRuleId] = useState('');
  const [value, setValue] = useState('');
  const [scope, setScope] = useState<ScopeAnswer | null>(null);
  const [reason, setReason] = useState('');
  const [confirmation, setConfirmation] = useState('');

  const needsConfirmation = scope === 'permanent';
  const ready =
    ruleId !== '' &&
    value !== '' &&
    scope !== null &&
    reason.trim() !== '' &&
    (!needsConfirmation || confirmation === value);

  return (
    <div className="flex max-w-xl flex-col gap-4 rounded-xl border border-border bg-surface p-5">
      <div>
        <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
          Detection rule
        </div>
        <Select value={ruleId} onValueChange={setRuleId}>
          <SelectTrigger>
            <SelectValue placeholder="Pick the rule this value matches" />
          </SelectTrigger>
          <SelectContent>
            {rules.map((r) => (
              <SelectItem key={r.id} value={r.id}>
                <span className="font-mono text-xs">{r.id}</span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div>
        <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
          Value to pre-authorize
        </div>
        <Input
          type="password"
          autoComplete="off"
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
          }}
          placeholder="Pasted once; stored only as a keyed fingerprint + masked preview"
          className="font-mono"
        />
      </div>

      <div>
        <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
          Scope — pick one
        </div>
        <ScopePicker value={scope} onChange={setScope} />
      </div>

      {needsConfirmation && (
        <div>
          <div className="mb-1.5 text-label font-semibold uppercase tracking-wider text-text-3">
            Retype the value to confirm a permanent grant
          </div>
          <Input
            type="password"
            autoComplete="off"
            value={confirmation}
            onChange={(e) => {
              setConfirmation(e.target.value);
            }}
            className="font-mono"
          />
        </div>
      )}

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

      {error && <p className="text-xs text-sev-critical">{error}</p>}

      <div>
        <Button
          variant="solid"
          tone="primary"
          size="sm"
          disabled={!ready || busy}
          onClick={() => {
            if (!scope) return;
            onSubmit({
              ruleId,
              value,
              scope,
              reason: reason.trim(),
              ...(needsConfirmation ? { confirmation } : {}),
            });
          }}
        >
          {busy ? 'Verifying…' : 'Grant exception'}
        </Button>
      </div>
    </div>
  );
}
