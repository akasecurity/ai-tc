'use client';
import type { WorkspaceSettings } from '@akasecurity/schema';
import { isModelJudgeConsentValid } from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';
import { useState } from 'react';

import { SectionLabel } from '../shared/DetailFields.tsx';

interface Choice<T extends string> {
  value: T;
  label: string;
  description: string;
}

// The global handling preference (settings.policy) no longer drives runtime
// enforcement — per-category Policies do (see the Policies page). It is kept as
// a stored default, so this copy describes a leaning, not a guaranteed effect,
// and points to where enforcement is actually decided.
export const HANDLING_SECTION_LABEL = 'Sensitive-data handling';

export const HANDLING_SECTION_DESCRIPTION =
  'Your default leaning for sensitive detections. What actually happens per detection is ' +
  'governed by the per-category Policies, not this global default.';

export const POLICY_CHOICES: Choice<WorkspaceSettings['policy']>[] = [
  {
    value: 'redact',
    label: 'Redact',
    description:
      'Lean toward replacing sensitive values before they reach the model (recommended).',
  },
  {
    value: 'warn',
    label: 'Warn only',
    description: 'Lean toward surfacing detections rather than redacting them by default.',
  },
];

// This is the same grant the /aka:setup wizard collects, and it is what gates
// the wizard's history sweep. That sweep sends what it finds to the model API to
// be rated, so the 'full' copy must disclose the egress here too — this is the
// surface the wizard points at for scope and revocation.
export const HISTORICAL_SECTION_LABEL = 'Historical access';

export const HISTORICAL_SECTION_DESCRIPTION =
  'Consent to inspect surfaces that existed before AKA was installed.';

export const HISTORICAL_CHOICES: Choice<WorkspaceSettings['historicalAccess']>[] = [
  {
    value: 'session-only',
    label: 'Session only',
    description: 'Only activity from after install is inspected (default — never assumed).',
  },
  {
    value: 'full',
    label: 'Full',
    description:
      'Pre-install surfaces (existing configs, history) may be scanned too. This also lets ' +
      '/aka:setup send what that scan finds — raw values including any secrets and the ' +
      'surrounding transcript text — to the model API to be rated. ' +
      'Switching back to Session only stops future scans; it cannot recall data already sent.',
  },
];

// The distinct consent for the /aka:setup model-judge egress — separate from
// historical access, which only governs READING local transcripts. This grants
// or revokes sending findings to the model API for triage.
type ModelJudgeChoice = 'granted' | 'revoked';

export const MODEL_JUDGE_SECTION_LABEL = 'Model-judge consent';

export const MODEL_JUDGE_SECTION_DESCRIPTION =
  'A separate consent from historical access: this governs whether the /aka:setup scan may ' +
  'send findings to the model API to sort real leaks from noise. The file path is never sent, ' +
  'and any secrets in the surrounding context are masked before it goes.';

export const MODEL_JUDGE_CHOICES: Choice<ModelJudgeChoice>[] = [
  {
    value: 'revoked',
    label: 'Not granted',
    description:
      'The setup scan will not send findings to the model API (default — never assumed).',
  },
  {
    value: 'granted',
    label: 'Granted',
    description:
      'The setup scan may send each finding, plus surrounding context with any secrets in it masked, to the model API to sort real leaks from noise.',
  },
];

// This is a custody change from one-way redaction: with the grant, a detected
// value survives as recoverable ciphertext instead of being destroyed. The form
// only ever emits the choice string — the grant object itself (acknowledgedAt,
// version) is stamped by the server action, never built client-side.
export const VAULT_SECTION_LABEL = 'Reversible secret vault';

export const VAULT_SECTION_DESCRIPTION =
  'Whether redaction keeps a recoverable copy of what it removes. Off destroys detected ' +
  'values as it redacts them; Vault & redact keeps an encrypted copy on this machine.';

export type VaultConsentChoice = 'off' | 'on';

export const VAULT_CHOICES: Choice<VaultConsentChoice>[] = [
  {
    value: 'off',
    label: 'Off (default)',
    description: 'Detected values keep being redacted irreversibly; nothing recoverable is stored.',
  },
  {
    value: 'on',
    label: 'Vault & redact',
    description:
      'A detected value is replaced by a pointer, and an encrypted, recoverable copy is ' +
      'kept in the local vault under ~/.aka — this machine holds recoverable copies of ' +
      'detected secrets, encrypted at rest. The pointers written into files and ' +
      'transcripts show where each secret is used, and which places share the same ' +
      'secret, to anyone who can read those files. Switching back to Off stops new ' +
      'vaulting but does not erase what is already stored — purging the vault from the ' +
      'CLI is what erases it.',
  },
];

// The stored grant maps to the form choice: a recorded consent renders as 'on',
// an absent one as 'off'.
export function vaultChoiceOf(vaultConsent: WorkspaceSettings['vaultConsent']): VaultConsentChoice {
  return vaultConsent ? 'on' : 'off';
}

function ChoiceGroup<T extends string>({
  name,
  choices,
  value,
  onChange,
}: {
  name: string;
  choices: Choice<T>[];
  value: T;
  onChange: (value: T) => void;
}) {
  return (
    <div className="flex flex-col gap-2" role="radiogroup" aria-label={name}>
      {choices.map((c) => (
        <label
          key={c.value}
          className={cn(
            'flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors',
            value === c.value
              ? 'border-primary bg-primary-tint'
              : 'border-border bg-surface hover:bg-surface-2',
          )}
        >
          <input
            type="radio"
            name={name}
            checked={value === c.value}
            onChange={() => {
              onChange(c.value);
            }}
            className="mt-1 accent-primary"
          />
          <span>
            <span className="block text-sm font-semibold text-text">{c.label}</span>
            <span className="mt-0.5 block text-xs text-text-2">{c.description}</span>
          </span>
        </label>
      ))}
    </div>
  );
}

export interface WorkspaceSettingsFormViewProps {
  settings: WorkspaceSettings;
  // Both consents are plain answers, not the stored records: acknowledgement
  // timestamps and versions are stamped server-side, so a client-supplied one
  // would only be discarded. modelJudgeConsent: true grants, false revokes.
  onSave: (
    changes: Pick<WorkspaceSettings, 'policy' | 'historicalAccess'> & {
      modelJudgeConsent: boolean;
      vaultConsent: VaultConsentChoice;
    },
  ) => void;
  busy?: boolean;
  error?: string | null;
  saved?: boolean;
}

/**
 * The workspace settings editor — the web twin of the `/aka:setup` wizard's
 * policy, historical-access, and vault-consent questions.
 */
export function WorkspaceSettingsFormView({
  settings,
  onSave,
  busy,
  error,
  saved,
}: WorkspaceSettingsFormViewProps) {
  const [policy, setPolicy] = useState(settings.policy);
  const [historicalAccess, setHistoricalAccess] = useState(settings.historicalAccess);
  // Validity, not presence: this is the same predicate the judge gate uses, so a
  // consent recorded against an older payload version renders as "Not granted"
  // (which is how the judge treats it) instead of showing a green "Granted" for
  // a grant that no longer authorizes anything. Deriving `dirty` from the same
  // value also keeps re-granting a stale consent a single save.
  const initialModelJudge: ModelJudgeChoice = isModelJudgeConsentValid(settings.modelJudgeConsent)
    ? 'granted'
    : 'revoked';
  const [modelJudge, setModelJudge] = useState<ModelJudgeChoice>(initialModelJudge);
  const [vaultConsent, setVaultConsent] = useState(vaultChoiceOf(settings.vaultConsent));
  const dirty =
    policy !== settings.policy ||
    historicalAccess !== settings.historicalAccess ||
    modelJudge !== initialModelJudge ||
    vaultConsent !== vaultChoiceOf(settings.vaultConsent);

  return (
    <div className="flex max-w-2xl flex-col gap-6">
      <section className="rounded-xl border border-border bg-surface p-5">
        <SectionLabel>{HANDLING_SECTION_LABEL}</SectionLabel>
        <p className="mb-3 text-xs text-text-3">{HANDLING_SECTION_DESCRIPTION}</p>
        <ChoiceGroup name="policy" choices={POLICY_CHOICES} value={policy} onChange={setPolicy} />
      </section>

      <section className="rounded-xl border border-border bg-surface p-5">
        <SectionLabel>{HISTORICAL_SECTION_LABEL}</SectionLabel>
        <p className="mb-3 text-xs text-text-3">{HISTORICAL_SECTION_DESCRIPTION}</p>
        <ChoiceGroup
          name="historicalAccess"
          choices={HISTORICAL_CHOICES}
          value={historicalAccess}
          onChange={setHistoricalAccess}
        />
      </section>

      <section className="rounded-xl border border-border bg-surface p-5">
        <SectionLabel>{MODEL_JUDGE_SECTION_LABEL}</SectionLabel>
        <p className="mb-3 text-xs text-text-3">{MODEL_JUDGE_SECTION_DESCRIPTION}</p>
        <ChoiceGroup
          name="modelJudgeConsent"
          choices={MODEL_JUDGE_CHOICES}
          value={modelJudge}
          onChange={setModelJudge}
        />
      </section>

      <section className="rounded-xl border border-border bg-surface p-5">
        <SectionLabel>{VAULT_SECTION_LABEL}</SectionLabel>
        <p className="mb-3 text-xs text-text-3">{VAULT_SECTION_DESCRIPTION}</p>
        <ChoiceGroup
          name="vaultConsent"
          choices={VAULT_CHOICES}
          value={vaultConsent}
          onChange={setVaultConsent}
        />
      </section>

      <div className="flex items-center gap-3">
        <Button
          variant="solid"
          tone="primary"
          size="sm"
          disabled={!dirty || busy}
          onClick={() => {
            onSave({
              policy,
              historicalAccess,
              // Just the answers — the server stamps the acknowledgement times
              // and the versions the grants are recorded against.
              modelJudgeConsent: modelJudge === 'granted',
              vaultConsent,
            });
          }}
        >
          {busy ? 'Saving…' : 'Save changes'}
        </Button>
        {saved && !dirty && <span className="text-xs text-ok">Saved.</span>}
        {error && <span className="text-xs text-sev-critical">{error}</span>}
      </div>
    </div>
  );
}
