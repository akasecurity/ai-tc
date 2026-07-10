'use client';
import type { WorkspaceSettings } from '@akasecurity/schema';
import { Button, cn } from '@akasecurity/ui-kit';
import { useState } from 'react';

import { SectionLabel } from '../shared/DetailFields.tsx';

interface Choice<T extends string> {
  value: T;
  label: string;
  description: string;
}

const POLICY_CHOICES: Choice<WorkspaceSettings['policy']>[] = [
  {
    value: 'redact',
    label: 'Redact',
    description: 'Sensitive values are replaced before they reach the model (recommended).',
  },
  {
    value: 'warn',
    label: 'Warn only',
    description: 'Detections are recorded and warned about, but nothing is altered.',
  },
];

const HISTORICAL_CHOICES: Choice<WorkspaceSettings['historicalAccess']>[] = [
  {
    value: 'session-only',
    label: 'Session only',
    description: 'Only activity from after install is inspected (default — never assumed).',
  },
  {
    value: 'full',
    label: 'Full',
    description: 'Pre-install surfaces (existing configs, history) may be scanned too.',
  },
];

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
  onSave: (changes: Pick<WorkspaceSettings, 'policy' | 'historicalAccess'>) => void;
  busy?: boolean;
  error?: string | null;
  saved?: boolean;
}

/**
 * The workspace settings editor — the web twin of the `/aka:setup` wizard's
 * policy + historical-access questions.
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
  const dirty = policy !== settings.policy || historicalAccess !== settings.historicalAccess;

  return (
    <div className="flex max-w-2xl flex-col gap-6">
      <section className="rounded-xl border border-border bg-surface p-5">
        <SectionLabel>Sensitive-data handling</SectionLabel>
        <p className="mb-3 text-xs text-text-3">
          What the plugin does when a detection fires in a prompt or file write. Takes effect on the
          next hook — no restart needed.
        </p>
        <ChoiceGroup name="policy" choices={POLICY_CHOICES} value={policy} onChange={setPolicy} />
      </section>

      <section className="rounded-xl border border-border bg-surface p-5">
        <SectionLabel>Historical access</SectionLabel>
        <p className="mb-3 text-xs text-text-3">
          Consent to inspect surfaces that existed before AKA was installed.
        </p>
        <ChoiceGroup
          name="historicalAccess"
          choices={HISTORICAL_CHOICES}
          value={historicalAccess}
          onChange={setHistoricalAccess}
        />
      </section>

      <div className="flex items-center gap-3">
        <Button
          variant="solid"
          tone="primary"
          size="sm"
          disabled={!dirty || busy}
          onClick={() => {
            onSave({ policy, historicalAccess });
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
