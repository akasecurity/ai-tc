'use client';
import { harnessFromTool } from '@akasecurity/schema';
import { Badge, Button, Card, cn, Input, SeverityBadge } from '@akasecurity/ui-kit';
import { type ReactNode, useId, useState } from 'react';

import { Ico } from '../inventory/Ico.tsx';
import type { IconName } from '../inventory/icons.ts';
import { relativeTime } from '../lib/relativeTime.ts';
import { MetaItem, SectionLabel } from '../shared/DetailFields.tsx';
import { PROVIDERS } from '../shared/Provider.tsx';
import { RefusalReason, refusedControlProps } from '../shared/Refusal.tsx';
import { namedByVariable } from './CredentialsListView.tsx';
import type { CredentialDetailModel } from './types.ts';

export interface CredentialDetailViewProps {
  credential: CredentialDetailModel;
  onBack: () => void;
  onOpenFinding: (id: string) => void;
  /** The instant relative times are measured against, in epoch milliseconds. */
  renderedAt: number;
  /**
   * Saves a label, or clears it with null. Rejects when the save fails, which
   * keeps the editor open. Omit it and no edit control is shown.
   */
  onSaveLabel?: ((label: string | null) => Promise<void>) | undefined;
  /** Why the last label save failed. */
  labelError?: string | undefined;
  /**
   * Why this reader may not label the credential. Set, the control shows
   * locked with this reason beside it; absent, it works.
   */
  labelRefusal?: string | undefined;
  /** The longest label the host accepts. */
  labelMaxLength?: number | undefined;
}

function LabelEditor({
  label,
  onSave,
  error,
  maxLength,
  refusal,
}: {
  label: string | null;
  onSave: (label: string | null) => Promise<void>;
  error: string | undefined;
  maxLength: number | undefined;
  refusal: string | undefined;
}) {
  const [draft, setDraft] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const reasonId = useId();

  const save = async (next: string | null) => {
    setSaving(true);
    try {
      await onSave(next);
      setDraft(null);
    } catch {
      // The host reports the failure through `error`; the draft stays for a retry.
    } finally {
      setSaving(false);
    }
  };

  const openLabel = label === null ? 'Add label' : 'Rename';
  if (refusal !== undefined) {
    return (
      <div className="flex flex-col items-end gap-1">
        <Button
          variant="outline"
          size="sm"
          {...refusedControlProps(reasonId, refusal, 'hover:bg-surface')}
        >
          {openLabel}
        </Button>
        <RefusalReason id={reasonId} dataSlot="credential-label-reason">
          {refusal}
        </RefusalReason>
      </div>
    );
  }
  if (draft === null) {
    return (
      <Button
        variant="outline"
        size="sm"
        onClick={() => {
          setDraft(label ?? '');
        }}
      >
        {openLabel}
      </Button>
    );
  }
  const trimmed = draft.trim();
  return (
    <form
      className="flex flex-col gap-1.5"
      onSubmit={(e) => {
        e.preventDefault();
        if (trimmed !== '') void save(trimmed);
      }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Input
          aria-label="Credential label"
          autoFocus
          value={draft}
          maxLength={maxLength}
          disabled={saving}
          className="w-64"
          onChange={(e) => {
            setDraft(e.target.value);
          }}
          onKeyDown={(e) => {
            if (e.key === 'Escape') setDraft(null);
          }}
        />
        <Button type="submit" size="sm" disabled={saving || trimmed === ''}>
          Save
        </Button>
        {label !== null && (
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={saving}
            onClick={() => {
              void save(null);
            }}
          >
            Clear label
          </Button>
        )}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={saving}
          onClick={() => {
            setDraft(null);
          }}
        >
          Cancel
        </Button>
      </div>
      {error !== undefined && (
        <p role="alert" className="text-xs text-sev-critical-ink">
          {error}
        </p>
      )}
    </form>
  );
}

// A sighting names the tool that sent it (`claude-code`); the label map is keyed
// by harness (`claudecode`). An id neither knows is shown as it is.
function harnessLabel(id: string): string {
  const harness = harnessFromTool(id);
  return Object.hasOwn(PROVIDERS, harness)
    ? PROVIDERS[harness as keyof typeof PROVIDERS].label
    : id;
}

function UsageRow({
  icon,
  label,
  children,
}: {
  icon: IconName;
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="flex items-start gap-3 py-2">
      <span className="flex w-28 shrink-0 items-center gap-2 text-xs font-semibold text-text-2">
        <Ico name={icon} className="size-3.5" /> {label}
      </span>
      <div className="flex min-w-0 flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

function Pill({ children, mono = false }: { children: ReactNode; mono?: boolean }) {
  return (
    <span
      className={`rounded-full border border-border bg-surface-2 px-2.5 py-0.5 text-xs ${mono ? 'font-mono' : ''}`}
    >
      {children}
    </span>
  );
}

const None = () => <span className="text-xs text-text-3">None seen</span>;

/** One credential: what it is, where it was seen, and the findings it raised. */
export function CredentialDetailView({
  credential: c,
  onBack,
  onOpenFinding,
  renderedAt,
  onSaveLabel,
  labelError,
  labelMaxLength,
  labelRefusal,
}: CredentialDetailViewProps) {
  const detectedOnly = c.reference === null;
  return (
    <Card className="flex flex-col gap-6 p-5 shadow-sm">
      <div>
        <Button variant="ghost" size="sm" onClick={onBack}>
          <Ico name="chevron-left" className="size-3.5" /> All credentials
        </Button>
      </div>

      <div className="flex items-center gap-3">
        <span className="grid size-11 shrink-0 place-items-center rounded-xl bg-sev-high-fill text-sev-high-ink">
          <Ico name="key" className="size-5" />
        </span>
        <div className="min-w-0 flex-1">
          <h2
            className={cn(
              'truncate text-lg font-semibold text-text',
              namedByVariable(c) && 'font-mono',
            )}
          >
            {c.displayName}
          </h2>
          <div className="text-xs text-text-3">{c.kind}</div>
        </div>
        {onSaveLabel !== undefined && (
          <LabelEditor
            key={c.id}
            label={c.label}
            onSave={onSaveLabel}
            error={labelError}
            refusal={labelRefusal}
            maxLength={labelMaxLength}
          />
        )}
      </div>

      {detectedOnly && (
        <div className="rounded-lg border border-border bg-surface-2 p-3">
          <div className="mb-1 flex items-center gap-2">
            <Badge variant="outline">Detected only</Badge>
            <span className="text-xs font-semibold text-text-2">
              Not linked to a secrets manager
            </span>
          </div>
          <p className="text-xs text-text-3">
            AKA found this value in your organization&apos;s activity. No secrets manager holds a
            reference to it, so its owner, rotation date and policy are unknown.
          </p>
        </div>
      )}

      <div>
        <SectionLabel>Details</SectionLabel>
        <div className="grid grid-cols-2 gap-x-6 gap-y-4 md:grid-cols-4">
          {c.label !== null && c.variableName !== null && (
            <MetaItem label="Variable">
              <span className="font-mono text-xs">{c.variableName}</span>
            </MetaItem>
          )}
          <MetaItem label="Provider">{c.provider ?? '—'}</MetaItem>
          <MetaItem label="Reference">
            {c.reference === null ? '—' : <span className="font-mono text-xs">{c.reference}</span>}
          </MetaItem>
          <MetaItem label="Owner">{c.owner ?? '—'}</MetaItem>
          <MetaItem label="Last rotated">
            {c.lastRotated === null ? '—' : relativeTime(c.lastRotated, renderedAt)}
          </MetaItem>
          <MetaItem label="First seen">{relativeTime(c.firstSeen, renderedAt)}</MetaItem>
          <MetaItem label="Last seen">{relativeTime(c.lastSeen, renderedAt)}</MetaItem>
          <MetaItem label="Sightings">{String(c.sightingCount)}</MetaItem>
          <MetaItem label="Rule">
            <span className="font-mono text-xs">{c.ruleId}</span>
          </MetaItem>
        </div>
      </div>

      <div>
        <SectionLabel>Where it is used</SectionLabel>
        <div className="divide-y divide-border rounded-lg border border-border px-3">
          <UsageRow icon="repo" label="Projects">
            {c.projects.length === 0 ? (
              <None />
            ) : (
              c.projects.map((p) => (
                <Pill key={p} mono>
                  {p}
                </Pill>
              ))
            )}
          </UsageRow>
          <UsageRow icon="user" label="Teams">
            {c.teams.length === 0 ? (
              <None />
            ) : (
              c.teams.map((t) => (
                <Pill key={t.name ?? ''}>
                  {t.name ?? 'Ungrouped'}{' '}
                  <span className="text-text-3">
                    · {String(t.userCount)} {t.userCount === 1 ? 'person' : 'people'}
                  </span>
                </Pill>
              ))
            )}
          </UsageRow>
          <UsageRow icon="terminal" label="Harnesses">
            {c.harnesses.length === 0 ? (
              <None />
            ) : (
              c.harnesses.map((h) => <Pill key={h}>{harnessLabel(h)}</Pill>)
            )}
          </UsageRow>
        </div>
        <p className="mt-2 text-xs text-text-3">
          Seen on {String(c.endpointCount)} {c.endpointCount === 1 ? 'endpoint' : 'endpoints'}.
          Teams are the group tags of the people whose machines saw it. The control plane holds a
          keyed fingerprint of this value, never the value itself.
        </p>
      </div>

      <div>
        <SectionLabel>Linked findings</SectionLabel>
        {c.findings.length === 0 ? (
          <p className="text-xs text-text-3">
            No findings. A finding links here when a capture that carried this value raised one
            under its rule.
          </p>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {c.findings.map((f) => (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => {
                    onOpenFinding(f.id);
                  }}
                  className="flex w-full cursor-pointer items-center gap-3 rounded-lg border border-border px-3 py-2 text-left hover:bg-surface-2"
                >
                  <SeverityBadge severity={f.severity} />
                  <span className="min-w-0 flex-1 truncate text-sm text-text">{f.name}</span>
                  <span className="shrink-0 text-xs text-text-3">
                    {relativeTime(f.detectedAt, renderedAt)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
