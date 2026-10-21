'use client';
import { TOOL_TO_HARNESS } from '@akasecurity/schema';
import { Badge, Button, Card } from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

import { Ico } from '../inventory/Ico.tsx';
import type { IconName } from '../inventory/icons.ts';
import { relativeTime } from '../lib/relativeTime.ts';
import { MetaItem, SectionLabel } from '../shared/DetailFields.tsx';
import { PROVIDERS } from '../shared/Provider.tsx';
import type { CredentialDetailModel } from './types.ts';

export interface CredentialDetailViewProps {
  credential: CredentialDetailModel;
  onBack: () => void;
  onOpenFinding: (id: string) => void;
  /** The instant relative times are measured against, in epoch milliseconds. */
  renderedAt: number;
}

// A sighting names the tool that sent it (`claude-code`); the label map is keyed
// by harness (`claudecode`). An id neither knows is shown as it is.
function harnessLabel(id: string): string {
  const harness = TOOL_TO_HARNESS[id] ?? id;
  return harness in PROVIDERS ? PROVIDERS[harness as keyof typeof PROVIDERS].label : id;
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
        <div className="min-w-0">
          <h2 className="truncate font-mono text-lg font-semibold text-text">
            {c.variableName ?? 'Unnamed'}
          </h2>
          <div className="text-xs text-text-3">{c.kind}</div>
        </div>
        <span className="ml-auto inline-flex items-center gap-1.5 text-xs font-semibold text-ok-ink">
          <Ico name="check-circle" className="size-4" /> OK
        </span>
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
          <MetaItem label="Kind">{c.kind}</MetaItem>
          <MetaItem label="Provider">{c.provider ?? '—'}</MetaItem>
          <MetaItem label="Variable name">
            <span className="font-mono text-xs">{c.variableName ?? '—'}</span>
          </MetaItem>
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
                  <Badge variant={f.severity}>{f.severity}</Badge>
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
