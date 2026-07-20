'use client';
// Right pane: full detail for one session — header + meta grid, token/tool band,
// the audit timeline, and a source footer. Presentational (takes the session via
// props) and renders its own loading / error / empty states, so both apps share
// one behaviour. Token figures + time labels are derived from the semantic
// @akasecurity/schema `ActivitySession` (raw counts + ISO timestamps).
import type { ActivitySession, SessionTokenReport } from '@akasecurity/schema';
import { Button, Skeleton } from '@akasecurity/ui-kit';
import { useState } from 'react';

import { MetaItem } from '../shared/DetailFields.tsx';
import {
  ArrowDownIcon,
  ArrowUpIcon,
  ArrowUpRightIcon,
  BoltIcon,
  DownloadIcon,
  ListIcon,
  TerminalIcon,
} from '../shared/icons.tsx';
import { Provider, PROVIDERS } from '../shared/Provider.tsx';
import { WidgetEmpty, WidgetError } from '../shared/widget-state.tsx';
import { MetaChips, SessionStatusBadge, ToolChip } from './atoms.tsx';
import { AuditTimelineView, type BuildActivityLinkHref } from './AuditTimelineView.tsx';
import {
  cacheHitPct,
  dayLabel,
  durationLabel,
  formatCostTotal,
  formatUsd,
  startLabel,
  tokenLabel,
} from './format.ts';
import { HARNESS_KIND, toolEntries, toolTotal } from './meta.ts';

// Export the reconstructed session (meta + token report + full timeline) as a
// pretty-printed JSON file — the "Download" action. Client-only (Blob + a
// transient anchor); a no-op if the DOM APIs are unavailable (SSR safety).
function downloadSession(session: ActivitySession): void {
  if (typeof document === 'undefined' || typeof URL.createObjectURL !== 'function') return;
  const blob = new Blob([JSON.stringify(session, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `session-${session.id.slice(0, 12)}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function DetailBody({
  session,
  tokenReport,
  liveFindings,
  linkHref,
  toolHref,
}: {
  session: ActivitySession;
  tokenReport?: SessionTokenReport | null;
  liveFindings?: { count: number; href: string } | null;
  linkHref?: BuildActivityLinkHref;
  toolHref?: (toolName: string) => string;
}) {
  const harness = PROVIDERS[session.harness];
  const tools = toolEntries(session.tools);
  // Whether the audit section shows the human timeline or the raw event JSON.
  const [rawOpen, setRawOpen] = useState(false);

  return (
    <div className="flex h-full min-h-0 flex-col">
      {/* Header + meta grid */}
      <div className="shrink-0 border-b border-border px-5 py-4">
        <div className="flex items-start gap-3.5">
          <Provider id={session.harness} size={40} />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="font-display text-lg font-semibold text-text">{session.title}</span>
              <SessionStatusBadge status={session.status} />
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-ui text-text-3">
              {harness.label} · {HARNESS_KIND[session.harness]}
              <span className="text-border-strong">·</span>
              <span className="font-mono">{session.id}</span>
            </div>
          </div>
          <div className="flex gap-1">
            <Button
              variant="ghost"
              size="sm"
              title="Export session data as JSON"
              aria-label="Export session data as JSON"
              onClick={() => {
                downloadSession(session);
              }}
            >
              <DownloadIcon aria-hidden focusable={false} className="size-4" />
            </Button>
          </div>
        </div>
        <div className="mt-4 grid 2xl:grid-cols-4 grid-cols-3 gap-x-4 gap-y-3.5 max-h-44 overflow-y-auto">
          <MetaItem label="Working dir">
            <span className="font-mono break-all">{session.cwd}</span>
          </MetaItem>
          <MetaItem label="Branch">
            <MetaChips items={session.branches} mono />
          </MetaItem>
          <MetaItem label="Model">
            <MetaChips items={session.models} mono />
          </MetaItem>
          <MetaItem label="Started">
            {startLabel(session.startedAt)} · {dayLabel(session.startedAt)}
          </MetaItem>
          <MetaItem label="Duration">
            {durationLabel(session.startedAt, session.endedAt, session.status)}
          </MetaItem>
          <MetaItem label="Turns">{session.turns}</MetaItem>
          <MetaItem label="Findings">
            {session.findings > 0 || liveFindings ? (
              <span className="inline-flex flex-wrap items-center gap-x-1.5">
                {session.findings > 0 && (
                  <span
                    className="font-semibold text-sev-critical"
                    title="Detection firings across this session's transcript — the same value fires once per event it appears in"
                  >
                    {session.findings} triggered
                  </span>
                )}
                {session.findings > 0 && liveFindings && (
                  <span className="text-border-strong">·</span>
                )}
                {liveFindings && (
                  <a
                    href={liveFindings.href}
                    className="inline-flex items-center gap-0.5 font-semibold text-sev-critical underline-offset-2 hover:underline"
                    title="Unique findings recorded by live enforcement — open in Findings"
                  >
                    {liveFindings.count} enforced live
                    <ArrowUpRightIcon aria-hidden focusable={false} className="size-3.5" />
                  </a>
                )}
              </span>
            ) : (
              <span className="text-ok">None</span>
            )}
          </MetaItem>
          <MetaItem label="Egress">
            {session.shares > 0 ? `${String(session.shares)} destinations` : 'None'}
          </MetaItem>
        </div>
      </div>

      {/* Token + tool band */}
      <div className="flex shrink-0 flex-wrap items-center gap-5 border-b border-border bg-surface-2 px-5 py-3">
        <div className="flex items-center gap-3.5">
          <span className="inline-flex items-center gap-1.5 text-ui">
            <ArrowUpIcon aria-hidden focusable={false} className="size-3.5 text-text-3" />
            <b className="font-semibold tabular-nums">{tokenLabel(session.tokens.inputTokens)}</b>
            <span className="text-text-3">in</span>
          </span>
          <span className="inline-flex items-center gap-1.5 text-ui">
            <ArrowDownIcon aria-hidden focusable={false} className="size-3.5 text-text-3" />
            <b className="font-semibold tabular-nums">{tokenLabel(session.tokens.outputTokens)}</b>
            <span className="text-text-3">out</span>
          </span>
          <span className="inline-flex items-center gap-1.5 text-ui">
            <BoltIcon aria-hidden focusable={false} className="size-3.5 text-primary" />
            <b className="font-semibold tabular-nums text-primary">
              {cacheHitPct(session.tokens)}%
            </b>
            <span className="text-text-3">cache</span>
          </span>
          {/* Estimated cost — DERIVED at read time from the token report (token
              counts are exact truth; cost is `~$X`, or `≥ $X` when some calls
              had unknown pricing). Absent (no report passed) → hidden. */}
          {tokenReport && (
            <span className="inline-flex items-center gap-1.5 text-ui">
              <b className="font-semibold tabular-nums text-text">
                {formatCostTotal(tokenReport.estimatedCostUsd ?? 0, tokenReport.costIsPartial)}
              </b>
              <span className="text-text-3">est. cost</span>
            </span>
          )}
        </div>
        <span className="h-5 w-px bg-border" />
        <div className="flex flex-1 flex-wrap items-center gap-2 max-h-22 overflow-y-auto">
          <span className="text-xs font-semibold text-text-3">
            {toolTotal(session.tools)} tool calls
          </span>
          {tools.map((t) => (
            <ToolChip
              key={t.name}
              name={t.name}
              n={t.n}
              {...(toolHref ? { href: toolHref(t.name) } : {})}
            />
          ))}
        </div>
      </div>

      {/* Per-model token/cost breakdown — only when the session touched more than
          one (provider, model); a single-model session is fully covered by the
          band above. Each chip: model · total tokens · estimated cost. */}
      {tokenReport && tokenReport.rollups.length > 1 && (
        <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border bg-surface-2 px-5 py-2.5">
          <span className="text-label font-semibold uppercase tracking-wider text-text-3">
            Cost by model
          </span>
          {tokenReport.rollups.map((r) => (
            <span
              key={`${r.provider} ${r.model}`}
              className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface py-0.5 px-2 text-xs text-text-2"
            >
              <span className="font-mono text-text">{r.model}</span>
              <span className="tabular-nums text-text-3">{tokenLabel(r.totalTokens)}</span>
              <span className="tabular-nums text-text">
                {r.estimatedCostUsd !== null ? formatUsd(r.estimatedCostUsd) : '—'}
              </span>
            </span>
          ))}
        </div>
      )}

      {/* Audit timeline — or the raw event JSON when toggled */}
      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4.5">
        <div className="mb-4 flex items-center gap-2 text-label font-semibold uppercase tracking-wider text-text-3">
          {rawOpen ? 'Raw events' : 'Audit log'}
          <span className="text-border-strong">·</span>
          <span className="font-mono text-label font-medium normal-case tracking-normal text-text-3">
            {session.events.length} events
          </span>
        </div>
        {rawOpen ? (
          session.events.length > 0 ? (
            <pre className="overflow-x-auto rounded-lg border border-border bg-surface-2 p-3 text-label leading-relaxed text-text-2">
              {JSON.stringify(session.events, null, 2)}
            </pre>
          ) : (
            <WidgetEmpty message="No events recorded for this session yet" />
          )
        ) : (
          <AuditTimelineView events={session.events} {...(linkHref ? { linkHref } : {})} />
        )}
      </div>

      {/* Footer */}
      <div className="flex shrink-0 items-center gap-2 border-t border-border px-5 py-2.5 text-xs text-text-3">
        <TerminalIcon aria-hidden focusable={false} className="size-3.5" />
        <span className="font-mono">Source: ~/.claude/audit.log</span>
        <Button
          variant="link"
          tone="primary"
          className="ml-auto text-ui"
          onClick={() => {
            setRawOpen((v) => !v);
          }}
        >
          <ListIcon aria-hidden focusable={false} className="size-3.5" />
          {rawOpen ? 'View timeline' : 'View raw events'}
        </Button>
      </div>
    </div>
  );
}

export function SessionDetailView({
  session,
  isLoading,
  error,
  tokenReport,
  liveFindings,
  linkHref,
  toolHref,
}: {
  session: ActivitySession | null;
  isLoading: boolean;
  error: string | null;
  /** The selected session's per-(provider, model) token report + derived cost.
   * Optional: some hosts pass it (from @akasecurity/persistence); a host
   * that omits it (e.g. until cost is available) leaves the
   * band/breakdown hidden. */
  tokenReport?: SessionTokenReport | null;
  /** The session's live-enforced findings: unique-value count + the
   * session-scoped findings-page href it links to. Shown beside the
   * transcript-firing tally (`session.findings`), which counts every firing —
   * the two legitimately differ. Optional/null → only the tally renders. */
  liveFindings?: { count: number; href: string } | null;
  /** Href builder for the timeline's cross-referencing event links — see
   * BuildActivityLinkHref. Omitted → the timeline renders no deep links. */
  linkHref?: BuildActivityLinkHref;
  /** Href for a tool chip (e.g. the findings page filtered to that tool).
   * Optional: omitted, the chips render as plain text. */
  toolHref?: (toolName: string) => string;
}) {
  if (error) {
    return (
      <div className="grid h-full place-items-center p-6">
        <WidgetError message={error} />
      </div>
    );
  }
  if (isLoading && !session) {
    return (
      <div className="flex h-full flex-col gap-4 p-5" aria-busy>
        <Skeleton className="h-10 w-2/3" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }
  if (!session) {
    return (
      <div className="grid h-full place-items-center p-6">
        <WidgetEmpty message="Select a session to view its audit timeline" />
      </div>
    );
  }
  return (
    <DetailBody
      session={session}
      tokenReport={tokenReport ?? null}
      liveFindings={liveFindings ?? null}
      {...(linkHref ? { linkHref } : {})}
      {...(toolHref ? { toolHref } : {})}
    />
  );
}
