'use client';
// The Activity page's token-usage panel: a collapsible Card that folds the token
// report (the plugin's `/aka:tokens` view) into the Activity surface instead of
// giving it its own page. Collapsed, it's a one-line glance — sessions, total
// tokens, estimated cost. Expanded, it's the per-(provider, model) breakdown.
// Props-driven off the shared @akasecurity/schema `TokenUsageSummary`
// (built by `aggregateTokenUsage`), so token counts are exact truth and cost is a
// read-time estimate (`~$X`, or `≥ $X` when some calls have unknown pricing).
import type { TokenUsageSummary } from '@akasecurity/schema';
import {
  Card,
  cn,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@akasecurity/ui-kit';
import { useState } from 'react';

import { AnalyticsIcon, ChevronDownIcon } from '../shared/icons.tsx';
import { WidgetError } from '../shared/widget-state.tsx';
import { formatCostTotal, formatUsd, tokenLabel } from './format.ts';

function HeaderIcon() {
  return (
    <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-primary-tint text-primary">
      <AnalyticsIcon aria-hidden focusable={false} className="size-4" />
    </span>
  );
}

/** Per-model rows table — the expanded body. Token counts are compact; a model
 * with no known price shows `—` in the cost column. */
function ModelTable({ summary }: { summary: TokenUsageSummary }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Provider</TableHead>
          <TableHead>Model</TableHead>
          <TableHead className="text-right">Input</TableHead>
          <TableHead className="text-right">Output</TableHead>
          <TableHead className="text-right">Cache</TableHead>
          <TableHead className="text-right">Total</TableHead>
          <TableHead className="text-right">Cost</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {summary.models.map((m) => (
          <TableRow key={`${m.provider} ${m.model}`}>
            <TableCell className="text-text-2">{m.provider}</TableCell>
            <TableCell className="font-mono text-text">{m.model}</TableCell>
            <TableCell className="text-right tabular-nums text-text-2">
              {tokenLabel(m.inputTokens)}
            </TableCell>
            <TableCell className="text-right tabular-nums text-text-2">
              {tokenLabel(m.outputTokens)}
            </TableCell>
            <TableCell className="text-right tabular-nums text-text-2">
              {tokenLabel(m.cacheTokens)}
            </TableCell>
            <TableCell className="text-right font-semibold tabular-nums text-text">
              {tokenLabel(m.totalTokens)}
            </TableCell>
            <TableCell className="text-right tabular-nums text-text">
              {m.estimatedCostUsd !== null ? formatUsd(m.estimatedCostUsd) : '—'}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function ActivityTokenUsageView({
  summary,
  isLoading,
  error,
  rangeLabel,
}: {
  summary: TokenUsageSummary | null;
  isLoading: boolean;
  error: string | null;
  /** e.g. "Last 30 days" — the time window the aggregate covers. */
  rangeLabel?: string;
}) {
  const [open, setOpen] = useState(false);

  if (error) {
    return (
      <Card className="mb-3.5 shrink-0 px-5 py-3.5 shadow-sm">
        <WidgetError message={error} />
      </Card>
    );
  }

  if (isLoading && !summary) {
    return (
      <Card className="mb-3.5 flex shrink-0 items-center gap-2.5 px-5 py-3.5 shadow-sm" aria-busy>
        <Skeleton className="size-8 shrink-0 rounded-lg" />
        <Skeleton className="h-5 w-64" />
      </Card>
    );
  }

  const hasUsage = summary !== null && summary.models.length > 0;

  if (!hasUsage) {
    return (
      <Card className="mb-3.5 flex shrink-0 items-center gap-2.5 px-5 py-3.5 shadow-sm">
        <HeaderIcon />
        <div className="min-w-0">
          <div className="text-ui font-semibold text-text">Token usage</div>
          <div className="text-xs text-text-3">
            No token usage recorded yet — sessions are reconciled as you work.
          </div>
        </div>
      </Card>
    );
  }

  const sessions = `${String(summary.sessionCount)} session${summary.sessionCount === 1 ? '' : 's'}`;
  const cost = formatCostTotal(summary.estimatedCostUsd, summary.costIsPartial);

  return (
    <Card className="mb-3.5 shrink-0 overflow-hidden shadow-sm">
      <button
        type="button"
        onClick={() => {
          setOpen((v) => !v);
        }}
        aria-expanded={open}
        aria-controls="activity-token-usage-body"
        className="flex w-full cursor-pointer items-center gap-2.5 px-5 py-3.5 text-left transition-colors hover:bg-surface-2"
      >
        <HeaderIcon />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <span className="text-ui font-semibold text-text">Token usage</span>
            {rangeLabel && <span className="text-xs text-text-3">· {rangeLabel}</span>}
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-2.5 gap-y-0.5 text-xs text-text-3">
            <span>{sessions}</span>
            <span className="text-border-strong">·</span>
            <span className="font-semibold tabular-nums text-text-2">
              {tokenLabel(summary.totalTokens)} tokens
            </span>
            <span className="text-border-strong">·</span>
            <span className="font-semibold tabular-nums text-text-2">{cost}</span>
          </div>
        </div>
        <ChevronDownIcon
          aria-hidden
          focusable={false}
          className={cn('size-4 shrink-0 text-text-3 transition-transform', open && 'rotate-180')}
        />
      </button>
      {open && (
        <div
          id="activity-token-usage-body"
          className="max-h-64 overflow-y-auto border-t border-border px-2 pb-2 pt-1"
        >
          <ModelTable summary={summary} />
          {summary.costIsPartial && (
            <p className="px-3 pb-1 pt-2 text-xs text-text-3">
              — = unknown pricing (a local or non-Anthropic model); the cost total is a lower bound.
            </p>
          )}
        </div>
      )}
    </Card>
  );
}
