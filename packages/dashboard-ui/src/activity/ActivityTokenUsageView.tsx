'use client';
// The Activity page's token-usage control: a compact chip that sits in the page's
// filter bar beside the range picker and opens the per-(provider, model)
// breakdown in a slide-over. It reads as a glance — total tokens + estimated
// cost — and costs one row of the filter bar rather than a full-width card, so
// the session list/detail below it keeps the viewport.
//
// It opens SIDEWAYS rather than expanding down on purpose: an inline expansion
// pushes the master/detail panes off-screen, which is the space the panel exists
// to summarise.
//
// Props-driven off the shared @akasecurity/schema `TokenUsageSummary` (built by
// `aggregateTokenUsage`), so token counts are exact truth and cost is a
// read-time estimate (`~$X`, or `≥ $X` when some calls have unknown pricing).
import type { TokenUsageSummary } from '@akasecurity/schema';
import {
  Button,
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@akasecurity/ui-kit';
import { useState } from 'react';

import { AnalyticsIcon } from '../shared/icons.tsx';
import { WidgetEmpty, WidgetError } from '../shared/widget-state.tsx';
import { formatCostTotal, formatUsd, tokenLabel } from './format.ts';

/** Per-model rows table — the slide-over body. Token counts are compact; a model
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
            <TableCell className="max-w-40 truncate font-mono text-text" title={m.model}>
              {m.model}
            </TableCell>
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

  if (isLoading && !summary) {
    return <Skeleton className="h-9 w-44 rounded-lg" aria-busy />;
  }

  const hasUsage = summary !== null && summary.models.length > 0;

  // The chip renders on every state so the control never moves; which of the
  // three bodies the slide-over shows is what varies.
  const chipLabel = error
    ? 'Token usage'
    : hasUsage
      ? `${tokenLabel(summary.totalTokens)} tokens · ${formatCostTotal(summary.estimatedCostUsd, summary.costIsPartial)}`
      : 'No token usage';

  const chipTitle = error
    ? `Token usage could not be read — ${error}`
    : hasUsage
      ? `Token usage${rangeLabel ? ` · ${rangeLabel}` : ''} — ${String(summary.sessionCount)} session${summary.sessionCount === 1 ? '' : 's'}. Open the per-model breakdown.`
      : 'No token usage recorded yet — open for details';

  return (
    <>
      <Button
        variant="outline"
        size="md"
        title={chipTitle}
        aria-label="Token usage — open the per-model breakdown"
        onClick={() => {
          setOpen(true);
        }}
      >
        <AnalyticsIcon
          aria-hidden
          focusable={false}
          className={error ? 'size-4 text-sev-critical-ink' : 'size-4 text-primary'}
        />
        <span className="max-w-56 truncate tabular-nums">{chipLabel}</span>
      </Button>

      <Sheet open={open} onOpenChange={setOpen}>
        {/* No description in this panel — opt out of Radix's aria-describedby. */}
        <SheetContent
          className="w-200 max-w-[94%] gap-0 overflow-hidden p-0"
          aria-describedby={undefined}
        >
          <SheetHeader className="shrink-0 border-b border-border px-5 py-4">
            <SheetTitle className="flex items-center gap-2">
              <AnalyticsIcon aria-hidden focusable={false} className="size-4 text-primary" />
              Token usage
              {rangeLabel && (
                <span className="text-ui font-normal text-text-3">· {rangeLabel}</span>
              )}
            </SheetTitle>
            {hasUsage && (
              <div className="mt-1 flex flex-wrap items-center gap-x-2.5 gap-y-0.5 text-xs text-text-3">
                <span>
                  {summary.sessionCount} session{summary.sessionCount === 1 ? '' : 's'}
                </span>
                <span>·</span>
                <span className="font-semibold tabular-nums text-text-2">
                  {tokenLabel(summary.totalTokens)} tokens
                </span>
                <span>·</span>
                <span className="font-semibold tabular-nums text-text-2">
                  {formatCostTotal(summary.estimatedCostUsd, summary.costIsPartial)}
                </span>
              </div>
            )}
          </SheetHeader>
          <div className="min-h-0 flex-1 overflow-auto px-2 py-2">
            {error ? (
              <div className="p-3">
                <WidgetError message={error} />
              </div>
            ) : hasUsage ? (
              <>
                <ModelTable summary={summary} />
                {summary.costIsPartial && (
                  <p className="px-3 pb-1 pt-2 text-xs text-text-3">
                    — = unknown pricing (a local or non-Anthropic model); the cost total is a lower
                    bound.
                  </p>
                )}
              </>
            ) : (
              <div className="p-3">
                <WidgetEmpty message="No token usage recorded yet — sessions are reconciled as you work." />
              </div>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </>
  );
}
