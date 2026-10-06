'use client';

import type { FindingContext } from '@akasecurity/schema';
import { cn, SeverityBadge, SheetHeader, SheetTitle } from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

import { relativeTime } from '../lib/relativeTime.ts';
import { MetaItem, SectionLabel } from '../shared/DetailFields.tsx';
import { KeyIcon } from '../shared/icons.tsx';
import { ActionTag } from './ActionTag.tsx';
import { DeploymentMetaItem } from './DeploymentMetaItem.tsx';
import {
  CATEGORY_ICON_FALLBACK,
  categoryLabel,
  categoryStyle,
  type DeploymentDisplay,
  instanceLocationLabel,
  type Selection,
  USER_COLUMN_TITLE,
} from './meta.ts';
import { ProviderTag } from './ProviderChips.tsx';
import { UserCell } from './UserCell.tsx';

/** Human-readable confidence band + score for an instance's 0–1 confidence. */
export function formatConfidence(confidence: number): { label: string; tone: string } {
  const score = confidence.toFixed(2);
  if (confidence >= 0.9) return { label: `High · ${score}`, tone: 'text-ok-ink' };
  if (confidence >= 0.7) return { label: `Medium · ${score}`, tone: 'text-sev-high-ink' };
  return { label: `Low · ${score}`, tone: 'text-text-2' };
}

function Confidence({ confidence }: { confidence: number }) {
  const { label, tone } = formatConfidence(confidence);
  return <span className={tone}>{label}</span>;
}

/**
 * Right-drawer body for ONE finding instance. Every caller opens the drawer
 * already narrowed to a row, so there is no group to render or step back to —
 * `Selection.instance` is required, which is what keeps that true.
 * Presentational: no data fetching, no mutations. App-specific affordances
 * (matched policy, Resolve, Action) are injected by the app via `footer`; the
 * OSS web-ui passes none.
 */
export function FindingDetailView({
  selection,
  footer,
  deployment,
  renderedAt,
  contextLoading = false,
}: {
  selection: Selection;
  footer?: ReactNode;
  /**
   * True while the host is still fetching this finding's excerpt, so the
   * Matched content block says so instead of reporting it was not kept.
   */
  contextLoading?: boolean;
  /**
   * The deployment this machine sends to, or null/absent where it is not
   * attached — which renders no Deployment row.
   */
  deployment?: DeploymentDisplay | null;
  /**
   * The instant this render is measured against, in epoch milliseconds. The host
   * captures one and every relative label below reads it. Required: a view that
   * picks its own instant renders one string while the server renders it and
   * another when the browser hydrates it. See ../lib/relativeTime.ts.
   */
  renderedAt: number;
}) {
  const { finding, instance } = selection;
  const Icon = CATEGORY_ICON_FALLBACK[finding.category] ?? KeyIcon;
  const category = categoryLabel(finding.category);

  return (
    <>
      <SheetHeader className="flex-row items-center gap-2.5 border-b border-border p-4 pr-12">
        <SeverityBadge severity={finding.severity} />
        {/* Doubles as the dialog's accessible name (Radix aria-labelledby). */}
        <SheetTitle className="min-w-0 font-mono text-xs font-semibold text-text-3 wrap-break-word">
          {instance.id}
        </SheetTitle>
      </SheetHeader>
      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
        {/* Title */}
        <div className="flex items-start gap-3">
          <span
            className={cn(
              'flex size-10 shrink-0 items-center justify-center rounded-lg',
              categoryStyle(finding.category),
            )}
          >
            <Icon className="size-5" />
          </span>
          <div className="flex flex-col">
            <span className="font-display text-base font-semibold">{finding.subtype}</span>
            <span className="text-xs text-text-3">
              {category} · {instance.repo} · detected{' '}
              {relativeTime(instance.detectedAt, renderedAt)}
            </span>
          </div>
        </div>

        <MatchedContent
          context={finding.match.context}
          contextPrefix={finding.match.contextPrefix}
          line={instance.line}
          loading={contextLoading}
          maskedValue={finding.match.maskedValue}
          file={instanceLocationLabel(instance)}
        />

        <div className="grid grid-cols-2 gap-x-3 gap-y-3.5">
          <MetaItem label="Source tool">
            <ProviderTag provider={instance.provider} />
          </MetaItem>
          <MetaItem label="Repository">
            <span className="font-mono text-xs wrap-break-word">{instance.repo}</span>
          </MetaItem>
          <MetaItem label="Location">
            <span className="font-mono text-xs wrap-break-word">
              {locationWithLine(
                instanceLocationLabel(instance),
                finding.match.context,
                instance.line,
              )}
            </span>
          </MetaItem>
          <MetaItem label="Action taken">
            <ActionTag action={instance.action} />
          </MetaItem>
          <MetaItem label="Detected">{relativeTime(instance.detectedAt, renderedAt)}</MetaItem>
          <MetaItem label="Confidence">
            <Confidence confidence={instance.confidence} />
          </MetaItem>
          {/* Only a store that attributes findings to people sets `user`. */}
          {instance.user !== undefined && (
            <MetaItem label="User">
              <span title={USER_COLUMN_TITLE}>
                <UserCell user={instance.user} />
              </span>
            </MetaItem>
          )}
          {deployment !== undefined && deployment !== null && instance.delivery !== undefined && (
            <DeploymentMetaItem
              delivery={instance.delivery}
              deployment={deployment}
              renderedAt={renderedAt}
            />
          )}
        </div>

        {/* App-injected sections (matched policy / Resolve / Action) render here. */}
        {footer}
      </div>
    </>
  );
}

/**
 * The finding's location with its line: `file:69` when the line counts in the
 * whole file, `file (line 3 of the captured text)` when it counts in a fragment
 * such as an edit's replacement text. No excerpt, no line: the excerpt says
 * which of the two the line counts in.
 *
 * `line` is the finding's own stored line, and wins; a finding recorded before
 * lines were stored falls back to what its excerpt can tell.
 */
export function locationWithLine(
  file: string,
  context: FindingContext | undefined,
  line?: number,
): string {
  if (context === undefined) return file;
  return context.basis === 'file'
    ? `${file}:${String(findingLine(context, line))}`
    : `${file} (line ${String(findingLine(context, line))} of the captured text)`;
}

/** The line a finding sits on: its stored line, else its excerpt's match, else the excerpt's only line. */
function findingLine(context: FindingContext, line: number | undefined): number {
  return line ?? context.match?.line ?? context.firstLine;
}

const PLACEHOLDER = /(\[REDACTED:[A-Z_]+\])/;

/** One excerpt line, with each redaction placeholder set apart from the code. */
function CodeText({ text }: { text: string }) {
  return (
    <>
      {text.split(PLACEHOLDER).map((part, i) =>
        PLACEHOLDER.test(part) ? (
          <span key={i} className="text-code-muted">
            {part}
          </span>
        ) : (
          part
        ),
      )}
    </>
  );
}

/**
 * The masked lines around the match, numbered, with the matched code
 * highlighted. Every secret in them was redacted when the finding was
 * detected; this renders what it is given.
 */
function MatchedContent({
  context,
  contextPrefix,
  line,
  loading,
  maskedValue,
  file,
}: {
  context: FindingContext | undefined;
  // A host that supplies only the line's prefix (the field the excerpt
  // supersedes) still has it shown before the masked value.
  contextPrefix: string;
  line: number | undefined;
  loading: boolean;
  maskedValue: string;
  file: string;
}) {
  const prefixOnly = context === undefined && !loading && contextPrefix !== '';
  return (
    <div>
      <SectionLabel>Matched content</SectionLabel>
      <div className="rounded-lg border border-border bg-ink p-3.5 font-mono text-xs leading-relaxed text-code-fg">
        <div className="text-code-muted wrap-break-word">{`// ${locationWithLine(file, context, line)}`}</div>
        {prefixOnly ? (
          <div>
            {contextPrefix}
            <span className="rounded bg-sev-critical/20 px-1 py-0.5 text-code-err wrap-break-word">{`"${maskedValue}"`}</span>
            ;
          </div>
        ) : context === undefined ? (
          <div className="text-code-muted">
            {loading
              ? 'Loading the code around this match…'
              : 'The code around this match wasn’t kept.'}
          </div>
        ) : (
          <ExcerptLines context={context} markedLine={findingLine(context, line)} />
        )}
        {/* The masked preview, wherever the match itself is not readable above:
            no excerpt yet or at all, or a value the excerpt redacts. A fully
            masked preview carries nothing a reader can use. */}
        {!prefixOnly && (context?.match ?? null) === null && maskedValue !== '***' && (
          <div>
            Matched value:{' '}
            <span className="rounded bg-sev-critical/20 px-1 py-0.5 text-code-err wrap-break-word">
              {maskedValue}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

function ExcerptLines({ context, markedLine }: { context: FindingContext; markedLine: number }) {
  const width = String(context.firstLine + context.lines.length - 1).length;
  return (
    <div className="mt-1 overflow-x-auto">
      {context.lines.map((text, i) => {
        const line = context.firstLine + i;
        const marked = line === markedLine;
        const match = context.match !== null && context.match.line === line ? context.match : null;
        return (
          <div
            key={line}
            data-line={line}
            className={cn('flex whitespace-pre', marked ? 'text-code-fg' : 'text-code-muted')}
          >
            <span aria-hidden="true" className="w-4 shrink-0 select-none text-code-err">
              {marked ? '▶' : ''}
            </span>
            <span className="mr-3 shrink-0 select-none text-right text-code-muted">
              {String(line).padStart(width, ' ')}
            </span>
            <span>
              {match === null ? (
                <CodeText text={text} />
              ) : (
                <>
                  <CodeText text={text.slice(0, match.start)} />
                  <mark className="rounded bg-sev-critical/20 px-0.5 text-code-err">
                    <CodeText text={text.slice(match.start, match.end)} />
                  </mark>
                  <CodeText text={text.slice(match.end)} />
                </>
              )}
            </span>
          </div>
        );
      })}
    </div>
  );
}
