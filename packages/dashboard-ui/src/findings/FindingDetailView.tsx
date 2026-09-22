'use client';

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
}: {
  selection: Selection;
  footer?: ReactNode;
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

        {/* Matched content (masked, syntax-highlighted) */}
        <MatchedContent
          code={finding.match.contextPrefix}
          snippet={finding.match.maskedValue}
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
              {instanceLocationLabel(instance)}
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

/** Syntax-highlighted code block showing the masked match in context. */
function MatchedContent({ code, snippet, file }: { code: string; snippet: string; file: string }) {
  return (
    <div>
      <SectionLabel>Matched content</SectionLabel>
      <div className="rounded-lg border border-border bg-ink p-3.5 font-mono text-xs leading-relaxed text-code-fg">
        <div className="text-code-muted wrap-break-word">{`// ${file}`}</div>
        <div>
          {code}
          <span className="rounded bg-sev-critical/20 px-1 py-0.5 text-code-err wrap-break-word">{`"${snippet}"`}</span>
          ;
        </div>
      </div>
    </div>
  );
}
