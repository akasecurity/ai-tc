'use client';

import type { FindingInstance } from '@akasecurity/schema';
import { Button, cn, SeverityBadge, SheetHeader, SheetTitle } from '@akasecurity/ui-kit';
import type { ReactNode } from 'react';

import { relativeTime } from '../lib/relativeTime.ts';
import { MetaItem, SectionLabel } from '../shared/DetailFields.tsx';
import { ChevronLeftIcon, ChevronRightIcon, EyeOffIcon, KeyIcon } from '../shared/icons.tsx';
import { Provider } from '../shared/Provider.tsx';
import { ActionTag } from './ActionTag.tsx';
import { CATEGORY_ICON_FALLBACK, CATEGORY_LABEL, categoryStyle, type Selection } from './meta.ts';
import { ProviderTag } from './ProviderChips.tsx';

/** Human-readable confidence band + score for an instance's 0–1 confidence. */
export function formatConfidence(confidence: number): { label: string; tone: string } {
  const score = confidence.toFixed(2);
  if (confidence >= 0.9) return { label: `High · ${score}`, tone: 'text-ok' };
  if (confidence >= 0.7) return { label: `Medium · ${score}`, tone: 'text-sev-high' };
  return { label: `Low · ${score}`, tone: 'text-text-2' };
}

function Confidence({ confidence }: { confidence: number }) {
  const { label, tone } = formatConfidence(confidence);
  return <span className={tone}>{label}</span>;
}

function getCategoryLabel(category: string): string {
  const categoryLabel = CATEGORY_LABEL[category as keyof typeof CATEGORY_LABEL];
  if (categoryLabel) return categoryLabel;
  return category;
}

/**
 * Right-drawer body for a finding — grouped (locations list) or single instance.
 * Presentational: no data fetching, no mutations. App-specific affordances
 * (matched policy, Resolve, Action) are injected by the app via `footer`; the
 * OSS web-ui passes none.
 */
export function FindingDetailView({
  selection,
  onSelectInstance,
  onBack,
  footer,
}: {
  selection: Selection;
  onSelectInstance: (instance: FindingInstance) => void;
  onBack: () => void;
  footer?: ReactNode;
}) {
  const { finding, instance } = selection;
  const Icon = CATEGORY_ICON_FALLBACK[finding.category] ?? KeyIcon;
  const grouped = !instance;
  const providerCount = finding.providers.length;
  const category = getCategoryLabel(finding.category);

  return (
    <>
      <SheetHeader className="flex-row items-center gap-2.5 border-b border-border p-4 pr-12">
        <SeverityBadge severity={finding.severity} />
        {/* Doubles as the dialog's accessible name (Radix aria-labelledby). */}
        <SheetTitle className="font-mono text-xs font-semibold text-text-3">
          {grouped ? category : instance.id}
        </SheetTitle>
      </SheetHeader>
      <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
        {/* Back link to the grouped view (single-instance, multi-location only). */}
        {!grouped && (
          <Button variant="link" tone="primary" size="sm" onClick={onBack} className="self-start">
            <ChevronLeftIcon aria-hidden focusable={false} className="size-4" />
            Back to finding
          </Button>
        )}

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
              {grouped
                ? `${String(finding.instances.length)} locations · ${String(providerCount)} tool${providerCount > 1 ? 's' : ''}`
                : `${category} · ${instance.repo} · detected ${relativeTime(instance.detectedAt)}`}
            </span>
          </div>
        </div>

        {/* Matched content (masked, syntax-highlighted) */}
        <MatchedContent
          code={finding.match.contextPrefix}
          snippet={finding.match.maskedValue}
          file={grouped ? `${String(finding.instances.length)} files` : instance.file}
        />

        {grouped ? (
          <div>
            <SectionLabel>Locations</SectionLabel>
            <div className="flex flex-col gap-2">
              {finding.instances.map((i) => (
                <LocationRow
                  key={i.id}
                  instance={i}
                  onClick={() => {
                    onSelectInstance(i);
                  }}
                />
              ))}
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-x-3 gap-y-3.5">
            <MetaItem label="Source tool">
              <ProviderTag provider={instance.provider} />
            </MetaItem>
            <MetaItem label="Repository">
              <span className="font-mono text-xs wrap-break-word">{instance.repo}</span>
            </MetaItem>
            <MetaItem label="Location">
              <span className="font-mono text-xs wrap-break-word">{instance.file}</span>
            </MetaItem>
            <MetaItem label="Action taken">
              <ActionTag action={instance.action} />
            </MetaItem>
            <MetaItem label="Detected">{relativeTime(instance.detectedAt)}</MetaItem>
            <MetaItem label="Confidence">
              <Confidence confidence={instance.confidence} />
            </MetaItem>
          </div>
        )}

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
      <SectionLabel className="flex items-center gap-2">
        Matched content
        <EyeOffIcon aria-hidden focusable={false} className="size-3.5" />
      </SectionLabel>
      <div className="rounded-lg border border-border bg-ink p-3.5 font-mono text-xs leading-relaxed text-code-fg">
        <div className="text-code-muted wrap-break-word">{`// ${file}`}</div>
        <div>
          {code}
          <span className="rounded bg-sev-critical/20 px-1 py-0.5 text-code-err">{`"${snippet}"`}</span>
          ;
        </div>
      </div>
    </div>
  );
}

/** One clickable location in the grouped view's Locations list. */
function LocationRow({ instance, onClick }: { instance: FindingInstance; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center cursor-pointer gap-3 rounded-lg border border-border bg-surface px-3 py-2.5 text-left transition-colors hover:bg-surface-2"
    >
      <Provider id={instance.provider} />
      <div className="flex min-w-0 flex-1 flex-col">
        <span className="text-xs font-medium text-text">{instance.repo}</span>
        <span className="font-mono text-label text-text-3 wrap-break-word">{instance.file}</span>
      </div>
      <ActionTag action={instance.action} />
      <ChevronRightIcon className="size-4 shrink-0 text-text-3" />
    </button>
  );
}
