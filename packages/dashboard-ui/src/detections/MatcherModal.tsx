'use client';
// Read-only rule inspector. Detection rules are immutable version snapshots from
// the registry — there is no in-place matcher editing — so this shows the rule's
// matcher configuration without an edit/save path. Shared by both dashboards.
import type { DetectionRule, Matcher } from '@akasecurity/schema';
import { Button, Dialog, DialogContent, DialogTitle, SeverityBadge } from '@akasecurity/ui-kit';
import { type ReactNode } from 'react';

import { ListIcon, XIcon } from '../shared/icons.tsx';
import { CATEGORY_LABEL, MATCHER_META } from './meta.ts';

function MatcherDetail({ matcher }: { matcher: Matcher }) {
  if (matcher.type === 'regex') {
    return (
      <div className="flex flex-col gap-3">
        <Field label="Pattern">
          <code className="block break-all rounded-md border border-border bg-surface-2 px-2.5 py-2 font-mono text-xs text-text">
            {matcher.pattern}
          </code>
        </Field>
        <Field label="Flags">
          <code className="font-mono text-xs text-text-2">{matcher.flags || '—'}</code>
        </Field>
        {typeof matcher.captureGroup === 'number' && (
          <Field label="Capture group">
            <span className="font-mono text-xs text-text-2">{matcher.captureGroup}</span>
          </Field>
        )}
      </div>
    );
  }
  if (matcher.type === 'keyword') {
    return (
      <div className="flex flex-col gap-3">
        <Field label="Keywords">
          <div className="flex flex-wrap gap-1.5">
            {matcher.keywords.map((kw) => (
              <span
                key={kw}
                className="inline-flex h-6 items-center rounded-md border border-border bg-surface-2 px-2 font-mono text-xs text-text-2"
              >
                {kw}
              </span>
            ))}
          </div>
        </Field>
        <Field label="Case sensitive">
          <span className="text-xs text-text-2">{matcher.caseSensitive ? 'Yes' : 'No'}</span>
        </Field>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-3">
      <Field label="Validator">
        <code className="font-mono text-xs text-text-2">{matcher.name}</code>
      </Field>
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="text-label font-semibold uppercase tracking-wider text-text-3">{label}</div>
      {children}
    </div>
  );
}

export function MatcherModal({
  rule,
  onClose,
}: {
  rule: DetectionRule | null;
  onClose: () => void;
}) {
  const open = !!rule;
  const mm = rule ? MATCHER_META[rule.matcher.type] : null;
  const MatcherIcon = mm?.icon;

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!o) onClose();
      }}
    >
      <DialogContent className="max-w-3xl" aria-describedby={undefined}>
        {rule && mm && (
          <>
            <DialogTitle className="sr-only">Rule · {rule.name}</DialogTitle>
            {/* header */}
            <div className="flex shrink-0 items-center gap-3 border-b border-border px-5 py-4">
              <span
                className="grid size-9 shrink-0 place-items-center rounded-lg"
                style={{ background: mm.fill, color: mm.color }}
              >
                {MatcherIcon && <MatcherIcon aria-hidden focusable={false} className="size-4.5" />}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2.5">
                  <span className="font-display text-base font-semibold text-text">
                    {rule.name}
                  </span>
                  <SeverityBadge severity={rule.severity} />
                </div>
                <div className="mt-px font-mono text-xs text-text-3">{rule.id}</div>
              </div>
              <span
                className="rounded-full px-2.5 py-1 text-xs font-semibold"
                style={{ background: mm.fill, color: mm.color }}
              >
                {mm.label}
              </span>
              <Button
                variant="ghost"
                tone="neutral"
                size="icon"
                onClick={onClose}
                aria-label="Close"
                className="size-8 text-text-3"
              >
                <XIcon aria-hidden focusable={false} />
              </Button>
            </div>

            {/* body */}
            <div className="min-h-0 flex-1 overflow-y-auto p-5">
              <div className="mb-4 flex flex-wrap gap-2">
                <Tag icon={<ListIcon aria-hidden focusable={false} className="size-3.5" />}>
                  {CATEGORY_LABEL[rule.category] || rule.category}
                </Tag>
                <Tag
                  icon={
                    MatcherIcon && (
                      <MatcherIcon aria-hidden focusable={false} className="size-3.5" />
                    )
                  }
                >
                  {mm.blurb}
                </Tag>
              </div>
              <MatcherDetail matcher={rule.matcher} />
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function Tag({ icon, children }: { icon?: ReactNode; children: ReactNode }) {
  return (
    <span className="inline-flex h-6 items-center gap-1.5 rounded-md border border-border bg-surface px-2 text-label font-medium text-text-2">
      {icon}
      {children}
    </span>
  );
}
