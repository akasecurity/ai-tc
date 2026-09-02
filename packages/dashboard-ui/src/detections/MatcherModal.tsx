'use client';
// Read-only rule inspector. Detection rules are immutable version snapshots from
// the registry — there is no in-place matcher editing — so this shows the rule's
// matcher configuration without an edit/save path. Shared by both dashboards.
import type { DetectionRule, Matcher, RuleFixture } from '@akasecurity/schema';
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

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="text-label font-semibold uppercase tracking-wider text-text-3">{label}</div>
      {children}
    </div>
  );
}

/**
 * One line of author-supplied text — an example or a fixture body.
 *
 * These are the strings a rule is built to CATCH, so they are secret-shaped by
 * construction and arrive from whoever published the pack. Rendered as text and
 * nothing else: React escapes children, so the only way to get markup in here
 * would be to reach for dangerouslySetInnerHTML, and there is no reason to.
 * `break-all` because a long unbroken token (which is the normal case) would
 * otherwise push the dialog sideways.
 */
function SampleText({ children }: { children: string }) {
  return (
    <code className="block break-all rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs text-text-2">
      {children}
    </code>
  );
}

/**
 * The gates a candidate match has to clear after the matcher has found it.
 *
 * Worth its own section rather than a footnote: a rule is not just its matcher.
 * `postValidators` is its false-positive guard, `appliesTo` scopes it to a file
 * type, and `requiresNearby` demands corroboration — so an inspector showing only
 * the pattern describes a rule that fires far more often than the real one does.
 * Half the bundled catalog carries at least one of these.
 *
 * Renders nothing when a rule sets none, which is the other half of the catalog.
 */
function GatingDetail({ rule }: { rule: DetectionRule }) {
  const nearby = rule.requiresNearby;
  const criteria = nearby
    ? [
        ...(nearby.categories ?? []).map((c) => `category ${c}`),
        ...(nearby.ruleIds ?? []).map((r) => `rule ${r}`),
        ...(nearby.labels ?? []).map((l) => `"${l}"`),
      ]
    : [];

  if (!rule.appliesTo && !rule.postValidators?.length && !nearby) return null;

  return (
    <div className="flex flex-col gap-3">
      {rule.appliesTo && (
        <Field label="Only in files">
          <div className="flex flex-wrap gap-1.5">
            {rule.appliesTo.extensions.map((ext) => (
              <span
                key={ext}
                className="inline-flex h-6 items-center rounded-md border border-border bg-surface-2 px-2 font-mono text-xs text-text-2"
              >
                {ext}
              </span>
            ))}
          </div>
        </Field>
      )}

      {rule.postValidators && rule.postValidators.length > 0 && (
        <Field label="Must also pass">
          <div className="flex flex-wrap gap-1.5">
            {rule.postValidators.map((v) => {
              // PostValidatorRef is a bare name or { name, config } — the object
              // form exists for per-rule tuning, and both spell the same name.
              const name = typeof v === 'string' ? v : v.name;
              return (
                <span
                  key={name}
                  className="inline-flex h-6 items-center rounded-md border border-border bg-surface-2 px-2 font-mono text-xs text-text-2"
                >
                  {name}
                </span>
              );
            })}
          </div>
        </Field>
      )}

      {nearby && (
        <Field label={`Needs corroboration within ${String(nearby.windowChars)} chars`}>
          <div className="text-xs leading-snug text-text-2">{criteria.join(' · ')}</div>
        </Field>
      )}
    </div>
  );
}

/**
 * The author's own test cases for this rule: what it must catch, and what it must
 * NOT catch. The negatives are the interesting half — they are how an author
 * records that a near-miss was considered and deliberately excluded, which is
 * exactly the question someone tuning a noisy rule is asking.
 *
 * Deliberately not scored here. A pass/fail verdict is a claim about what the
 * engine does right now, and this component runs no engine — it renders what the
 * pack shipped. Anything that wants a live verdict has POST /v1/rules/test.
 */
function FixtureList({ fixtures }: { fixtures: readonly RuleFixture[] }) {
  return (
    <div className="flex flex-col gap-2">
      {fixtures.map((f, i) => (
        <div key={`${f.label}-${String(i)}`} className="flex flex-col gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={
                'inline-flex h-5 items-center rounded-full px-2 text-label font-semibold ' +
                (f.shouldMatch ? 'bg-ok-fill text-ok-ink' : 'bg-surface-3 text-text-3')
              }
            >
              {f.shouldMatch ? 'matches' : 'does not match'}
            </span>
            <span className="text-xs text-text-2">{f.label}</span>
            {f.filePath !== undefined && (
              <span className="font-mono text-label text-text-3">{f.filePath}</span>
            )}
          </div>
          <SampleText>{f.text}</SampleText>
        </div>
      ))}
    </div>
  );
}

/**
 * Everything the rule inspector says about a rule: what it matches on, what gates
 * that match has to clear, what it catches, and what its author asserted about it.
 *
 * Split out of the dialog rather than inlined, for two reasons. It is the reusable
 * half — a host wanting this in a side panel or an expanded row needs the content
 * without the modal chrome. And it is the TESTABLE half: `MatcherModal` renders
 * through a Radix portal, which produces no markup at all under
 * `renderToStaticMarkup`, so every assertion aimed at the dialog would pass
 * against an empty string. This package's suite runs on Node with no DOM.
 */
export function RuleInspectorBody({
  rule,
  fixtures,
}: {
  rule: DetectionRule;
  fixtures?: readonly RuleFixture[] | undefined;
}) {
  const mm = MATCHER_META[rule.matcher.type];
  const MatcherIcon = mm.icon;

  return (
    <>
      <div className="mb-4 flex flex-wrap gap-2">
        <Tag icon={<ListIcon aria-hidden focusable={false} className="size-3.5" />}>
          {CATEGORY_LABEL[rule.category] || rule.category}
        </Tag>
        <Tag icon={<MatcherIcon aria-hidden focusable={false} className="size-3.5" />}>
          {mm.blurb}
        </Tag>
      </div>
      <MatcherDetail matcher={rule.matcher} />

      {/* Everything below is optional per rule, and each section renders only
          when the rule actually has it — an empty heading says "nothing here"
          where absence says "this rule does not use it". */}
      <GatingDetail rule={rule} />

      {rule.examples && rule.examples.length > 0 && (
        <div className="mt-4">
          <Field label="Catches values like">
            <div className="flex flex-col gap-1.5">
              {rule.examples.map((ex, i) => (
                <SampleText key={`${ex}-${String(i)}`}>{ex}</SampleText>
              ))}
            </div>
          </Field>
        </div>
      )}

      {fixtures && fixtures.length > 0 && (
        <div className="mt-4">
          <Field label={`Test cases (${String(fixtures.length)})`}>
            <FixtureList fixtures={fixtures} />
          </Field>
        </div>
      )}
    </>
  );
}

export function MatcherModal({
  rule,
  fixtures,
  onClose,
}: {
  rule: DetectionRule | null;
  /**
   * The rule's published test cases, when the app has them.
   *
   * A prop rather than something this component fetches, because the two
   * dashboards get them from different places and one of them cannot get them at
   * all: they live on the registry's pack version and are deliberately not copied
   * into the installed snapshot, so an app with no registry configured has none
   * to pass. Omitted renders no section — an absent fixtures block reads as "not
   * loaded here", which is true, where an empty one would read as "this rule
   * ships no tests", which would be false for every bundled rule.
   */
  fixtures?: readonly RuleFixture[] | undefined;
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
              <RuleInspectorBody rule={rule} fixtures={fixtures} />
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
