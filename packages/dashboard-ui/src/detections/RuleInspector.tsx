'use client';
// Read-only rule inspector. Detection rules are immutable version snapshots from
// the registry — there is no in-place editing — so this shows what a rule matches
// on, what gates that match has to clear, what it catches, and what its author
// asserted about it, with no edit/save path. Shared by both dashboards, as the
// `MatcherModal` dialog and as the bare `RuleInspectorBody` a host can drop into a
// side panel or an expanded row.
import type { DetectionRule, Matcher, RuleFixture } from '@akasecurity/schema';
import { Button, Dialog, DialogContent, DialogTitle, SeverityBadge } from '@akasecurity/ui-kit';
import { type ReactNode } from 'react';

import { ListIcon, XIcon } from '../shared/icons.tsx';
import { CATEGORY_LABEL, MATCHER_META, type MatcherMeta } from './meta.ts';

/**
 * Bounds on author-supplied lists.
 *
 * Examples, fixtures and post-validator configs all arrive from whoever published
 * the pack, and none of them is bounded by the schema: `Rule.examples` is a bare
 * `z.array(z.string())`, `RuleFixture.text` caps ONE body at 50,000 characters and
 * says nothing about how many bodies a pack ships, and a validator `config` is an
 * open record. A pack declaring a few thousand entries would otherwise render
 * every one of them into a dialog the tenant did not choose to open.
 *
 * The escaping half of this surface was already handled — React escapes children,
 * and nothing here reaches for an escape hatch. This is the volume half. The
 * render says what it left out rather than quietly showing less than the pack
 * ships.
 */
const MAX_SAMPLES = 20;
const MAX_SAMPLE_CHARS = 1_000;
const MAX_LABEL_CHARS = 120;
const MAX_CONFIG_ENTRIES = 6;

function clamp(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/** The trailing count for a list the render bounded. Nothing when it did not. */
function Elided({ hidden }: { hidden: number }) {
  if (hidden <= 0) return null;
  return <div className="text-xs text-text-2">+{String(hidden)} more not shown</div>;
}

/** One monospace pill — a keyword, a file extension, a post-validator. */
function Chip({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex h-6 items-center rounded-md border border-border bg-surface-2 px-2 font-mono text-xs text-text-2">
      {children}
    </span>
  );
}

/**
 * One block of author-supplied text — a regex pattern, an example, a fixture body.
 *
 * These are the strings a rule is built to CATCH, so they are secret-shaped by
 * construction and arrive from whoever published the pack. Rendered as text and
 * nothing else: React escapes children, so the only way to get markup in here
 * would be to reach for dangerouslySetInnerHTML, and there is no reason to.
 * `break-all` because a long unbroken token (which is the normal case) would
 * otherwise push the dialog sideways.
 *
 * `emphasis` is the pattern's own tier — it is the rule's defining value rather
 * than one of several illustrations of it. Everything else about the block is
 * shared, so a token retune lands in one place instead of two that drifted.
 */
function SampleText({ children, emphasis = false }: { children: string; emphasis?: boolean }) {
  return (
    <code
      className={
        'block break-all rounded-md border border-border bg-surface-2 px-2.5 font-mono text-xs ' +
        (emphasis ? 'py-2 text-text' : 'py-1.5 text-text-2')
      }
    >
      {children}
    </code>
  );
}

function MatcherDetail({ matcher }: { matcher: Matcher }) {
  if (matcher.type === 'regex') {
    return (
      <div className="flex flex-col gap-3">
        <Field label="Pattern">
          <SampleText emphasis>{matcher.pattern}</SampleText>
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
          {matcher.keywords.map((kw, i) => (
            // `keywords` carries no uniqueness constraint, so the index keeps two
            // spellings of the same keyword from colliding.
            <Chip key={`${kw}-${String(i)}`}>{kw}</Chip>
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
 * A post-validator's per-rule tuning, flattened onto its chip.
 *
 * Dropping it misdescribes the rule one level down from the misdescription this
 * inspector exists to fix: `entropy` alone reads as the engine's defaults, and a
 * rule carrying a config is precisely one that does not use them. A short-secret
 * rule tuned to `minLength 8 / threshold 3.0` would otherwise render identically
 * to one running at 20 / 3.5.
 *
 * Only primitives are rendered. `config` is an open `Record<string, unknown>`, so
 * a value may be any JSON, and a nested object stringified onto a chip is noise
 * rather than information.
 */
function formatConfig(config: Record<string, unknown> | undefined): string {
  if (!config) return '';
  return Object.entries(config)
    .flatMap(([k, v]) =>
      typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
        ? [`${clamp(k, MAX_LABEL_CHARS)} ${clamp(String(v), MAX_LABEL_CHARS)}`]
        : [],
    )
    .slice(0, MAX_CONFIG_ENTRIES)
    .join(' · ');
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
        // Through CATEGORY_LABEL, because the rule's OWN category renders through
        // it a few lines up — a raw enum here prints "Code context" and
        // "category code_context" in the same dialog. The fallback keeps an
        // unknown member readable.
        ...(nearby.categories ?? []).map((c) => `category ${CATEGORY_LABEL[c] || c}`),
        ...(nearby.ruleIds ?? []).map((r) => `rule ${r}`),
        ...(nearby.labels ?? []).map((l) => `"${l}"`),
      ]
    : [];

  if (!rule.appliesTo && !rule.postValidators?.length && !nearby) return null;

  // `mt-4` on the root rather than on a wrapper at the call site: the parent is a
  // plain block container, so nothing spaces these siblings for them, and putting
  // the margin here keeps the null case rendering literally nothing instead of an
  // empty spaced div.
  return (
    <div className="mt-4 flex flex-col gap-3">
      {rule.appliesTo && (
        <Field label="Only in files">
          <div className="flex flex-wrap gap-1.5">
            {rule.appliesTo.extensions.map((ext, i) => (
              // `extensions` is `.min(1)` with no uniqueness constraint, so
              // [".py", ".py"] is valid input and a content-derived key collides
              // on it. Index-suffixed, like the examples and fixtures lists.
              <Chip key={`${ext}-${String(i)}`}>{ext}</Chip>
            ))}
          </div>
        </Field>
      )}

      {rule.postValidators && rule.postValidators.length > 0 && (
        <Field label="Must also pass">
          <div className="flex flex-wrap gap-1.5">
            {rule.postValidators.map((v, i) => {
              // PostValidatorRef is a bare name or { name, config } — the object
              // form exists for per-rule tuning, and both spell the same name. So
              // ['entropy', { name: 'entropy', config: … }] is valid input, and is
              // the natural way to say "the default one plus a tuned one": the key
              // carries the index for the same reason the two lists above do.
              const name = typeof v === 'string' ? v : v.name;
              const tuning = typeof v === 'string' ? '' : formatConfig(v.config);
              return (
                <Chip key={`${name}-${String(i)}`}>{tuning ? `${name} · ${tuning}` : name}</Chip>
              );
            })}
          </div>
        </Field>
      )}

      {nearby && (
        <Field label={`Needs corroboration within ${String(nearby.windowChars)} chars`}>
          {/* "Any of", because ONE criterion satisfies the gate. A bare separator
              between a category and a label reads equally as "needs both", which
              over-describes the gate — the mirror image of the under-description
              this section exists to fix. */}
          <div className="text-xs leading-snug text-text-2">
            {criteria.length > 1 ? `Any of: ${criteria.join(' · ')}` : criteria.join(' · ')}
          </div>
          {nearby.confidenceBoost !== undefined && (
            // Does not decide whether the rule fires, but it does move the
            // confidence stamped on every corroborated finding — one of the
            // numbers a reader of this panel is trying to account for.
            <div className="text-xs leading-snug text-text-3">
              Corroborated matches gain {String(nearby.confidenceBoost)} confidence
            </div>
          )}
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
 * pack shipped.
 */
function FixtureList({ fixtures }: { fixtures: readonly RuleFixture[] }) {
  const shown = fixtures.slice(0, MAX_SAMPLES);
  return (
    <div className="flex flex-col gap-2">
      {shown.map((f, i) => (
        <div
          key={`${clamp(f.label, MAX_LABEL_CHARS)}-${String(i)}`}
          className="flex flex-col gap-1"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={
                'inline-flex h-5 items-center rounded-full px-2 text-label font-semibold ' +
                // text-2 rather than text-3 on this fill: text-3 is calibrated
                // against --color-primary-tint, and --color-surface-3 is darker
                // than that, which puts the pair under the 4.5:1 body-text floor
                // in both themes. This is 11px, so the large-text exemption does
                // not apply either.
                (f.shouldMatch ? 'bg-ok-fill text-ok-ink' : 'bg-surface-3 text-text-2')
              }
            >
              {f.shouldMatch ? 'matches' : 'does not match'}
            </span>
            <span className="text-xs text-text-2">{clamp(f.label, MAX_LABEL_CHARS)}</span>
            {f.filePath !== undefined && (
              <span className="font-mono text-label text-text-3">
                {clamp(f.filePath, MAX_LABEL_CHARS)}
              </span>
            )}
          </div>
          <SampleText>{clamp(f.text, MAX_SAMPLE_CHARS)}</SampleText>
        </div>
      ))}
      <Elided hidden={fixtures.length - shown.length} />
    </div>
  );
}

/**
 * A rule's published test cases, carried WITH the id of the rule they describe.
 *
 * The pairing is the point. A fixture is an assertion about ONE rule ("this rule
 * must NOT match this"), so a set rendered under a different rule is not merely
 * stale — it is false. A host doing the obvious thing, fetching fixtures when a
 * rule is opened, otherwise shows the PREVIOUS rule's set for the duration of the
 * fetch, and permanently if two fetches resolve out of order. Carrying the id
 * makes that unrepresentable: the section renders only when the id matches the
 * rule on screen.
 *
 * `RuleFixture` itself is the @akasecurity/schema contract; this is the props
 * pairing around it, not a second declaration of it.
 */
export interface RuleFixtures {
  ruleId: string;
  cases: readonly RuleFixture[];
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
  fixtures?: RuleFixtures | undefined;
}) {
  // Read through a widened view. MATCHER_META is keyed on the matcher union, so a
  // MISSING entry is a compile error — but `rule` here is whatever a host passed,
  // and this component is exported from the package barrel for hosts to render on
  // their own. One that builds a rule from an API response without putting it
  // through the DetectionRule parse (a matcher kind whose client schema copy has
  // not caught up — exactly the drift a shared package sees) would otherwise take
  // the page down on `mm.icon`. Inside the modal its own `mm &&` gate covered
  // this; standing alone, this has to cover it itself.
  const table: Partial<Record<string, MatcherMeta>> = MATCHER_META;
  const mm = table[rule.matcher.type];
  if (!mm) return null;
  const MatcherIcon = mm.icon;

  const examples = rule.examples ?? [];
  // Only this rule's own fixtures — see RuleFixtures on why the id travels with
  // them.
  const cases = fixtures?.ruleId === rule.id ? fixtures.cases : [];

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
          where absence says "this rule does not use it". Each carries its own
          top margin: the parent is a plain block container, so nothing spaces
          these siblings for them. */}
      <GatingDetail rule={rule} />

      {examples.length > 0 && (
        <div className="mt-4">
          <Field label="Catches values like">
            <div className="flex flex-col gap-1.5">
              {examples.slice(0, MAX_SAMPLES).map((ex, i) => {
                const text = clamp(ex, MAX_SAMPLE_CHARS);
                return <SampleText key={`${text}-${String(i)}`}>{text}</SampleText>;
              })}
              <Elided hidden={examples.length - MAX_SAMPLES} />
            </div>
          </Field>
        </div>
      )}

      {cases.length > 0 && (
        <div className="mt-4">
          <Field label={`Test cases (${String(cases.length)})`}>
            <FixtureList fixtures={cases} />
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
  fixtures?: RuleFixtures | undefined;
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
