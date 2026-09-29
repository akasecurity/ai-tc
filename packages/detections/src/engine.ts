import type { PostValidatorName, Rule, Span } from '@akasecurity/schema';

import { escapeRegExp } from './escape-regexp.ts';
import type { FormatCharNormalization } from './format-chars.ts';
import { mapSpanToOriginal, normalizeFormatChars } from './format-chars.ts';
import { KeywordMatcher } from './matchers/keyword.ts';
import { RegexMatcher } from './matchers/regex.ts';
import { memoizedRegExpList } from './regex-cache.ts';
import type { MatchResult, RulePack } from './types.ts';
import { isHighEntropy } from './validators/entropy.ts';
import { luhnCheck } from './validators/luhn.ts';

const keywordMatcher = new KeywordMatcher();
const regexMatcher = new RegexMatcher();

// A matcher PRODUCES the candidate spans a rule then filters. Keyed on the
// schema's own matcher union for the reason POST_VALIDATORS is keyed on
// PostValidatorName: while this was an if/else chain ending in `continue`, an
// arm the schema accepted and this file did not handle fell straight through and
// contributed nothing, so the rule parsed, loaded and matched NOTHING — a dead
// rule that reads from the outside exactly like a pattern finding no secrets.
// An arm added to the union without an entry here now fails to compile.
const MATCHERS: Record<Rule['matcher']['type'], (text: string, rule: Rule) => Span[]> = {
  keyword: (text, rule) => keywordMatcher.match(text, rule),
  regex: (text, rule) => regexMatcher.match(text, rule),
};

const packs = new Map<string, RulePack>();

// Post-validators run against each candidate match (the captured span) and must
// all pass for the match to become a finding. A validator may take per-rule
// config (the object form of PostValidatorRef).
//
// Keyed on the schema's PostValidatorName rather than on `string`, which is what
// binds the two together: a name the schema accepts and this table does not
// implement fails to compile, and so does an entry here the schema would reject.
// While the key was `string` the pair could drift in either direction in
// silence, and drift in the schema's direction meant a rule that referenced a
// nonexistent validator parsed, loaded and fired with its false-positive guard
// absent — the guard the author believed they had added doing nothing at all.
const POST_VALIDATORS: Record<
  PostValidatorName,
  (value: string, config?: Record<string, unknown>) => boolean
> = {
  entropy: (value, config) =>
    isHighEntropy(value, numberOption(config, 'threshold'), numberOption(config, 'minLength')),
  luhn: (value) => luhnCheck(value),
};

// Pull a numeric option out of untyped validator config; undefined (falling
// back to the validator's own default) for anything missing or non-numeric.
function numberOption(
  config: Record<string, unknown> | undefined,
  key: string,
): number | undefined {
  const value = config?.[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function passesPostValidators(rule: Rule, value: string): boolean {
  const validators = rule.postValidators;
  if (!validators || validators.length === 0) return true;
  for (const ref of validators) {
    const name = typeof ref === 'string' ? ref : ref.name;
    const config = typeof ref === 'string' ? undefined : ref.config;
    // Unconditional: `name` is a PostValidatorName, so the table has an entry
    // for it by type. This used to be guarded by `validate && …`, and that
    // guard WAS the defect — it turned a name the table did not know into a
    // silently skipped check rather than an error, which is how a rule shipped
    // with its false-positive guard absent. The schema refuses such a name now,
    // so there is no longer a missing entry to fall through.
    if (!POST_VALIDATORS[name](value, config)) return false;
  }
  return true;
}

export function registerPack(pack: RulePack): void {
  packs.set(pack.id, pack);
}

export function getLoadedRules(): Rule[] {
  return [...packs.values()].flatMap((p) => p.rules);
}

// A candidate match plus the rule that produced it, retained between the two
// passes of scan() so the proximity gate can inspect each candidate's rule.
interface Candidate {
  rule: Rule;
  match: MatchResult;
}

// Escape regex metacharacters so a label is matched literally.

// Gating helper: is `candidate` corroborated by another signal within its
// rule's proximity window? Looks for (a) another match in one of `categories`
// FROM A DIFFERENT RULE, (b) another match whose ruleId is in `ruleIds`, or
// (c) a `labels` keyword present (on word boundaries) in the surrounding text
// window. Pure and non-throwing — a malformed `requiresNearby` simply fails to
// corroborate.
//
// `candidates` is the POOLED list scan() gates in one pass — see scan() — so
// on the slow path it holds candidates from BOTH the original-text and the
// normalized-text matcher runs, every span already expressed in ORIGINAL-text
// coordinates. (a)/(b) need no special handling for that: they only compare
// spans and rule identity, which already means the same thing regardless of
// which pass produced a candidate.
function isCorroborated(candidate: Candidate, candidates: Candidate[], text: string): boolean {
  const req = candidate.rule.requiresNearby;
  if (!req) return true;

  // windowChars has a schema default (160), so it is always present post-parse.
  // It is a radius applied on both sides of the span, hence "half window".
  const halfWindow = req.windowChars;
  const { start, end } = candidate.match.span;
  const winStart = start - halfWindow;
  const winEnd = end + halfWindow;

  // (a)/(b): another candidate match whose span falls inside the window and
  // whose category/ruleId matches. A candidate never corroborates itself.
  const categories = req.categories;
  const ruleIds = req.ruleIds;
  if (categories?.length || ruleIds?.length) {
    for (const other of candidates) {
      if (other === candidate) continue;
      const os = other.match.span;
      // Overlap of [os.start, os.end] with [winStart, winEnd].
      if (os.end < winStart || os.start > winEnd) continue;
      // Category corroboration must come from a DIFFERENT rule — otherwise two
      // matches of the same rule (e.g. two nearby dates) would corroborate each
      // other, defeating independent corroboration. `ruleIds` is an explicit
      // opt-in, so it is intentionally not subject to this restriction.
      if (
        other.match.ruleId !== candidate.match.ruleId &&
        categories?.includes(other.match.category)
      ) {
        return true;
      }
      if (ruleIds?.includes(other.match.ruleId)) return true;
    }
  }

  // (c): a label keyword present in the surrounding text window. Matched on word
  // boundaries (not a raw substring) so e.g. the label "state" does not
  // corroborate inside "estate" — labels behave like standalone keywords/phrases.
  const labels = req.labels;
  if (labels && labels.length > 0) {
    const haystack = text.slice(Math.max(0, winStart), winEnd);
    // A label's own boundary can be satisfied by a format character that
    // survives in only ONE of the two texts scan() matches against — the same
    // shape of regression the primitive-match fix (see scan()) exists for,
    // just for this lookaround instead of `\b`. Searching only `haystack`
    // (original text) misses a label that was split apart and only reads as
    // one word once normalized (e.g. a label inside a secret whose OWN
    // characters carry the format character); searching only a normalized
    // form misses a label whose boundary depends on a format character still
    // present in the original text. Re-normalizing this window on demand
    // — bounded by `windowChars`, so cheap — rather than threading a second
    // haystack through every caller covers both without scan() needing to
    // know which shape it is looking at. It is a no-op whenever the window
    // itself has no format character, which is the common case even on the
    // slow path: most of a scanned text is not the one stripped region.
    const haystackNormalized = normalizeFormatChars(haystack)?.normalized;
    // Boundaries = non-alphanumeric neighbours; robust for labels containing
    // punctuation or spaces (e.g. "p.o. box") where \b is unreliable.
    //
    // This was the densest construction site in the package: the loop runs per
    // label per gated candidate, so a rule whose primitive matcher fires often
    // and corroborates rarely (a 5-digit ZIP against a column of numbers)
    // reached it once per candidate per label — and built the pattern string as
    // well as the object each time. Compiling the set once per `requiresNearby`
    // takes both off that product.
    for (const re of memoizedRegExpList('label', req, () =>
      labels.map((label) => {
        const trimmed = label.trim();
        return trimmed.length === 0
          ? undefined
          : new RegExp(`(?<![A-Za-z0-9])${escapeRegExp(trimmed)}(?![A-Za-z0-9])`, 'i');
      }),
    )) {
      if (!re) continue;
      if (re.test(haystack)) return true;
      if (haystackNormalized !== undefined && re.test(haystackNormalized)) return true;
    }
  }

  return false;
}

// Where the scanned text came from, when known. The worktree scanner supplies
// the file path; live prompt/response hooks have none.
export interface ScanContext {
  filePath?: string | undefined;
}

// Pass 1: runs the primitive matchers for every applicable rule against
// `matchText` and applies post-validators, returning candidates whose
// span/rawMatch are in `matchText`'s OWN index space — no mapping. Called
// once on the fast path (against `text`) and twice on the slow path (against
// `text` and separately against the normalized text — see scan()).
function buildCandidates(
  matchText: string,
  ruleset: Rule[],
  extension: string | undefined,
): Candidate[] {
  const candidates: Candidate[] = [];
  for (const rule of ruleset) {
    if (!ruleApplies(rule, extension)) continue;
    const spans = MATCHERS[rule.matcher.type](matchText, rule);

    for (const span of spans) {
      // Post-validators (entropy, Luhn) run against the CLEAN value here —
      // scoring a value with an invisible character still mixed in would
      // misjudge the secret's actual entropy/checksum.
      const rawMatch = matchText.slice(span.start, span.end);
      if (!passesPostValidators(rule, rawMatch)) continue;
      candidates.push({
        rule,
        match: {
          ruleId: rule.id,
          category: rule.category,
          severity: rule.severity,
          span,
          rawMatch,
          confidence: 0.9,
        },
      });
    }
  }
  return candidates;
}

// Maps a normalized-text candidate's span (and re-slices its rawMatch) back
// onto `text`, the original this normalization was built from.
//
// DECISION, recorded rather than left implicit: `rawMatch` stays the exact
// original-text slice, format characters included when the match genuinely
// has one inside it. That is what redaction and vault-restore need — the
// same secret has to come back byte-for-byte — so it is the PRIMARY reading
// of a finding's value. It also means two occurrences of the same secret,
// one clean and one with a format character planted inside it, produce
// `rawMatch` values that differ, and a consumer that fingerprints `rawMatch`
// directly (`packages/plugin-sdk/src/runtime.ts`'s exception matching,
// `packages/local-ops/src/fs-scan.ts`'s vault fingerprint) will not treat
// them as the same secret. A consumer that wants that identity-invariant
// reading instead should fingerprint the format-character-stripped value —
// `normalizeFormatChars(finding.rawMatch)?.normalized ?? finding.rawMatch`,
// exported from this package for exactly that — rather than `rawMatch`
// itself; this package does not make that substitution unasked, because
// doing so at the finding-production boundary would be the wrong tradeoff
// for the consumer that DOES need the exact text (redaction/vault-restore),
// and there is no single `rawMatch` that is correct for both uses at once.
function mapCandidateToOriginal(
  candidate: Candidate,
  normalization: FormatCharNormalization,
  text: string,
): Candidate {
  const span = mapSpanToOriginal(candidate.match.span, normalization);
  return {
    rule: candidate.rule,
    match: { ...candidate.match, span, rawMatch: text.slice(span.start, span.end) },
  };
}

// Pass 2: proximity gating over a candidate list whose spans are ALL already
// expressed in the same coordinate space (`text`'s). Candidates whose rule
// has no `requiresNearby` are kept verbatim (identical to the pre-gate
// behavior).
function gate(candidates: Candidate[], text: string): MatchResult[] {
  const findings: MatchResult[] = [];
  for (const candidate of candidates) {
    const req = candidate.rule.requiresNearby;
    if (!req) {
      findings.push(candidate.match);
      continue;
    }
    if (!isCorroborated(candidate, candidates, text)) continue;
    const boost = req.confidenceBoost;
    // Cap below 1.0 — a heuristic, corroboration-based match should never read as
    // mathematically "certain".
    findings.push(
      boost
        ? { ...candidate.match, confidence: Math.min(0.99, candidate.match.confidence + boost) }
        : candidate.match,
    );
  }
  return findings;
}

// One rule's worth of the sweep `mergeOverlappingSameRule` runs below: an
// open, growing region plus the fields a closed finding needs that do not
// come from a span (same for every member, since the group shares a rule).
interface OpenRegion {
  start: number;
  end: number;
  confidence: number;
  ruleId: string;
  category: MatchResult['category'];
  severity: MatchResult['severity'];
}

function closeRegion(open: OpenRegion, text: string): MatchResult {
  const span = { start: open.start, end: open.end };
  return {
    ruleId: open.ruleId,
    category: open.category,
    severity: open.severity,
    span,
    rawMatch: text.slice(span.start, span.end),
    confidence: open.confidence,
  };
}

/**
 * Collapses every group of overlapping SAME-rule findings into one, keeping
 * the UNION of their spans (re-sliced from `text`) and the highest of their
 * confidences. Only runs on the slow path — see scan() — where the original-
 * text and normalized-text passes can each independently find the same
 * secret occurrence, sometimes at a slightly different span.
 *
 * Bucket by ruleId, sort each bucket by `span.start`, then sweep once,
 * extending an OPEN region's `end` (never re-comparing it against every
 * finding merged so far — the quadratic shape a pairwise "check candidate
 * against every finding kept" merge had): O(n log n) instead of O(n²), and
 * TRANSITIVE, because the open region keeps growing as long as the next
 * sorted finding starts before its current (possibly already-extended) end
 * — so a third finding that only overlaps the WIDENED region, not either of
 * the first two individually, still gets folded in rather than left as a
 * second overlapping finding of the same rule.
 *
 * Deliberately keyed on ruleId + span overlap, not on which pass produced a
 * finding: the keyword matcher can already produce overlapping spans for the
 * SAME rule within a SINGLE pass (two keywords where one is a substring of
 * the other), and those are exactly as much "the same finding" as a genuine
 * cross-pass duplicate. This does not run on the fast path, so a keyword
 * rule with that shape still returns two findings there, unchanged from
 * before this file normalized anything — narrower than "collapses every
 * same-rule overlap this package could ever produce" on purpose, to keep the
 * ordinary (no format character) path's behavior exactly as it was.
 *
 * Exported for its own unit test only; not part of the package's public API.
 */
export function mergeOverlappingSameRule(findings: MatchResult[], text: string): MatchResult[] {
  if (findings.length === 0) return findings;

  const groups = new Map<string, MatchResult[]>();
  const ruleOrder: string[] = [];
  for (const finding of findings) {
    const group = groups.get(finding.ruleId);
    if (group) {
      group.push(finding);
    } else {
      groups.set(finding.ruleId, [finding]);
      ruleOrder.push(finding.ruleId);
    }
  }

  const merged: MatchResult[] = [];
  for (const ruleId of ruleOrder) {
    const group = groups.get(ruleId) ?? [];
    const sorted = [...group].sort(
      (a, b) => a.span.start - b.span.start || a.span.end - b.span.end,
    );
    let open: OpenRegion | undefined;
    for (const finding of sorted) {
      if (open && finding.span.start < open.end) {
        open.end = Math.max(open.end, finding.span.end);
        open.confidence = Math.max(open.confidence, finding.confidence);
        continue;
      }
      if (open) merged.push(closeRegion(open, text));
      open = {
        start: finding.span.start,
        end: finding.span.end,
        confidence: finding.confidence,
        ruleId: finding.ruleId,
        category: finding.category,
        severity: finding.severity,
      };
    }
    if (open) merged.push(closeRegion(open, text));
  }
  return merged;
}

// Pure string-ops extension extraction (this package takes no Node-API deps, so
// no node:path). Mirrors path.extname semantics: dotfiles (.eslintrc) and
// extension-less names (Makefile) yield undefined. Lowercased for comparison.
function extensionOf(filePath: string): string | undefined {
  const base = filePath.slice(Math.max(filePath.lastIndexOf('/'), filePath.lastIndexOf('\\')) + 1);
  const dot = base.lastIndexOf('.');
  return dot > 0 ? base.slice(dot).toLowerCase() : undefined;
}

// Should this rule run against text from this context? An `appliesTo`-scoped
// rule is skipped only when the context provides a NON-matching extension.
// With no file context (or no recognizable extension) the rule still runs:
// pasted code in a prompt has no knowable language, and missing a real leak
// costs more than a cross-language false positive there.
function ruleApplies(rule: Rule, extension: string | undefined): boolean {
  if (!rule.appliesTo || extension === undefined) return true;
  return rule.appliesTo.extensions.some((e) => e.toLowerCase() === extension);
}

export function scan(text: string, rules?: Rule[], context?: ScanContext): MatchResult[] {
  const ruleset = rules ?? getLoadedRules();
  const extension = context?.filePath ? extensionOf(context.filePath) : undefined;

  // An invisible Unicode format character (ZERO WIDTH SPACE, a bidi control,
  // …) planted INSIDE a secret defeats every regex/keyword rule
  // character-for-character while leaving the secret itself unchanged, since
  // nothing upstream of this package normalizes text before matching — so
  // matching against a normalized (stripped) copy is necessary. But `\b` (and
  // this file's own `(?<![A-Za-z0-9])…(?![A-Za-z0-9])` label boundary) treats
  // any non-word character, format characters included, as a boundary — so a
  // rule can ALSO rely on a format character sitting *next to* a secret to
  // satisfy a boundary the surrounding text alone would not (a word char
  // then a format char then "AKIA…" matches `\bAKIA…` on the original text;
  // stripped to a word char directly against "AKIA…", the boundary is gone
  // and the same rule misses). Normalizing is therefore necessary for one
  // shape of secret and can regress another, so on the slow path this builds
  // candidates from BOTH texts, maps the normalized-text ones back onto
  // `text`'s own coordinates, and gates the POOLED set in one pass — rather
  // than gating each pass on its own and merging findings afterward. Gating
  // separately would miss a `requiresNearby` candidate whose keyword only
  // exists in one text and whose corroborating label only exists in the
  // other (a candidate present in only one pass can never see a
  // corroborator that only the OTHER pass produced); pooling first means
  // every candidate, from either pass, sees every other candidate.
  // `buildCandidates` on ordinary input (no format character present) is
  // called exactly once, against `text` itself, and its output goes straight
  // to `gate` with nothing pooled or merged: the one-regex-test fast path in
  // `normalizeFormatChars` returns `undefined` and no normalized copy, no
  // segment table, and no second matcher pass is ever built or run.
  //
  // The slow path DOES run every applicable rule twice — once per text — and
  // that cost is not limited to a text an attacker crafted: a UTF-8 BOM at
  // the start of a Windows-authored file, a ZWJ inside a combined emoji, a
  // ZWNJ inside an ordinary Persian or Indic word, and a soft hyphen from an
  // HTML export all carry a \p{Cf} character with no secret anywhere nearby.
  // Windowing the second pass to only the regions around stripped positions
  // was considered instead of a full second pass, to avoid paying for that
  // doubling on ordinary text — but a window has to stay correct for every
  // matcher shape (a keyword whose match starts before the window and ends
  // inside it, a `requiresNearby` label window that itself needs to extend
  // past the window, an entropy/Luhn validator scoring a value truncated by
  // the window boundary), which is a real redesign with its own bug surface,
  // not a narrow guard. Measured instead: `bench/benign-format-chars.bench.ts`
  // runs the bundled ruleset against exactly those four benign shapes, and
  // the slow path's worst case there (100 KB of HTML text with a soft hyphen
  // roughly every 8 characters) took ~13ms against a ~7ms extrapolated fast-
  // path baseline for the same size — bounded, linear in text size, and over
  // 700x inside the hook's 10s timeout even at that density. That margin,
  // not the ruleset running twice, is what the windowing would have bought
  // back, so it was not built.
  //
  // Invariant: for any input, the set of ruleIds this returns findings for is
  // a SUPERSET of what a build with no format-character handling at all
  // would return — never a subset. Pinned by the "the original-text pass
  // still finds a match whose boundary is a format character" suite in
  // test/security/unicode.test.ts.
  const normalization = normalizeFormatChars(text);
  const originalCandidates = buildCandidates(text, ruleset, extension);
  if (!normalization) return gate(originalCandidates, text);

  const normalizedCandidates = buildCandidates(normalization.normalized, ruleset, extension).map(
    (candidate) => mapCandidateToOriginal(candidate, normalization, text),
  );
  const findings = gate([...originalCandidates, ...normalizedCandidates], text);
  // The two passes can each independently find the same secret occurrence —
  // sometimes at a slightly different span, since a pattern with no upper
  // bound can match further in one text than the other — so the pooled,
  // gated set still needs collapsing before it is returned. See
  // mergeOverlappingSameRule for why this differs from a pairwise "merge into
  // the first thing it overlaps" fold (that shape was quadratic in the
  // number of findings and could leave two overlapping findings of the same
  // rule behind when a third one only overlapped the widened result of
  // merging the first two).
  return mergeOverlappingSameRule(findings, text);
}

// Severity precedence for naming a merged region's placeholder — the most
// severe finding inside the region wins.
const SEVERITY_RANK: Record<MatchResult['severity'], number> = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0,
};

// A contiguous stretch of text covered by one or more overlapping findings,
// replaced by a single placeholder.
interface RedactRegion {
  start: number;
  end: number;
  category: MatchResult['category'];
  rank: number;
}

export function redact(text: string, findings: MatchResult[]): string {
  if (findings.length === 0) return text;

  // Findings may overlap (cross-rule double-fires, duplicate keyword spans).
  // Replacing overlapping spans independently splices with indices from the
  // original string and corrupts the output, so fold them into disjoint
  // regions first: sort ascending, extend the open region while spans overlap.
  // Adjacent-but-disjoint spans stay separate regions.
  const sorted = [...findings].sort(
    (a, b) => a.span.start - b.span.start || a.span.end - b.span.end,
  );
  const regions: RedactRegion[] = [];
  for (const f of sorted) {
    const rank = SEVERITY_RANK[f.severity];
    const open = regions[regions.length - 1];
    if (open && f.span.start < open.end) {
      open.end = Math.max(open.end, f.span.end);
      if (rank > open.rank) {
        open.rank = rank;
        open.category = f.category;
      }
    } else {
      regions.push({ start: f.span.start, end: f.span.end, category: f.category, rank });
    }
  }

  // Replace back-to-front so earlier region indices stay valid.
  let result = text;
  for (const r of [...regions].reverse()) {
    const placeholder = `[REDACTED:${r.category.toUpperCase()}]`;
    result = result.slice(0, r.start) + placeholder + result.slice(r.end);
  }
  return result;
}
