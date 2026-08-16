import type { PostValidatorName, Rule, Span } from '@akasecurity/schema';

import { escapeRegExp } from './escape-regexp.ts';
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

// Pass 2 helper: is `candidate` corroborated by another signal within its
// rule's proximity window? Looks for (a) another match in one of `categories`
// FROM A DIFFERENT RULE, (b) another match whose ruleId is in `ruleIds`, or
// (c) a `labels` keyword present (on word boundaries) in the surrounding text
// window. Pure and non-throwing — a malformed `requiresNearby` simply fails to
// corroborate.
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
      if (re?.test(haystack)) return true;
    }
  }

  return false;
}

// Where the scanned text came from, when known. The worktree scanner supplies
// the file path; live prompt/response hooks have none.
export interface ScanContext {
  filePath?: string | undefined;
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

  // Pass 1: run primitive matchers for ALL applicable rules → candidate matches.
  const candidates: Candidate[] = [];
  for (const rule of ruleset) {
    if (!ruleApplies(rule, extension)) continue;
    const spans = MATCHERS[rule.matcher.type](text, rule);

    for (const span of spans) {
      const rawMatch = text.slice(span.start, span.end);
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

  // Pass 2: apply proximity gating. Candidates whose rule has no
  // `requiresNearby` are kept verbatim (identical to the pre-gate behavior).
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
