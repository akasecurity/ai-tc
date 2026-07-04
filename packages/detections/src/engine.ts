import type { Rule } from '@akasecurity/schema';

import { KeywordMatcher } from './matchers/keyword.ts';
import { RegexMatcher } from './matchers/regex.ts';
import type { MatchResult, RulePack } from './types.ts';
import { isHighEntropy } from './validators/entropy.ts';
import { luhnCheck } from './validators/luhn.ts';

const keywordMatcher = new KeywordMatcher();
const regexMatcher = new RegexMatcher();

const packs = new Map<string, RulePack>();

// Post-validators run against each candidate match (the captured span) and must
// all pass for the match to become a finding. Unknown validator names are
// ignored so rules can reference validators a given engine build doesn't ship.
// A validator may take per-rule config (the object form of PostValidatorRef).
const POST_VALIDATORS: Record<
  string,
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
    const validate = POST_VALIDATORS[name];
    if (validate && !validate(value, config)) return false;
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
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

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
    for (const label of labels) {
      const trimmed = label.trim();
      if (trimmed.length === 0) continue;
      // Boundaries = non-alphanumeric neighbours; robust for labels containing
      // punctuation or spaces (e.g. "p.o. box") where \b is unreliable.
      const re = new RegExp(`(?<![A-Za-z0-9])${escapeRegExp(trimmed)}(?![A-Za-z0-9])`, 'i');
      if (re.test(haystack)) return true;
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
    let spans;
    if (rule.matcher.type === 'keyword') {
      spans = keywordMatcher.match(text, rule);
    } else if (rule.matcher.type === 'regex') {
      spans = regexMatcher.match(text, rule);
    } else {
      continue;
    }

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

export function redact(text: string, findings: MatchResult[]): string {
  if (findings.length === 0) return text;

  // Sort spans by start descending so slice replacements don't shift indices
  const sorted = [...findings].sort((a, b) => b.span.start - a.span.start);
  let result = text;
  for (const f of sorted) {
    const placeholder = `[REDACTED:${f.category.toUpperCase()}]`;
    result = result.slice(0, f.span.start) + placeholder + result.slice(f.span.end);
  }
  return result;
}
