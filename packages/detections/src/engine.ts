import type { Rule } from '@aka/schema';

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
const POST_VALIDATORS: Record<string, (value: string) => boolean> = {
  entropy: (value) => isHighEntropy(value),
  luhn: (value) => luhnCheck(value),
};

function passesPostValidators(rule: Rule, value: string): boolean {
  const validators = rule.postValidators;
  if (!validators || validators.length === 0) return true;
  for (const name of validators) {
    const validate = POST_VALIDATORS[name];
    if (validate && !validate(value)) return false;
  }
  return true;
}

export function registerPack(pack: RulePack): void {
  packs.set(pack.id, pack);
}

export function getLoadedRules(): Rule[] {
  return [...packs.values()].flatMap((p) => p.rules);
}

export function scan(text: string, rules?: Rule[]): MatchResult[] {
  const ruleset = rules ?? getLoadedRules();
  const findings: MatchResult[] = [];

  for (const rule of ruleset) {
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
      findings.push({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        span,
        rawMatch,
        confidence: 0.9,
      });
    }
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
