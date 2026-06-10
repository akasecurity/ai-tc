import type { Rule } from '@aka/schema';

import { KeywordMatcher } from './matchers/keyword.ts';
import { RegexMatcher } from './matchers/regex.ts';
import type { MatchResult, RulePack } from './types.ts';

const keywordMatcher = new KeywordMatcher();
const regexMatcher = new RegexMatcher();

const packs = new Map<string, RulePack>();

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
      findings.push({
        ruleId: rule.id,
        category: rule.category,
        severity: rule.severity,
        span,
        rawMatch: text.slice(span.start, span.end),
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
