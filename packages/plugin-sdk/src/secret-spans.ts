import type { MatchResult } from '@akasecurity/detections';
import { scan } from '@akasecurity/detections';
import type { DetectionCategory, Rule } from '@akasecurity/schema';

import { dropShieldedFindings, shieldPointers } from './pointer-shield.ts';
import { bundledDetections } from './rule-packs.ts';

/**
 * One secret span in a text. `value` is the span's text when a single match
 * covers the whole span, and undefined when overlapping matches leave no one
 * value to name.
 */
export interface SecretSpan {
  start: number;
  end: number;
  ruleId: string;
  category: DetectionCategory;
  value: string | undefined;
}

let secretRulesCache: Rule[] | undefined;

// The bundled secret-category rules only: the same set in every process, and
// each one CI-timed, so a scan here runs in-process without a timing gate.
function bundledSecretRules(): Rule[] {
  secretRulesCache ??= bundledDetections()
    .flatMap((pack) => pack.rules)
    .filter((rule) => rule.category === 'secret');
  return secretRulesCache;
}

/** Overlapping matches merged into disjoint spans, in text order. */
export function disjointSecretSpans(text: string, matches: readonly MatchResult[]): SecretSpan[] {
  const sorted = matches
    .filter((m) => m.span.start >= 0 && m.span.end <= text.length && m.span.start < m.span.end)
    .sort((a, b) => a.span.start - b.span.start || b.span.end - a.span.end);
  const groups: { start: number; end: number; first: MatchResult; members: MatchResult[] }[] = [];
  for (const match of sorted) {
    const last = groups.at(-1);
    if (last !== undefined && match.span.start < last.end) {
      last.end = Math.max(last.end, match.span.end);
      last.members.push(match);
      continue;
    }
    groups.push({ start: match.span.start, end: match.span.end, first: match, members: [match] });
  }
  return groups.map(({ start, end, first, members }) => {
    const covering = members.find((m) => m.span.start === start && m.span.end === end);
    const named = covering ?? first;
    return {
      start,
      end,
      ruleId: named.ruleId,
      category: named.category,
      value: covering === undefined ? undefined : text.slice(start, end),
    };
  });
}

/**
 * The secret-category spans the bundled rules find in `text`, disjoint and in
 * text order. Vault pointers and sighting tokens are never scanned. Throws when
 * the scan fails.
 */
export function findSecretSpans(text: string): SecretSpan[] {
  const shielded = shieldPointers(text);
  const matches = dropShieldedFindings(scan(shielded.text, bundledSecretRules()), shielded.spans);
  return disjointSecretSpans(text, matches);
}
