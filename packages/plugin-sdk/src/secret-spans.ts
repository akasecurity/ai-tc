import type { MatchResult } from '@akasecurity/detections';
import { scan } from '@akasecurity/detections';
import type { DetectionCategory, Rule } from '@akasecurity/schema';

import type { BoundedScanRequest, GuardedScanner, GuardedScanPartition } from './guarded-scan.ts';
import { createGuardedScanner } from './guarded-scan.ts';
import { ISOLATED_SCAN_BUDGET_MS, ISOLATED_START_BUDGET_MS } from './isolated-scan.ts';
import { dropShieldedFindings, shieldPointers } from './pointer-shield.ts';
import { bundledDetections } from './rule-packs.ts';
import { ruleProbeKey } from './rule-quarantine.ts';

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

/**
 * The secret-category rules to scan with: `installed` (the machine's effective
 * ruleset beyond the compiled-in packs) and every bundled secret rule. Rules
 * sharing an id are all kept unless their matchers are identical, so a rule
 * reusing a bundled id adds a matcher and never replaces the bundled one. A
 * regex rule that is not a bundled pattern is `unverified` and only ever runs
 * under the bounded scan.
 */
export function secretRulePartition(installed: readonly Rule[]): GuardedScanPartition {
  const bundled = bundledSecretRules();
  const bundledPatterns = new Set(bundled.map(ruleProbeKey));
  const byMatcher = new Map<string, Rule>();
  for (const rule of [...bundled, ...installed]) {
    const identity = `${rule.id}\n${JSON.stringify(rule.matcher)}`;
    if (rule.category === 'secret' && !byMatcher.has(identity)) byMatcher.set(identity, rule);
  }
  const verified: Rule[] = [];
  const unverified: Rule[] = [];
  for (const rule of byMatcher.values()) {
    if (rule.matcher.type === 'regex' && !bundledPatterns.has(ruleProbeKey(rule))) {
      unverified.push(rule);
    } else {
      verified.push(rule);
    }
  }
  return { verified, unverified };
}

export interface SecretSpanScanner {
  /** The secret spans in `text`. Throws when the scan cannot finish. */
  find(text: string): Promise<SecretSpan[]>;
  close(): Promise<void>;
}

const NO_VERDICT_STORE = { setRuleProbeVerdict: (): Promise<void> => Promise.resolve() };

/** The SDK's own isolated-scan allowances, so a contended machine is not read as a failed scan. */
export const DEFAULT_SECRET_SCAN_BOUND: BoundedScanRequest = {
  budgetMs: ISOLATED_SCAN_BUDGET_MS,
  startBudgetMs: ISOLATED_START_BUDGET_MS,
};

/**
 * A scanner over `partition`: in-process when every rule is verified, and
 * otherwise the whole ruleset in a worker under `bound`.
 */
export function createSecretSpanScanner(
  partition: GuardedScanPartition,
  bound: BoundedScanRequest = DEFAULT_SECRET_SCAN_BOUND,
): SecretSpanScanner {
  let guarded: GuardedScanner | undefined;
  return {
    async find(text) {
      const shielded = shieldPointers(text);
      let matches: MatchResult[];
      if (partition.unverified.length === 0) {
        matches = scan(shielded.text, partition.verified);
      } else {
        // A bounded scan never quarantines, so the verdict store is never written.
        guarded ??= createGuardedScanner(partition, NO_VERDICT_STORE);
        const outcome = await guarded.scanBounded(shielded.text, undefined, bound);
        if (outcome.status !== 'ok') throw new Error(`secret scan ${outcome.status}`);
        matches = outcome.findings;
      }
      return disjointSecretSpans(text, dropShieldedFindings(matches, shielded.spans));
    },
    async close() {
      await guarded?.close();
    },
  };
}
