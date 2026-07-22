import { checkRuleTiming } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';

import type { DataGateway } from './data-gateway.ts';
import { contentHashOf } from './events.ts';

// Overall wall-clock budget for one filtering pass across all not-yet-cached
// rules. Protects the hook's timeout against a pack containing many
// never-before-seen slow rules at once: once the cap is hit, every remaining
// unchecked rule is quarantined without measurement rather than continuing to
// spend time on it.
const PASS_BUDGET_MS = 2_000;

// The subset of DataGateway this module actually needs — narrower than the
// full port so callers (and tests) don't have to construct a complete fake
// gateway just to exercise the filter.
export type RuleProbeGateway = Pick<DataGateway, 'getRuleProbeVerdict' | 'setRuleProbeVerdict'>;

/**
 * The cache key for a regex rule's timing verdict: a content hash of its
 * pattern+flags only — not the whole rule — so a metadata-only change
 * (severity, category, name) doesn't invalidate a still-valid verdict, and an
 * unrelated rule with an identical pattern reuses the same verdict. Returns
 * undefined for a non-regex rule (keyword/validator rules are never checked).
 */
export function ruleProbeKey(rule: Rule): string | undefined {
  if (rule.matcher.type !== 'regex') return undefined;
  return contentHashOf(`${rule.matcher.pattern} ${rule.matcher.flags}`);
}

function warnQuarantined(rule: Rule, worstMs: number | undefined): void {
  const timing = worstMs === undefined ? 'not verified in time' : `${worstMs.toFixed(1)}ms`;
  process.stderr.write(
    `[aka] quarantined rule "${rule.id}": regex matcher exceeded the ReDoS timing budget ` +
      `(${timing}); excluded from this scan.\n`,
  );
}

/**
 * Filters `rules` down to those whose regex matcher is verified safe against
 * the adversarial probe battery — the runtime gate for rules that arrive from
 * a pulled or custom pack (bundled rules are gated by the CI battery instead
 * and should never be passed here). A regex rule's verdict is measured at
 * most once, ever, and cached via `gateway`; a rule that exceeds the timing
 * budget is excluded from the result and logged to stderr, never silently
 * dropped. Non-regex rules (keyword, validator) pass through unchecked.
 */
export async function filterUnsafeRules(
  rules: Rule[],
  gateway: RuleProbeGateway,
  opts?: { passBudgetMs?: number },
): Promise<Rule[]> {
  const passBudgetMs = opts?.passBudgetMs ?? PASS_BUDGET_MS;
  const passStart = performance.now();
  const safe: Rule[] = [];

  for (const rule of rules) {
    const key = ruleProbeKey(rule);
    if (key === undefined) {
      safe.push(rule);
      continue;
    }

    const cached = await gateway.getRuleProbeVerdict(key);
    if (cached) {
      if (cached.verdict === 'safe') safe.push(rule);
      else warnQuarantined(rule, cached.worstProbeMs);
      continue;
    }

    if (performance.now() - passStart >= passBudgetMs) {
      await gateway.setRuleProbeVerdict(key, 'quarantined', passBudgetMs);
      warnQuarantined(rule, undefined);
      continue;
    }

    const { safe: isSafe, worstMs } = checkRuleTiming(rule);
    await gateway.setRuleProbeVerdict(key, isSafe ? 'safe' : 'quarantined', worstMs);
    if (isSafe) safe.push(rule);
    else warnQuarantined(rule, worstMs);
  }

  return safe;
}
