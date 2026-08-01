import { checkRuleTiming } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';

import type { DataGateway } from './data-gateway.ts';
import { contentHashOf } from './events.ts';
import type { IsolatedProbeOutcome } from './isolated-scan.ts';

// Overall wall-clock budget for one filtering pass across all not-yet-cached
// rules. Protects the hook's timeout against a pack containing many
// never-before-seen slow rules at once: once the cap is hit, every remaining
// unchecked rule is quarantined without measurement rather than continuing to
// spend time on it.
const PASS_BUDGET_MS = 2_000;

// What a user runs to undo a quarantine. Named in every warning this module
// writes, because the verdict is cached forever and the stderr line is the only
// place the machine ever mentions it.
const UNQUARANTINE_HINT = 'clear it with `aka detections unquarantine`';

// The subset of DataGateway this module actually needs — narrower than the
// full port so callers (and tests) don't have to construct a complete fake
// gateway just to exercise the filter.
export type RuleProbeGateway = Pick<DataGateway, 'getRuleProbeVerdict' | 'setRuleProbeVerdict'>;

/**
 * Measures one rule somewhere it can be killed. The battery decides whether a
 * pattern is safe by driving it into backtracking, so the measurement is itself
 * an unbounded run of an untrusted pattern — see `isolated-scan.ts`.
 */
export interface RuleProber {
  probe(rule: Rule): Promise<IsolatedProbeOutcome>;
}

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

function warn(rule: Rule, detail: string, recoverable: boolean): void {
  const hint = recoverable ? ` (${UNQUARANTINE_HINT})` : '';
  process.stderr.write(`[aka] quarantined rule "${rule.id}": ${detail}${hint}\n`);
}

function warnQuarantined(rule: Rule, worstMs: number | undefined, cached: boolean): void {
  const timing = worstMs === undefined ? 'not verified in time' : `${worstMs.toFixed(1)}ms`;
  warn(
    rule,
    `regex matcher exceeded the ReDoS timing budget (${timing}); excluded from this scan.`,
    cached,
  );
}

/**
 * Records a rule as quarantined outside the probe battery — for a rule the
 * battery cleared that then blew the hard runtime bound on real text
 * (`guarded-scan.ts`). The verdict shares the battery's cache, so the next hook
 * process drops the rule before it ever reaches a scan.
 *
 * Best-effort on the write, loud on stderr either way: this runs on a recovery
 * path, and a store error here must not cost the caller its scan on top of the
 * hang it just absorbed. A non-regex rule has no probe key and so cannot be
 * cached; it is still reported, because the caller saw it hang.
 */
export async function quarantineRule(
  gateway: Pick<RuleProbeGateway, 'setRuleProbeVerdict'>,
  rule: Rule,
  worstMs: number,
  detail: string,
): Promise<void> {
  const key = ruleProbeKey(rule);
  let cached = false;
  if (key !== undefined) {
    try {
      await gateway.setRuleProbeVerdict(key, 'quarantined', worstMs);
      cached = true;
    } catch {
      // The verdict did not stick, so the next process re-measures this rule
      // and may hang on it once more. Better than losing this scan too.
    }
  }
  warn(rule, detail, cached);
}

/**
 * Filters `rules` down to those whose regex matcher is verified safe against
 * the adversarial probe battery — the runtime gate for rules that arrive from
 * a pulled or custom pack (bundled rules are gated by the CI battery instead
 * and should never be passed here). A regex rule's verdict is measured at
 * most once, ever, and cached via `gateway`; a rule that exceeds the timing
 * budget is excluded from the result and logged to stderr, never silently
 * dropped. Non-regex rules (keyword, validator) pass through unchecked.
 *
 * `opts.prober` is where the measurement runs. The battery works by making the
 * rule's own pattern backtrack, so measuring a pattern that never returns hangs
 * whatever thread does it — the plugin runtime always supplies a prober that
 * can be killed. Without one the measurement falls back to this thread, which
 * has no upper bound; that path is for callers that already control the rules
 * they pass (tests, tooling), never for a pulled pack.
 */
export async function filterUnsafeRules(
  rules: Rule[],
  gateway: RuleProbeGateway,
  // `| undefined` explicitly: under exactOptionalPropertyTypes a caller
  // forwarding its own optional seam would otherwise have to strip the key.
  opts?: { passBudgetMs?: number | undefined; prober?: RuleProber | undefined },
): Promise<Rule[]> {
  const passBudgetMs = opts?.passBudgetMs ?? PASS_BUDGET_MS;
  const prober = opts?.prober;
  const passStart = performance.now();
  const safe: Rule[] = [];

  for (const rule of rules) {
    const key = ruleProbeKey(rule);
    if (key === undefined) {
      safe.push(rule);
      continue;
    }

    let cached;
    try {
      cached = await gateway.getRuleProbeVerdict(key);
    } catch {
      // A cache-read failure (e.g. a transient store error) is treated as a
      // cache miss: fall through to measuring the rule fresh rather than
      // letting the error propagate out and abort the entire scan.
      cached = undefined;
    }
    if (cached) {
      if (cached.verdict === 'safe') safe.push(rule);
      else warnQuarantined(rule, cached.worstProbeMs, true);
      continue;
    }

    if (performance.now() - passStart >= passBudgetMs) {
      // The pass budget ran out before this rule could be measured at all —
      // exclude it from this pass, but do NOT persist a verdict: caching
      // 'quarantined' here would permanently quarantine a rule that was
      // never actually timed, just because it was unlucky enough to be late
      // in the list on a slow or cold-cache pass.
      warnQuarantined(rule, undefined, false);
      continue;
    }

    let isSafe: boolean;
    let worstMs: number;
    if (prober) {
      const outcome = await prober.probe(rule);
      if (outcome.status === 'unavailable') {
        // Nowhere safe to measure it. Exclude without persisting — the rule was
        // never timed, and running it here to find out is the unbounded call
        // the prober exists to replace.
        warnQuarantined(rule, undefined, false);
        continue;
      }
      // A measurement that had to be terminated is the strongest unsafe verdict
      // there is: the pattern did not merely exceed the per-probe budget, it
      // never came back. Persist it — this one has been measured.
      isSafe = outcome.status === 'ok' ? outcome.safe : false;
      worstMs = outcome.status === 'ok' ? outcome.worstMs : outcome.elapsedMs;
    } else {
      try {
        ({ safe: isSafe, worstMs } = checkRuleTiming(rule));
      } catch {
        // The measurement itself failed (unexpected error inside the probe
        // battery). This IS a real, if failed, measurement attempt — unlike
        // the budget-exhausted case above — so quarantine and persist it,
        // rather than letting the exception escape and skip the whole scan.
        isSafe = false;
        worstMs = Number.POSITIVE_INFINITY;
      }
    }
    let persisted = false;
    try {
      await gateway.setRuleProbeVerdict(key, isSafe ? 'safe' : 'quarantined', worstMs);
      persisted = true;
    } catch {
      // Losing the verdict only costs a re-measurement next process, never a
      // wrong decision now — the verdict for THIS pass is already in hand.
    }
    if (isSafe) safe.push(rule);
    else warnQuarantined(rule, worstMs, persisted);
  }

  return safe;
}
