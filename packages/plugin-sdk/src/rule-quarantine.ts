import type { RuleTimingVerdict } from '@akasecurity/detections';
import { checkRuleTiming } from '@akasecurity/detections';
import type { Rule } from '@akasecurity/schema';

import type { DataGateway } from './data-gateway.ts';
import { contentHashOf } from './events.ts';
import type { IsolatedProbeOutcome } from './isolated-scan.ts';
import { workClockMs } from './work-clock.ts';

// Overall wall-clock budget for one filtering pass across all not-yet-cached
// rules. Protects the hook's timeout against a pack containing many
// never-before-seen slow rules at once: once the cap is hit, every remaining
// unchecked rule is quarantined without measurement rather than continuing to
// spend time on it.
const PASS_BUDGET_MS = 2_000;

// What a user runs to undo a quarantine. Named in every warning that LEFT A
// VERDICT BEHIND, because that verdict is cached forever and the stderr line is
// the only place the machine ever mentions it. A line that cached nothing must
// not carry it: `aka detections unquarantine` would find no row for that rule,
// so the one offered next step leads nowhere.
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

/**
 * Every per-rule line this module writes.
 *
 * `verb` is load-bearing rather than decorative. A rule can leave the pre-flight
 * for four reasons that want four different responses, and only ONE of them is a
 * statement about the rule at all — so only one is a "quarantine". Collapsing
 * them tells a user to fix a rule when the ruleset is fine, or to clear a
 * quarantine row that was never written.
 */
function warn(rule: Rule, verb: string, detail: string, recoverable: boolean): void {
  const hint = recoverable ? ` (${UNQUARANTINE_HINT})` : '';
  process.stderr.write(`[aka] ${verb} rule "${rule.id}": ${detail}${hint}\n`);
}

/**
 * Case 1 — the battery MEASURED this rule and it failed.
 *
 * The only outcome that is evidence against the rule, and so the only one
 * allowed to say "exceeded the ReDoS timing budget". `worstMs` is always a real
 * reading here: a cached verdict carries the number that produced it, and a live
 * measurement carries its own. The non-finite case is the battery erroring out
 * rather than returning a time — still a real, if failed, attempt, so it is
 * still persisted, but it has no duration to quote and must not invent one
 * ("Infinityms" reads as a measurement rather than the absence of one).
 */
function warnQuarantined(rule: Rule, worstMs: number, cached: boolean): void {
  warn(
    rule,
    'quarantined',
    Number.isFinite(worstMs)
      ? `regex matcher exceeded the ReDoS timing budget (${worstMs.toFixed(1)}ms); excluded from this scan.`
      : 'the timing battery failed while measuring its regex matcher; excluded from this scan.',
    cached,
  );
}

/**
 * Case 2 — the pre-flight's pass budget ran out before this rule's turn.
 *
 * Nothing was measured and nothing was cached, so the rule is neither
 * quarantined nor suspected: it was unlucky in the ordering and comes back on
 * the next pass. Says so without invoking the timing budget, and never carries
 * the unquarantine hint — there is no row to clear.
 */
function warnUnmeasured(rule: Rule): void {
  warn(
    rule,
    'skipped',
    'the timing pre-flight ran out of time before this rule could be measured; ' +
      'excluded for the rest of this run, and measured again next time.',
    false,
  );
}

/**
 * Case 4 — the rule blew the wall budget while doing essentially no work.
 *
 * The rule is excluded exactly as a measured breach is: the wall bound is what
 * the hook's harness enforces, and it was genuinely blown. What is different is
 * that NOTHING is cached, so this line must not carry the unquarantine hint —
 * there is no row to clear, and sending someone to `aka detections unquarantine`
 * lands them on a list their rule is not on.
 *
 * The wording blames the machine rather than the rule, because that is what the
 * measurement says. A descheduled thread accrues elapsed time having executed
 * nothing, and a developer machine under a build or a test run is the normal
 * case rather than an edge one — quoting a timing budget here would be a false
 * accusation against a pattern that may be perfectly ordinary. Both numbers are
 * quoted precisely so the claim can be checked rather than taken on trust.
 */
function warnUncorroborated(rule: Rule, worstMs: number, corroboratedMs: number): void {
  warn(
    rule,
    'deferred',
    `its regex matcher ran past the ReDoS timing budget (${worstMs.toFixed(1)}ms) but spent ` +
      `only ${corroboratedMs.toFixed(1)}ms of CPU doing it, which is a busy machine rather than ` +
      'a slow pattern; excluded from this run and measured again next time, with nothing ' +
      'recorded against it.',
    false,
  );
}

/**
 * Case 3 — there was nowhere to measure anything.
 *
 * One line for the whole pass, and deliberately without a rule id. A missing or
 * unstartable worker is a property of the INSTALL: it excludes every
 * pulled/custom regex rule on the machine from every scan until the install is
 * repaired, so it is one fact rather than N facts about rules. Naming a rule
 * here is what sends someone to inspect a ruleset that is fine, and the fix —
 * reinstalling — is one they would never reach from a per-rule timing line.
 *
 * It does not claim a span, which is the mistake `guarded-scan.ts` needs its
 * `degradeScope` parameter to avoid. The pre-flight runs ONCE per process, and a
 * hook scans many fields in that process, so "this scan" would be wrong for
 * every caller — and understating a whole-category gap as momentary is what
 * talks a reader out of the reinstall this line just asked for. What is true
 * without qualification is that nothing was cached, so repairing the install is
 * the whole fix.
 */
function warnUnmeasurable(reason: string, count: number): void {
  process.stderr.write(
    `[aka] ${String(count)} pulled/custom-pack rule(s) could not be time-checked: ${reason}. ` +
      'That is a problem with this install, not with the rules — until it is fixed they are ' +
      'excluded from every scan on this machine. Nothing was quarantined, so reinstalling AKA ' +
      'brings them straight back.\n',
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
  warn(rule, 'quarantined', detail, cached);
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
  // Case 3 is one fact about the install rather than N facts about rules, so it
  // is counted here and reported once at the end of the pass. Keyed by reason:
  // a pass normally sees only one (the scanner latches a dead worker and every
  // later probe returns the same answer), but two distinct reasons are two
  // distinct faults and merging them would name neither.
  const unmeasurable = new Map<string, number>();

  // Buffered, so the flush has to survive an abandoned pass as well as a
  // completed one. Every failure inside the loop is caught except the prober's
  // own rejection, and dropping the buffer there would lose the one accurate
  // account of a broken install — the exact silence this reporting exists to
  // break. Cheaper to guarantee than to reason about per caller.
  try {
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
        warnUnmeasured(rule);
        continue;
      }

      let verdict: RuleTimingVerdict;
      let worstMs: number;
      // The work reading behind the verdict, so the `deferred` line can quote it
      // rather than assert it. A terminated measurement has none — it never came
      // back — and that path is `over-budget`, which never reads this.
      let corroboratedMs = 0;
      if (prober) {
        const outcome = await prober.probe(rule);
        if (outcome.status === 'unavailable') {
          // Nowhere safe to measure it. Exclude without persisting — the rule was
          // never timed, and running it here to find out is the unbounded call
          // the prober exists to replace. The prober's own reason is the ONE
          // accurate diagnosis of this failure anywhere in the process, so carry
          // it rather than collapsing it into a timing message; reported once for
          // the whole pass, below.
          unmeasurable.set(outcome.reason, (unmeasurable.get(outcome.reason) ?? 0) + 1);
          continue;
        }
        // A measurement that had to be TERMINATED is persisted WITHOUT
        // corroboration. That asymmetry is deliberate, and so is its cost.
        //
        // Why it is right: measuring a rule means driving its own pattern into
        // backtracking, so a pulled rule that hangs the battery is the ordinary
        // case on this path rather than an exotic one, and this is the only
        // verdict that converges it. Withhold the row and every later process
        // pays the same deadline to learn the same thing, for ever.
        //
        // Why it is not free, stated because the obvious reading is wrong:
        // `ISOLATED_PROBE_BUDGET_MS` is itself a WALL deadline, so the parent
        // cannot tell "never came back" from "was not scheduled for a second".
        // A severe enough stall therefore writes a permanent quarantine for a
        // benign rule — the exact defect corroboration exists to remove,
        // reached through the one door it does not cover. What bounds it is how
        // far the two clocks must diverge: the slowest bundled rule's whole
        // battery measures 1.46ms, so blowing the 1000ms deadline takes ~684x,
        // against the 210x measured under 96 CPU burners on 14 cores. Rare, not
        // impossible.
        //
        // Closing it needs the worker to report its own thread CPU as it walks,
        // so a terminated probe can be corroborated too. That is a wire change
        // and is tracked separately — do not "fix" this by dropping the write,
        // which trades a common correct outcome for a rare wrong one.
        verdict = outcome.status === 'ok' ? outcome.verdict : 'over-budget';
        worstMs = outcome.status === 'ok' ? outcome.worstMs : outcome.elapsedMs;
        if (outcome.status === 'ok') corroboratedMs = outcome.corroboratedMs;
      } else {
        try {
          ({ verdict, worstMs, corroboratedMs } = checkRuleTiming(rule, workClockMs));
        } catch {
          // The measurement itself failed (unexpected error inside the probe
          // battery). This IS a real, if failed, measurement attempt — unlike
          // the budget-exhausted case above — so quarantine and persist it,
          // rather than letting the exception escape and skip the whole scan.
          verdict = 'over-budget';
          worstMs = Number.POSITIVE_INFINITY;
        }
      }

      if (verdict === 'uncorroborated') {
        // Over the wall budget while almost nothing executed. That is evidence
        // about the MACHINE, not about the rule, so the rule is excluded from
        // this run — the wall bound is what the harness enforces and it was
        // genuinely blown — and NOTHING is cached. Caching here is the whole
        // defect: the verdict is permanent, nothing re-measures, and the rule the
        // user installed is disabled for every later process because one moment
        // on a busy machine looked like backtracking.
        warnUncorroborated(rule, worstMs, corroboratedMs);
        continue;
      }

      const isSafe = verdict === 'safe';
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
  } finally {
    for (const [reason, count] of unmeasurable) warnUnmeasurable(reason, count);
  }

  return safe;
}
