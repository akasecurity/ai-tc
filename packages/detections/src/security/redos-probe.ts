import type { Rule } from '@akasecurity/schema';

import { scan } from '../index.ts';

// scan() is synchronous and cannot be interrupted mid-exec, so a catastrophic
// regex rule can hang the hook path. This module measures a rule's worst-case
// execution time against an adversarial probe battery — used both by the CI
// gate for bundled rules (redos.test.ts) and by the runtime pre-flight check
// for rules that arrive from a pulled or custom pack.
export const BUDGET_MS = 100;

// Two FIXED probe tiers, because the two failure modes need opposite inputs.
//
// Exponential backtracking blows up on SHORT input — 25 chars is already
// well over the budget — so a longer probe would hang the run instead of
// failing it (a single scan() cannot be interrupted mid-exec). Each unit is a
// near-miss run capped with a character that forces the match to fail, which
// is what drives the backtracking. The upper length stays low enough that even
// the slowest CI runner finishes one scan in seconds, not tens of seconds.
const EXPONENTIAL_UNITS = [
  'a',
  '0',
  ' ',
  'x',
  'ab',
  'a.',
  'a-',
  'a_',
  'a@',
  'a/',
  'a:',
  'a=',
  'a;',
  'aA0',
  '\t',
];
export const EXPONENTIAL_PROBES = EXPONENTIAL_UNITS.flatMap((unit) =>
  [23, 25].map((len) => unit.repeat(Math.ceil(len / unit.length)).slice(0, len) + '!'),
);

// Quadratic backtracking only shows up at scale — this is the tier that
// catches slow-but-not-catastrophic patterns a short probe would miss.
export const POLYNOMIAL_PROBES = ['abc-', 'a.', 'a ', 'a=', 'x', '0', 'a@', 'a/', 'ab'].map(
  (unit) => unit.repeat(10_000).slice(0, 40_000) + '!',
);

// The literal prefix a pattern requires before its first variable construct.
// A rule like `ghp_([A-Za-z0-9]+)+$` fails at the literal `ghp_` for every
// probe that does not start with it, so its catastrophic tail is unreachable
// unless the probe is prefixed. Anchors and boundaries are skipped; a `\d`,
// `\w`, `.` etc. ends the prefix.
function literalPrefix(pattern: string): string {
  let prefix = '';
  let i = 0;
  if (pattern[i] === '^') i++;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === undefined) break;
    if (c === '\\') {
      const next = pattern[i + 1];
      if (next === 'b' || next === 'B') {
        i += 2;
        continue;
      }
      if (next === undefined || /[dDwWsSnrtfv.]/.test(next)) break;
      prefix += next;
      i += 2;
      continue;
    }
    if ('([{.*+?|)]}^$'.includes(c)) break;
    prefix += c;
    i++;
  }
  return prefix;
}

// One representative character per character class / shorthand the pattern uses,
// so a probe run is made of characters the pattern's repeated group actually
// consumes. Falls back to 'a' when the pattern names no class.
function fuelChars(pattern: string): string[] {
  const fuel = new Set<string>();
  for (const m of pattern.matchAll(/\[\^?([^\]]+)\]/g)) {
    const body = m[1];
    if (body === undefined) continue;
    const range = /([A-Za-z0-9])-[A-Za-z0-9]/.exec(body);
    const rangeStart = range?.[1];
    if (rangeStart !== undefined) fuel.add(rangeStart);
    else {
      const literal = body.replace(/\\/g, '')[0];
      if (literal !== undefined && literal !== '^') fuel.add(literal);
    }
  }
  if (pattern.includes('\\w')) fuel.add('a');
  if (pattern.includes('\\d')) fuel.add('0');
  if (pattern.includes('\\s')) fuel.add(' ');
  if (/(?<!\\)\./.test(pattern)) fuel.add('a');
  if (fuel.size === 0) fuel.add('a');
  return [...fuel];
}

// Adversarial inputs derived from the pattern itself: `<prefix><fuel×N><term>`,
// where `term` is a character the fuel class does not contain, forcing the
// repeated group to fail and backtrack. Exponential-scale only (23/25 chars) —
// a long derived probe would false-positive on rules that are linear-but-slow
// on a big input of their own alphabet.
function derivedProbes(pattern: string): string[] {
  const prefix = literalPrefix(pattern);
  const fuel = fuelChars(pattern);
  const terminators = ['!', '#', '~', '\n'];
  const probes: string[] = [];
  for (const f of fuel) {
    for (const term of terminators) {
      if (term === f) continue;
      for (const len of [23, 25]) probes.push(prefix + f.repeat(len) + term);
    }
  }
  return probes;
}

// Fixed short probes and per-rule derived probes run FIRST (both cheap on a safe
// rule, budget-blowing on a bad one); the fixed 40KB polynomial tier runs last.
// The ordering matters: a pattern that backtracks catastrophically on a short
// probe takes geological time on a 40KB one, so it must fail on a short probe
// before the polynomial tier is ever reached. `scan()` cannot be interrupted
// mid-exec, so the walk stops at the first over-budget probe.
function probesFor(rule: Rule): string[] {
  const derived = rule.matcher.type === 'regex' ? derivedProbes(rule.matcher.pattern) : [];
  return [...derived, ...EXPONENTIAL_PROBES, ...POLYNOMIAL_PROBES];
}

// A monotonic clock reading milliseconds, injected so a caller can time the
// walk against a resource other than wall time.
//
// The default is wall time, which is what the RUNTIME pre-flight wants: a rule
// is quarantined because it would spend the hook's harness timeout, and that
// timeout is wall-clock. But wall time answers "how long did this take" rather
// than "how much work was this", and the two diverge on a loaded machine — a
// descheduled thread accumulates wall time having executed nothing, and the
// walk cannot tell that from a pattern that backtracked for the same duration.
// A caller that needs the second question — the bundled-rule CI gate, where a
// stall is a false accusation against a reviewed rule — passes a clock that
// reads CPU time instead. Reading a different resource is the whole reason this
// is a parameter and not a constant: the probe walk, its ordering and its
// early stop must stay a single implementation, because a second copy of them
// would be free to disagree about which probe the verdict came from.
export type ProbeClock = () => number;

const wallClock: ProbeClock = () => performance.now();

// Each probe is timed ONCE, and that single measurement is the verdict. Do not
// re-run a probe and keep the lower sample — not to "confirm" a breach, not as
// an average, not as a best-of-N. V8 executes a regex in the Irregexp bytecode
// interpreter on its first execution and tiers up to native code afterwards,
// caching the compiled form against source+flags, so rebuilding the matcher
// does not reset it. For `^(a+)+bc` on this battery's first probe that is
// ~120ms interpreted against ~15ms native, and the interpreted number is the
// one production pays: a plugin hook is a fresh short-lived process that scans
// each rule once. A second sample therefore measures the native tier, and
// keeping the lower of the two admits an over-budget rule — permanently, since
// the verdict is cached. A GC pause and the interpreted tier are
// indistinguishable by re-measurement; only the first is noise.
//
// That rule is what forces the clock to be the adjustable part. Re-measuring is
// the obvious answer to a noisy sample and it is closed off here, so a caller
// that cannot tolerate noise has to change WHAT is measured rather than HOW
// MANY times — which is also the stronger fix, since one CPU-time sample
// rejects a stall that no number of wall-time samples can separate from the
// interpreted tier.
/**
 * What one probe walk measured.
 *
 * `corroboratedMs` is a SECOND clock's reading of the SAME probe window that
 * produced `ms` — not of the whole walk, and not of a second walk. Both halves
 * of that matter. A reading over the whole walk charges the winning probe with
 * every other probe's cost, and a second walk measures the native tier rather
 * than the interpreted one the paragraph above is about, so neither can be
 * compared against `ms` at all.
 */
export interface ProbeTiming {
  /** The deciding clock's worst reading. */
  ms: number;
  /** The probe that produced it. */
  probe: string;
  /**
   * The corroborating clock over that same window, or `undefined` when no
   * second clock was supplied. `undefined` is "nobody asked", never "zero".
   */
  corroboratedMs: number | undefined;
}

/** The slowest probe against `rule`, in ms; stops early once one blows the budget. */
export function worstProbeMs(
  rule: Rule,
  now: ProbeClock = wallClock,
  corroborate?: ProbeClock,
): ProbeTiming {
  let ms = 0;
  let probe = '';
  let corroboratedMs: number | undefined;
  for (const text of probesFor(rule)) {
    const start = now();
    const corroborateStart = corroborate?.();
    scan(text, [rule]);
    const elapsed = now() - start;
    // Read unconditionally, so every probe's corroborating window has the same
    // shape whether or not it wins — reading inside the branch below would give
    // the winner a window measured differently from the ones it was compared
    // against. Both windows already span the `now()` call above; that cost is
    // one clock read and is charged identically to every probe.
    const corroborateEnd = corroborate?.();
    if (elapsed > ms) {
      ms = elapsed;
      probe = text;
      corroboratedMs =
        corroborateStart === undefined || corroborateEnd === undefined
          ? undefined
          : corroborateEnd - corroborateStart;
    }
    if (ms >= BUDGET_MS) break;
  }
  return { ms, probe, corroboratedMs };
}

// A same-length ordinary input for `rule` that cannot enter the pattern's
// repeated group, so scan() runs linearly over it. Its cost is this machine's
// baseline for an input of this size — the denominator a catastrophic probe is
// measured against, so the ratio reflects backtracking blowup rather than raw
// machine speed. 'z' matches none of the meta-test patterns' required prefixes
// or character classes, so every probe fails before the group and never
// backtracks. `min` over several samples rejects scheduler noise on a
// sub-millisecond measurement.
export function benignBaselineMs(rule: Rule, length: number): number {
  const text = 'z'.repeat(length);
  scan(text, [rule]);
  let ms = Infinity;
  for (let i = 0; i < 7; i++) {
    const start = performance.now();
    scan(text, [rule]);
    ms = Math.min(ms, performance.now() - start);
  }
  return ms;
}

// A catastrophic probe must cost dramatically more than an ordinary input of the
// same length on the SAME machine. This ratio is scale-free: hardware speed and
// CPU contention slow both measurements together and cancel out, where an
// absolute-millisecond threshold does not.
export const CATASTROPHIC_RATIO = 50;

// Below any genuine scan cost, so it only replaces an unmeasurably fast baseline
// that rounded to zero and never distorts a real measurement.
const MIN_BASELINE_MS = 1e-6;

// The worst probe's slowdown over a same-length benign baseline for `rule`.
export function backtrackRatio(rule: Rule): { ratio: number; ms: number; benignMs: number } {
  const { ms, probe } = worstProbeMs(rule);
  const benignMs = Math.max(benignBaselineMs(rule, probe.length), MIN_BASELINE_MS);
  return { ratio: ms / benignMs, ms, benignMs };
}

// How much of the budget must be WORK before a breach is allowed to become a
// permanent verdict, as a share of BUDGET_MS.
//
// The measured separation this sits in, taken on an arm64 Mac (14 cores, Node
// 24.18) with the battery driven over all 101 bundled rules:
//
//   - A benign rule's whole battery costs 1.2ms of CPU quiet. Under 96
//     concurrent CPU burners one crossed the 100ms WALL budget at 104.9ms
//     having burned 0.5ms — a 210x divergence, and the false accusation this
//     constant exists to refuse. A wider fleet run recorded the same shape
//     across five different rules at 0.2-7.7ms of CPU.
//   - A genuinely catastrophic pattern is CPU-bound by construction. Quiet,
//     the four textbook shapes burn 163-458ms. Under the same 96 burners they
//     still burn 196-600ms — except `(x+x+)+y`, measured at 44.5 / 45.9 / 48.8
//     / 49.1ms over four runs, which is the floor this has to sit under.
//
// So the gap is roughly 7.7ms to 44.5ms, and 20ms splits it: ~2.6x above the
// worst stall, ~2.2x below the worst-case genuine breach.
//
// Why the genuine floor drops so far under load is worth keeping, because it is
// what rules out the obvious threshold. The walk stops at the first probe whose
// WALL reading crosses the budget, so a stalled machine ends the walk earlier in
// CPU terms than a quiet one — a full `BUDGET_MS` of corroborating CPU is
// therefore NOT reachable on a loaded machine, and requiring it would refuse to
// quarantine a genuinely catastrophic rule exactly when the machine is busiest.
//
// The two errors are not symmetric, which is what settles the direction to lean.
// Too high, and a hostile rule is excluded from every run but never cached: the
// enforcement still happens, it is just re-measured each process, and it becomes
// permanent as soon as the machine is quiet enough to burn the CPU. Too low, and
// a stall permanently disables a rule the user installed. Only the second is
// unrecoverable without `aka detections unquarantine`, so a value that errs
// toward "measure it again" is the safe one.
const CPU_CORROBORATION_SHARE = 0.2;

/** The corroborating clock must read at least this much for a breach to be cached. */
export const CORROBORATION_FLOOR_MS = BUDGET_MS * CPU_CORROBORATION_SHARE;

/**
 * What the pre-flight learned about a rule, and — separately — whether that is
 * worth remembering.
 *
 * The two questions are NOT the same, and collapsing them is the defect this
 * replaced. A rule is excluded on WALL time, because the thing being defended
 * is the hook's harness timeout and that timeout is wall-clock. But the verdict
 * is cached forever and nothing ever re-measures, so what may be written down
 * has to answer a stricter question: was this elapsed time WORK?
 *
 *   - `safe` — under budget. Cacheable; the rule runs.
 *   - `over-budget` — over budget, and the corroborating clock agrees the time
 *     was spent executing. Evidence against the rule, so cacheable.
 *   - `uncorroborated` — over budget on the wall while almost nothing ran. That
 *     is a statement about the MACHINE, not about the rule: a descheduled thread
 *     accrues elapsed time having executed nothing, and no number of wall-clock
 *     samples can separate that from a pattern that backtracked for as long. The
 *     rule is still excluded from this run — the wall bound is what the harness
 *     enforces and it was genuinely blown — but nothing is written down, so the
 *     next process measures it again instead of inheriting an accusation.
 */
export type RuleTimingVerdict = 'safe' | 'over-budget' | 'uncorroborated';

export interface RuleTiming {
  verdict: RuleTimingVerdict;
  /** The wall reading that decided exclusion. */
  worstMs: number;
  /** The work reading over that same probe window. */
  corroboratedMs: number;
  probe: string;
}

/**
 * The runtime pre-flight check: is `rule`'s regex matcher safe against this same
 * probe battery, and — if not — is the breach worth caching?
 *
 * Any verdict other than `safe` means the rule must be excluded from the active
 * ruleset entirely: never registered, never silently allowed through. Only
 * `over-budget` may be persisted.
 *
 * `corroborate` is REQUIRED rather than defaulted, and deliberately so. A caller
 * that omitted it would get today's behaviour — a permanent verdict from a wall
 * clock — which is exactly the failure this signature exists to make
 * unrepresentable, and an optional parameter is dropped in silence (nothing
 * typechecks it, nothing lints it, no test sees it). Every caller therefore has
 * to name the resource it is willing to disable a user's rule on. This package
 * takes no Node-API dependency, so it cannot read CPU time itself — the clock
 * comes from whichever caller has one.
 */
export function checkRuleTiming(rule: Rule, corroborate: ProbeClock): RuleTiming {
  const { ms, probe, corroboratedMs } = worstProbeMs(rule, wallClock, corroborate);
  // A walk that never ran a probe reports 0 on both clocks, which is `safe` on
  // the first test and never reaches the second.
  const work = corroboratedMs ?? 0;
  const verdict: RuleTimingVerdict =
    ms < BUDGET_MS ? 'safe' : work >= CORROBORATION_FLOOR_MS ? 'over-budget' : 'uncorroborated';
  return { verdict, worstMs: ms, corroboratedMs: work, probe };
}
