import type { EventKind, Rule } from '@akasecurity/schema';

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
//
// THE CLASS SCAN BELOW IS QUADRATIC, DELIBERATELY LEFT SO, AND CodeQL'S ALERT ON
// IT IS DISMISSED AS `won't fix` RATHER THAN AS A FALSE POSITIVE. The difference
// matters, because the tempting reading is the wrong one.
//
// It is NOT a false positive. `/\[\^?([^\]]+)\]/g` is our own regex run over
// text we did not write — a pulled pack's `pattern` — which is exactly the shape
// a real ReDoS takes. That this module's job is adversarial concerns the probes
// it BUILDS; this is a parser over hostile input, and being next to adversarial
// code buys it nothing. On `[` repeated with no closing `]`, `matchAll` restarts
// at each position and each restart consumes to the end: measured 2.2ms / 26.7ms
// / 356ms at 2k / 8k / 32k characters.
//
// What makes it safe is the INPUT BOUND, and only that. `Rule.matcher.pattern`
// is capped at `MAX_PATTERN_LENGTH` (2000) by `@akasecurity/schema`, so 2.2ms is
// the worst reachable cost — and production reaches this only from inside the
// scan worker, under `ISOLATED_PROBE_BUDGET_MS`, where it can be killed anyway.
//
// So the dismissal rests on that cap. Raise `MAX_PATTERN_LENGTH` and this grows
// as its square with nothing guarding the link; re-measure before you do.
//
// Do not "fix" it with an atomic group. `(?=([^\]]+))\1` is provably equivalent
// here — 0 diffs across all 90 bundled patterns and 13 adversarial cases — and
// still quadratic (4.8/17.6/64.0/246.7ms at 4k/8k/16k/32k), because the cost is
// per START POSITION, not inner backtracking. Every rewrite that IS linear
// changes which classes are extracted, and that changes the probes the whole
// battery derives.
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
// 24.18) with the battery driven over all the bundled rules (101 then):
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
//
// Every number above was taken where the corroborating clock resolves to
// 0.001ms. That is not universal, and the exception decides where this value
// may go. Windows credits a whole scheduler tick to whichever thread was
// running at the timer interrupt, measured at 16.0000ms on the CI runner (the
// `Runner facts` step in ci.yml prints it), so there the reading is not how
// much CPU a probe burned but how many interrupts it was running at — and the
// 0.2-7.7ms-against-44.5ms separation above collapses onto a lattice of 0, 16,
// 32.
//
// 20ms survives that by sitting between one tick and two: a benign rule can be
// charged at most one tick and still not corroborate, while a genuine breach
// crosses two. So the usable range on a coarse clock is ONE TICK < floor <= TWO
// TICKS, which is narrower than the measured separation suggests and is not
// visible in it. A share of 0.16 or less puts the floor at or under one tick,
// at which point a benign rule whose probe merely straddles a timer interrupt
// is corroborated and quarantined for ever. Both ends are held by cases in
// test/security/redos-probe.test.ts rather than by this paragraph.
const CPU_CORROBORATION_SHARE = 0.2;

/** The corroborating clock must read at least this much for a breach to be cached. */
export const CORROBORATION_FLOOR_MS = BUDGET_MS * CPU_CORROBORATION_SHARE;

// The growth tier: how a rule's cost SCALES, rather than what one probe costs.
//
// Both tiers above judge a single reading against an absolute budget, so they
// cannot see a pattern that is polynomial with a small constant. One that costs
// 30ms on a 40KB probe passes them and still costs seconds at the engine's
// 200,000-char input cap — the same timed-out, fail-open hook as a catastrophic
// pattern, reached through a bigger input. And the fixed polynomial probes are
// single-unit runs of letters and digits, so they never supply what the
// slow shapes actually rescan: quote characters, SQL keywords between quotes,
// whitespace runs, a rule's own literal opener repeated without its closer.
//
// So this tier times each rule on structured corpora at doubling sizes and
// compares neighbouring sizes. A linear pattern costs about twice as much on
// twice the input; a quadratic one about four times, a cubic one eight. The
// ratio is scale-free — machine speed moves both readings together — so the
// verdict does not depend on how fast the runner is, only on the SHAPE of the
// cost curve.
//
// This runs in the bundled-rule CI gate only, never in the runtime pre-flight:
// it takes several samples per size (which the single-sample walk above
// forbids for its own reasons) and scans hundreds of KB per rule.

/** The smallest corpus size the growth tier measures. */
export const GROWTH_START_CHARS = 2_000;

/**
 * The largest corpus size the growth tier climbs to. `judgePair` may read one
 * doubling past it, so the largest size the tier scans is twice this.
 */
export const GROWTH_MAX_CHARS = 32_000;

// A doubling of the input may cost at most this many times as much. Linear
// scans sit near 2 and quadratic ones near 4, so 3 leaves room for noise on
// both sides.
export const MAX_GROWTH_RATIO = 3;

// The ratio is only judged once the larger reading costs at least this much.
// Below it, a sub-millisecond scan's ratio is timer resolution and GC noise,
// not a property of the pattern.
export const GROWTH_FLOOR_MS = 5;

// Rounds in the first pass over a pair of sizes. The verdict uses the fastest
// reading of each size, so a stall or GC pause on any reading but the best
// cannot decide it.
export const GROWTH_SAMPLES = 5;

// Rounds in the second pass `judgePair` runs on a pair over the ratio. The
// verdict on growth is given on the fastest readings of this pass alone.
export const GROWTH_CONFIRM_SAMPLES = 15;

// Sampling stops once this many rounds have run and every reading so far at
// the largest size being sampled is at or over the budget.
export const OVER_BUDGET_READINGS = 3;

// With a corroborating clock, an over-budget pair is a breach only if that
// clock's fastest reading of the larger size is at least this much.
//
// A growth reading is one whole scan rather than a walk cut short at its first
// slow probe, so a scan that really does a budget's worth of work reads close
// to the full budget on a work clock whatever the machine is doing. On a clock
// that advances in whole scheduler ticks (16ms on the Windows runner) it reads
// at most one tick under, so at least 84ms. A scan that only took that long
// because its thread waited for a core reads what it executed. Measured on an
// arm64 Mac with coverage instrumentation on, the bundled rules' worst scan at
// the top size burns 6.4ms of thread CPU quiet and 8.6ms under 30 CPU burners
// on 10 cores, where its wall reading was 34ms; loaded CI runners have read
// rules like it at 104-142ms on the wall. Half the budget sits above any
// benign scan plus a tick and below any breach minus one.
export const GROWTH_CORROBORATION_FLOOR_MS = BUDGET_MS / 2;

/** A named generator of adversarial text of an exact length. */
export interface GrowthCorpus {
  name: string;
  build: (length: number) => string;
}

function repeatTo(unit: string, length: number): string {
  return unit.repeat(Math.ceil(length / unit.length)).slice(0, length);
}

function joinTo(length: number, open: string, close: string, item: (i: number) => string): string {
  const parts: string[] = [];
  let size = open.length;
  for (let i = 0; size < length; i++) {
    const next = (i === 0 ? '' : ',') + item(i);
    parts.push(next);
    size += next.length;
  }
  return (open + parts.join('') + close).slice(0, length);
}

const SQL_WORDS = ['select', 'insert', 'update', 'delete', 'drop', 'where'];

// Fixed corpora shared by every rule. Each one is ordinary-looking text that
// is dense in a character or token some pattern shape rescans from every start
// position: quotes on one line, quoted SQL keywords, whitespace and newline
// runs. The fixed polynomial units are reused at growth sizes too.
export const GROWTH_CORPORA: readonly GrowthCorpus[] = [
  {
    name: 'one-line JSON dictionary',
    build: (length) => joinTo(length, '{', '}', (i) => `"id-${String(i)}":"label ${String(i)}"`),
  },
  {
    name: 'JSON array of quoted SQL keywords',
    build: (length) =>
      joinTo(length, '[', ']', (i) => `"${SQL_WORDS[i % SQL_WORDS.length] ?? ''} ${String(i)}"`),
  },
  { name: "single-quoted keyword run ('where)", build: (length) => repeatTo("'where", length) },
  {
    name: 'double-quoted keyword literal run ("where" )',
    build: (length) => repeatTo('"where" ', length),
  },
  { name: 'double-quote run', build: (length) => repeatTo('"', length) },
  { name: 'space run', build: (length) => repeatTo(' ', length) },
  { name: 'newline run', build: (length) => repeatTo('\n', length) },
  ...['abc-', 'a.', 'a ', 'a=', 'x', '0', 'a@', 'a/', 'ab'].map((unit): GrowthCorpus => ({
    name: `unit run ${JSON.stringify(unit)}`,
    build: (length) => repeatTo(unit, length),
  })),
];

// Corpora derived from the rule's own `examples`: each example's matched text
// repeated, and the same text without its last character repeated. A pattern
// whose cost is spent between its opener and a closer it looks ahead for is
// exercised on its own opener this way, which no fixed alphabet reaches.
function derivedCorpora(rule: Rule): GrowthCorpus[] {
  const units = new Set<string>();
  for (const example of rule.examples ?? []) {
    for (const finding of scan(example, [rule], scanContextFor(rule))) {
      units.add(finding.rawMatch);
      if (finding.rawMatch.length > 1) units.add(finding.rawMatch.slice(0, -1));
    }
  }
  return [...units].map((unit) => ({
    name: `example match run ${JSON.stringify(unit)}`,
    build: (length) => repeatTo(unit, length),
  }));
}

// A rule scoped to capture kinds does not run on a scan that names none, so
// the growth tier scans as the first kind the rule names.
function scanContextFor(rule: Rule): { eventKind: EventKind | undefined } {
  return { eventKind: rule.appliesTo?.eventKinds?.[0] };
}

/**
 * A growth-tier breach: the corpus, the two sizes compared, and their fastest
 * readings. An `over-budget` breach is the pair alone. A `superlinear` breach
 * also carries `nextChars` and `nextMs`, the doubling after the pair, and all
 * three of its readings come from the same rounds.
 */
export interface GrowthBreach {
  reason: 'over-budget' | 'superlinear';
  corpus: string;
  smallChars: number;
  largeChars: number;
  smallMs: number;
  largeMs: number;
  nextChars?: number;
  nextMs?: number;
  /**
   * The corroborating clock's fastest reading at `largeChars`, on an
   * `over-budget` breach found with one.
   */
  largeWorkMs?: number;
}

// The fastest reading of each text, in the order given. Each round scans every
// text once, smallest first, so the readings a ratio compares are taken next
// to each other and a slow stretch of the machine lands on all of them.
//
// The fastest reading, not the median. Everything a busy machine adds to a
// reading is added: a descheduled thread, a GC pause, a JIT tier-up. None of it
// can make a scan finish sooner than the work takes, so the minimum over
// several readings converges on the cost of the scan from above. A superlinear
// pattern is not hidden by this: its fastest readings are its true costs, and
// their ratio is the same 4x or 8x.
//
// Sampling stops short of `rounds` once OVER_BUDGET_READINGS rounds have run
// and every reading of the last text was at or over the budget, which bounds
// what an expensive pattern costs to measure.
//
// `work` is the corroborating clock's fastest reading of each text over the
// same windows, or `undefined` when no corroborating clock was given.
function fastestReadings<const T extends readonly string[]>(
  rule: Rule,
  texts: T,
  rounds: number,
  now: ProbeClock,
  corroborate: ProbeClock | undefined,
): { ms: { [K in keyof T]: number }; work: { [K in keyof T]: number } | undefined } {
  const context = scanContextFor(rule);
  const fastest = texts.map(() => Infinity);
  const fastestWork = texts.map(() => Infinity);
  for (let round = 0; round < rounds; round++) {
    texts.forEach((text, i) => {
      const start = now();
      const workStart = corroborate?.();
      scan(text, [rule], context);
      fastest[i] = Math.min(fastest[i] ?? Infinity, now() - start);
      const workEnd = corroborate?.();
      if (workStart !== undefined && workEnd !== undefined) {
        fastestWork[i] = Math.min(fastestWork[i] ?? Infinity, workEnd - workStart);
      }
    });
    if (round + 1 >= OVER_BUDGET_READINGS && (fastest.at(-1) ?? 0) >= BUDGET_MS) break;
  }
  return {
    ms: fastest as { [K in keyof T]: number },
    work: corroborate ? (fastestWork as { [K in keyof T]: number }) : undefined,
  };
}

function ratio(smallerMs: number, largerMs: number): number {
  return largerMs / Math.max(smallerMs, 1e-6);
}

function isSuperlinear(smallMs: number, largeMs: number): boolean {
  return largeMs >= GROWTH_FLOOR_MS && ratio(smallMs, largeMs) > MAX_GROWTH_RATIO;
}

// The verdict on the pair `small` and `small * 2` chars of one corpus, and the
// fastest reading at `small * 4` chars when that size was sampled.
//
// The first pass samples the pair alone. A larger reading at or over the
// budget is an `over-budget` breach; the budget is judged at this size and at
// no other. With a corroborating clock, the breach also needs that clock's
// fastest larger reading at GROWTH_CORROBORATION_FLOOR_MS or more; a pair that
// read over the budget without it is judged on its ratio like any other. A
// pair at or under the ratio is cleared without scanning anything larger.
//
// A pair over the ratio is sampled again in a second pass, together with the
// doubling after it, and is a `superlinear` breach only if both ratios read
// over MAX_GROWTH_RATIO on that pass's readings. One doubling cannot tell
// growth that persists from a step: a cost that is linear on both sides of a
// threshold between the two sizes reads a against 2a + c there, which is any
// ratio above 2 depending on the step. The next doubling separates the two by
// the shape of the curve. Past a step, a linear cost at most doubles again,
// whatever the first ratio was and whatever the scan costs. A polynomial cost
// does the opposite, because its highest term takes a larger share as the
// input grows: a quadratic rule that read 3.1x reads closer to 4x on the next
// doubling, a cubic one closer to 8x.
//
// The matchers stop at MAX_MATCHES_PER_RULE. That bounds how many matches a
// scan makes, not what each match costs: on a corpus that matches at every
// unit the count stops growing once the text holds that many units, and from
// there a pattern whose every match scans the rest of the text grows linearly
// with the text. A corpus that reaches the cap between the pair's sizes reads
// as a step here.
function judgePair(
  rule: Rule,
  corpus: GrowthCorpus,
  small: number,
  now: ProbeClock,
  corroborate: ProbeClock | undefined,
): { breach?: GrowthBreach; nextMs?: number } {
  const pair = { corpus: corpus.name, smallChars: small, largeChars: small * 2 };
  const smallText = corpus.build(pair.smallChars);
  const largeText = corpus.build(pair.largeChars);
  const { ms: first, work } = fastestReadings(
    rule,
    [smallText, largeText],
    GROWTH_SAMPLES,
    now,
    corroborate,
  );
  if (first[1] >= BUDGET_MS && (work === undefined || work[1] >= GROWTH_CORROBORATION_FLOOR_MS)) {
    return {
      breach: {
        reason: 'over-budget',
        ...pair,
        smallMs: first[0],
        largeMs: first[1],
        ...(work === undefined ? {} : { largeWorkMs: work[1] }),
      },
    };
  }
  if (!isSuperlinear(first[0], first[1])) return {};

  const nextChars = pair.largeChars * 2;
  const {
    ms: [smallMs, largeMs, nextMs],
  } = fastestReadings(
    rule,
    [smallText, largeText, corpus.build(nextChars)],
    GROWTH_CONFIRM_SAMPLES,
    now,
    undefined,
  );
  if (ratio(largeMs, nextMs) <= MAX_GROWTH_RATIO || !isSuperlinear(smallMs, largeMs)) {
    return { nextMs };
  }
  return { breach: { reason: 'superlinear', ...pair, smallMs, largeMs, nextChars, nextMs } };
}

/**
 * The first breach `judgePair` reports on `rule`, or `undefined` when it
 * reports none. A breach is a pair whose larger reading is at or over the
 * budget, or one whose cost grows by more than `MAX_GROWTH_RATIO` per doubling
 * across two consecutive doublings, the larger reading of the pair at
 * `GROWTH_FLOOR_MS` or more.
 *
 * Each corpus climbs from `GROWTH_START_CHARS` by doubling, one reading per
 * size, and judges the pair at the first size whose reading crosses the budget
 * — so a pattern that is cubic on a corpus is judged at the size where it first
 * gets expensive, not at the top — then keeps climbing while that pair clears.
 * The top pair is judged whether or not any reading crossed the budget, and no
 * pair sits above it: the budget is judged at `GROWTH_MAX_CHARS` and never at
 * twice it, so a reading over the budget at twice it that grew by
 * `MAX_GROWTH_RATIO` or less still returns `undefined`. A size a pair was
 * sampled at is not scanned again on the way up: its fastest reading stands in
 * for the single one. `judgePair` holds the second pass.
 *
 * `now` takes every reading the verdicts are given on. `corroborate`, when
 * given, is read over the same windows and only gates the `over-budget`
 * breach; see `judgePair`.
 *
 * Call this only on a rule that already passed `worstProbeMs`. A pattern that
 * backtracks exponentially does not return on a 2,000-char input, and the
 * short probes are what catch it cheaply.
 */
export function superlinearGrowth(
  rule: Rule,
  now: ProbeClock = wallClock,
  corroborate?: ProbeClock,
): GrowthBreach | undefined {
  const context = scanContextFor(rule);
  for (const corpus of [...GROWTH_CORPORA, ...derivedCorpora(rule)]) {
    let measuredMs: number | undefined;
    for (let small = GROWTH_START_CHARS; small * 2 <= GROWTH_MAX_CHARS; small *= 2) {
      const large = small * 2;
      let reading = measuredMs;
      measuredMs = undefined;
      if (reading === undefined) {
        const text = corpus.build(large);
        const start = now();
        scan(text, [rule], context);
        reading = now() - start;
      }
      if (reading < BUDGET_MS && large < GROWTH_MAX_CHARS) continue;
      const { breach, nextMs } = judgePair(rule, corpus, small, now, corroborate);
      if (breach) return breach;
      measuredMs = nextMs;
    }
  }
  return undefined;
}

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
