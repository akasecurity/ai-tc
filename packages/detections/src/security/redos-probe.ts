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

// Rounds in the first pass over a pair of sizes. Each size reduces to its
// fastest reading over the rounds, so a stall or GC pause on a single round
// cannot decide the verdict.
export const GROWTH_SAMPLES = 3;

/**
 * How many steps of its clock one pair reading spans. A clock that advances in
 * steps reads a single scan as the cost rounded to a step either way, so a
 * reading repeats its scan until the clock has advanced by this many steps and
 * reads the cost per scan: the rounding is then at most one step in this many,
 * spread over every repetition. On a clock with a fine step that is one scan.
 */
export const GROWTH_WINDOW_STEPS = 8;

/**
 * How long, in elapsed time, one pair reading may take to fill its window. A
 * window spans `GROWTH_WINDOW_STEPS` steps of its clock, at most 128ms of work
 * on a 16ms step, so a reading needs about 1.3% of one core across this window
 * to finish in time. That is far below an ordinarily busy runner's share, but
 * not below every one: a thread starved past it never fills a window, exactly
 * as a clock that stops advancing does, and the two cannot be told apart here.
 * Either way the reading is refused, as a clock whose step was not measured is.
 */
export const GROWTH_WINDOW_DEADLINE_MS = 10_000;

// Rounds in the second pass `judgePair` runs on a pair over the ratio. The
// verdict on growth is given on the readings of this pass alone. Each reading
// is a window of a work clock, which a descheduled thread does not advance, so
// what this pass has to read through is what the work itself can pick up — a
// GC pause, a slower core. Each size reduces to its FASTEST reading over the
// rounds, which needs one round in four to be clean; a mean, which every GC
// pause inflates, needed many more rounds to settle. On a clock with a fine
// step a window is a single scan, so the rounds, not the window, are what read
// through that noise there.
export const GROWTH_CONFIRM_SAMPLES = 4;

// The largest size being sampled stops being read once this many rounds have
// run and every reading of it is at or over the budget, which bounds what an
// expensive pattern costs to measure. That binds only the second pass: the
// first runs GROWTH_SAMPLES rounds, no more than this many, so it never stops
// early. The second pass keeps reading the smaller sizes once it stops.
export const OVER_BUDGET_READINGS = 3;

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

// The literal WORDS a pattern contains, in order of first appearance: maximal
// runs of MIN_LITERAL_TOKEN_CHARS or more letters that sit in the pattern as
// LITERAL TEXT, outside any character class and never an escape's letter (`\b`,
// `\s`, `\n` and `\w` name no literal). Deduplicated, and capped at
// MAX_LITERAL_TOKENS.
//
// A single left-to-right walk, like `literalPrefix`, deliberately: this reads
// the same hostile `pattern` string that `fuelChars`' quadratic class scan does,
// and a second regex over it would owe the same input-bound argument. A walk
// owes none, because it is linear.
const MIN_LITERAL_TOKEN_CHARS = 3;
const MAX_LITERAL_TOKENS = 8;

function literalTokens(pattern: string): string[] {
  const tokens: string[] = [];
  const seen = new Set<string>();
  let token = '';
  let inClass = false;
  const flush = (): void => {
    if (token.length >= MIN_LITERAL_TOKEN_CHARS && !seen.has(token)) {
      seen.add(token);
      tokens.push(token);
    }
    token = '';
  };
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    // An escape's letter is a class or an anchor, never text the pattern
    // matches, so it ends a token rather than extending one. Checked before the
    // class state, so `\]` inside a class does not close it.
    if (c === '\\') {
      flush();
      i++;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      continue;
    }
    if (c === '[') {
      flush();
      inClass = true;
      continue;
    }
    if (c !== undefined && /[A-Za-z]/.test(c)) {
      token += c;
      continue;
    }
    flush();
  }
  flush();
  return tokens.slice(0, MAX_LITERAL_TOKENS);
}

// What a token run has to carry before the pattern will look at it at all: the
// pattern's literal prefix, and — appended to it — one representative STRUCTURAL
// character its classes admit, meaning one that is neither alphanumeric nor
// whitespace. A token run is itself letters and spaces, so an alphanumeric or
// whitespace fuel character adds nothing a bare run does not already have;
// a quote, bracket or operator is the gate a bare run cannot pass.
//
// `["']...` is the case that decides this. Its literal prefix is empty, so an
// ungated run of its own `select` never enters the pattern and costs nothing
// (measured 0.0ms at 64,000 chars against 596ms for the same run behind one
// `"`). Capped at MAX_TOKEN_GATES, and the prefix alone when the pattern names
// no structural character — which is the empty gate when it names no prefix
// either, and that is correct for a pattern whose tokens need nothing in front
// of them.
const MAX_TOKEN_GATES = 2;

function tokenGates(pattern: string): string[] {
  const prefix = literalPrefix(pattern);
  const gates = fuelChars(pattern)
    .filter((c) => !/[A-Za-z0-9\s]/.test(c))
    .slice(0, MAX_TOKEN_GATES)
    .map((c) => prefix + c);
  return gates.length > 0 ? gates : [prefix];
}

/**
 * Corpora built from the pattern's own literal words, repeated behind its gate.
 *
 * This is the one shape neither of the other two corpus families reaches.
 * `GROWTH_CORPORA` is a fixed alphabet plus one hard-coded SQL vocabulary, so it
 * carries a pattern's literal only by coincidence; `derivedCorpora` reaches the
 * pattern's own text only through an example that MATCHES, and repeats that
 * match or the match short of its last character — a unit the length of a whole
 * finding, where what costs is one WORD of it repeated. What costs is a walk
 * that has entered the pattern, is looking for a literal that never arrives,
 * and restarts at the next occurrence of the literal that let it in.
 *
 * Two families, because two different things are being gated past:
 *
 *   - a run of ONE token, every other literal absent. This is the input for an
 *     inner walk that a single literal opens — `select\b…\bfrom\b` entered at
 *     every `select` in a run that holds no `from`, each entry rescanning the
 *     rest of the run.
 *   - a run of an ADJACENT PAIR of the pattern's tokens, the pair present and
 *     every later literal absent. A walk whose opener is two words (`insert`
 *     `into`, `drop` `table`) is not entered by either word alone, so the pair
 *     is what a single-token run cannot reach.
 *
 * Each `build` fills to exactly `length`, as every corpus does; the growth tier
 * never asks past `GROWTH_MAX_CHARS * 2`, well inside the `MAX_REGEX_INPUT_LENGTH`
 * the matcher truncates at.
 */
export function literalTokenCorpora(rule: Rule): GrowthCorpus[] {
  if (rule.matcher.type !== 'regex') return [];
  const tokens = literalTokens(rule.matcher.pattern);
  const corpora: GrowthCorpus[] = [];
  for (const rawGate of tokenGates(rule.matcher.pattern)) {
    // A gate that ends ALPHANUMERIC would run into the token behind it and
    // spell a third word (`AKIA` before a run of `AKIA ` reads `AKIAAKIA`), so
    // it takes a separator. One that ends in anything else must not — `_`, `-`
    // and a quote are the gates whose whole point is to sit flush against what
    // follows, as `ghp_` does, and a space after them is a gate the pattern no
    // longer recognises.
    const gate = /[A-Za-z0-9]$/.test(rawGate) ? `${rawGate} ` : rawGate;
    const fill = (unit: string) => (length: number) =>
      gate + repeatTo(unit, Math.max(length - gate.length, 0));
    for (const [i, token] of tokens.entries()) {
      corpora.push({
        name: `literal token run ${JSON.stringify(gate + token + ' ')}`,
        build: fill(`${token} `),
      });
      const partner = tokens[i + 1];
      if (partner === undefined) continue;
      corpora.push({
        name: `literal token pair run ${JSON.stringify(`${gate}${token} ${partner} `)}`,
        build: fill(`${token} ${partner} `),
      });
    }
  }
  return corpora;
}

/** Every corpus the growth tier measures `rule` on, cheapest family first. */
export function growthCorporaFor(rule: Rule): GrowthCorpus[] {
  return [...GROWTH_CORPORA, ...derivedCorpora(rule), ...literalTokenCorpora(rule)];
}

// A rule scoped to capture kinds does not run on a scan that names none, so
// the growth tier scans as the first kind the rule names.
function scanContextFor(rule: Rule): { eventKind: EventKind | undefined } {
  return { eventKind: rule.appliesTo?.eventKinds?.[0] };
}

/**
 * A growth-tier breach: the corpus, the two sizes compared, and their fastest
 * readings, each the cost of one scan. An `over-budget` breach is the pair alone. A `superlinear` breach
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
}

/**
 * The cost of one run of `run`, read on `now`, a clock that advances in steps of
 * `stepMs` (0 for a clock whose step is negligible).
 *
 * The clock is read once before the first run and once after each, and `run` is
 * repeated until the clock has advanced by `GROWTH_WINDOW_STEPS` steps, so the
 * cost is a whole window divided by the runs in it. A stepped clock reads an
 * interval as its length rounded to a step either way: over one short run that
 * rounding can be the whole reading, or all of it can be missing, and over a
 * window it is one step among the window's.
 *
 * `clearBelowMs` ends the window early once the cost per run is under that line
 * beyond the rounding: the interval read plus one step, over the runs made. A
 * run that cheap needs no finer reading to be judged against the line, and on a
 * coarse clock that is what keeps a cheap scan from paying for a whole window.
 * `cleared` says that this is how the window ended.
 *
 * A window still short of its steps after `GROWTH_WINDOW_DEADLINE_MS` of
 * `wallNow` throws: the clock is starved or has stopped, and a reading cannot
 * be taken on it.
 */
export function windowReadingMs(
  run: () => void,
  now: ProbeClock,
  stepMs: number,
  clearBelowMs?: number,
  wallNow: ProbeClock = wallClock,
): { ms: number; cleared: boolean } {
  if (!Number.isFinite(stepMs) || stepMs < 0) {
    throw new Error(
      `the growth tier was given a clock step of ${String(stepMs)}ms; a reading cannot be ` +
        `windowed on a clock whose step was not measured`,
    );
  }
  const windowMs = stepMs * GROWTH_WINDOW_STEPS;
  const deadline = wallNow() + GROWTH_WINDOW_DEADLINE_MS;
  const start = now();
  let runs = 0;
  let elapsed: number;
  do {
    run();
    runs++;
    elapsed = now() - start;
    if (clearBelowMs !== undefined && (elapsed + stepMs) / runs < clearBelowMs) {
      return { ms: elapsed / runs, cleared: true };
    }
    if (elapsed < windowMs && wallNow() >= deadline) {
      throw new Error(
        `the growth tier's clock advanced ${String(elapsed)}ms of a ${String(windowMs)}ms ` +
          `window over ${String(runs)} runs in ${String(GROWTH_WINDOW_DEADLINE_MS)}ms of ` +
          `elapsed time; the clock is starved or stopped, so no growth tier is read`,
      );
    }
  } while (elapsed < windowMs);
  return { ms: elapsed / runs, cleared: false };
}

// The reading of each text, in the order given: the fastest of its window
// readings over `rounds` rounds. Each round reads every text once, in that
// order, so the readings a ratio compares are taken next to each other and a
// slow stretch of the machine lands on all of them.
//
// Everything a busy machine adds to a reading is added: a descheduled thread
// on an elapsed-time clock; on a clock of the work done, a GC pause, a JIT
// tier-up, a slower core or a cache another process emptied. None of it can
// make a scan cheaper than its work, so the fastest reading converges on the
// cost from above, and a superlinear pattern keeps its 4x or 8x between
// fastest readings. The rounding of a stepped clock is the one error that runs
// the other way, and the window bounds it.
//
// The `largest` text, the last unless given, stops being read once
// OVER_BUDGET_READINGS rounds have run and every reading of it was at or over
// the budget, which bounds what an expensive pattern costs to measure. The pass
// then ends with it, unless `keepOthers` asks for the other texts to be read
// through the remaining rounds: a verdict that compares them is only as good as
// their readings, and those cost a fraction of the largest text's. A pass of
// no more than OVER_BUDGET_READINGS rounds, as `judgePair`'s first pass is,
// reaches that stop only on its last round, so it binds the second pass.
//
// `clearBelowMs` is passed to the largest text's windows: once one reads it
// under that line beyond the clock's rounding, the pass ends with `cleared`
// set.
function readings<const T extends readonly string[]>(
  rule: Rule,
  texts: T,
  rounds: number,
  now: ProbeClock,
  stepMs: number,
  {
    keepOthers = false,
    clearBelowMs,
    largest = texts.length - 1,
  }: { keepOthers?: boolean; clearBelowMs?: number; largest?: number } = {},
): { ms: { [K in keyof T]: number }; cleared: boolean } {
  const context = scanContextFor(rule);
  const fastest = texts.map(() => Infinity) as { -readonly [K in keyof T]: number };
  let largestDone = false;
  for (let round = 0; round < rounds; round++) {
    for (const [i, text] of texts.entries()) {
      if (i === largest && largestDone) continue;
      const reading = windowReadingMs(
        () => scan(text, [rule], context),
        now,
        stepMs,
        i === largest ? clearBelowMs : undefined,
      );
      fastest[i] = Math.min(fastest[i] ?? Infinity, reading.ms);
      if (reading.cleared) return { ms: fastest, cleared: true };
    }
    largestDone ||=
      round + 1 >= OVER_BUDGET_READINGS && (fastest[largest] ?? Infinity) >= BUDGET_MS;
    if (largestDone && !keepOthers) break;
  }
  return { ms: fastest, cleared: false };
}

function ratio(smallerMs: number, largerMs: number): number {
  return largerMs / Math.max(smallerMs, 1e-6);
}

// What a quadratic cost grows by per doubling: the shape this tier exists to
// catch, and the yardstick for how far a next doubling might carry a pair.
const QUADRATIC_GROWTH = 4;

// The least a pair may grow by and still be sampled with the next doubling: the
// ratio from which a quadratic next doubling would carry the two doublings
// together past MAX_GROWTH_RATIO per doubling. A linear pair, near 2, is under it.
export const SAMPLED_GROWTH = MAX_GROWTH_RATIO ** 2 / QUADRATIC_GROWTH;

function maySuperlinear(smallMs: number, largeMs: number): boolean {
  return largeMs >= GROWTH_FLOOR_MS && ratio(smallMs, largeMs) > SAMPLED_GROWTH;
}

// Growth over the pair and the doubling after it: more than MAX_GROWTH_RATIO
// per doubling across the two together, and more than it on the second alone.
function isSuperlinear(smallMs: number, largeMs: number, nextMs: number): boolean {
  return (
    maySuperlinear(smallMs, largeMs) &&
    ratio(largeMs, nextMs) > MAX_GROWTH_RATIO &&
    ratio(smallMs, nextMs) > MAX_GROWTH_RATIO ** 2
  );
}

// The verdict on the pair `small` and `small * 2` chars of one corpus, and the
// reading at `small * 4` chars when that size was sampled.
//
// The first pass samples the pair alone, the larger text first in each round.
// A larger reading at or over the budget is an `over-budget` breach; the budget
// is judged at this size and at no other. A pair at or under SAMPLED_GROWTH is
// cleared without scanning anything larger, and so is a pair whose larger text
// reads under GROWTH_FLOOR_MS beyond the clock's rounding, as soon as one
// reading shows it: that is under the budget too, and the ratio is not judged
// below the floor. Reading the larger text first is what lets that clear a
// cheap pair before the smaller text has been read at all.
//
// A pair over SAMPLED_GROWTH is sampled again in a second pass, together with
// the doubling after it, and is a `superlinear` breach only if, on that pass's
// readings, the second doubling grew by more than MAX_GROWTH_RATIO and the two
// together by more than its square. One doubling cannot tell growth that
// persists from a step: a cost that is linear on both sides of a threshold
// between the two sizes reads a against 2a + c there, which is any ratio above
// 2 depending on the step. The next doubling separates the two by the shape of
// the curve. Past a step, a linear cost at most doubles again, whatever the
// first ratio was and whatever the scan costs. A polynomial cost does the
// opposite, because its highest term takes a larger share as the input grows: a
// quadratic rule that read 3.1x reads closer to 4x on the next doubling, a cubic
// one closer to 8x.
//
// Nor is one doubling enough to clear a pair. Where the polynomial term has not
// yet taken over, a quadratic rule reads under MAX_GROWTH_RATIO on the pair —
// 2.8x to 3.3x was read on a loaded machine for a rule that reads 4x idle — and
// a clock that advances in coarse steps moves a single ratio further than that
// margin. Over the two doublings the same rule reads 13x or more against a line
// of 9, and a linear one 4x, so the verdict on growth is judged across both.
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
  stepMs: number,
): { breach?: GrowthBreach; nextMs?: number } {
  const pair = { corpus: corpus.name, smallChars: small, largeChars: small * 2 };
  const smallText = corpus.build(pair.smallChars);
  const largeText = corpus.build(pair.largeChars);
  const first = readings(rule, [largeText, smallText], GROWTH_SAMPLES, now, stepMs, {
    clearBelowMs: GROWTH_FLOOR_MS,
    largest: 0,
  });
  if (first.cleared) return {};
  const [firstLargeMs, firstSmallMs] = first.ms;
  if (firstLargeMs >= BUDGET_MS) {
    return {
      breach: { reason: 'over-budget', ...pair, smallMs: firstSmallMs, largeMs: firstLargeMs },
    };
  }
  if (!maySuperlinear(firstSmallMs, firstLargeMs)) return {};

  const nextChars = pair.largeChars * 2;
  const [smallMs, largeMs, nextMs] = readings(
    rule,
    [smallText, largeText, corpus.build(nextChars)],
    GROWTH_CONFIRM_SAMPLES,
    now,
    stepMs,
    { keepOthers: true },
  ).ms;
  if (!isSuperlinear(smallMs, largeMs, nextMs)) return { nextMs };
  return { breach: { reason: 'superlinear', ...pair, smallMs, largeMs, nextChars, nextMs } };
}

/**
 * The first breach `judgePair` reports on `rule`, or `undefined` when it
 * reports none. A breach is a pair whose larger reading is at or over the
 * budget, or one whose cost grows by more than `MAX_GROWTH_RATIO` per doubling
 * across the pair and the doubling after it together, and by more than it on
 * that second doubling alone, the larger reading of the pair at
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
 * sampled at is not scanned again on the way up: its reading stands in for the
 * single one. `judgePair` holds the second pass.
 *
 * `now` is the clock the readings are taken with and `stepMs` the step it
 * advances by, which sizes each pair reading's window; see `windowReadingMs`.
 * The scouts on the way up are one scan each: a scout only decides where a pair
 * is first judged, and the top pair is judged whatever the scouts read.
 *
 * Call this only on a rule that already passed `worstProbeMs`. A pattern that
 * backtracks exponentially does not return on a 2,000-char input, and the
 * short probes are what catch it cheaply.
 */
export function superlinearGrowth(
  rule: Rule,
  now: ProbeClock = wallClock,
  stepMs = 0,
): GrowthBreach | undefined {
  const context = scanContextFor(rule);
  for (const corpus of growthCorporaFor(rule)) {
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
      const { breach, nextMs } = judgePair(rule, corpus, small, now, stepMs);
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
