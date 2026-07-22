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

/** The slowest probe against `rule`, in ms; stops early once one blows the budget. */
export function worstProbeMs(rule: Rule): { ms: number; probe: string } {
  let ms = 0;
  let probe = '';
  for (const text of probesFor(rule)) {
    const start = performance.now();
    scan(text, [rule]);
    const elapsed = performance.now() - start;
    if (elapsed > ms) {
      ms = elapsed;
      probe = text;
    }
    if (ms >= BUDGET_MS) break;
  }
  return { ms, probe };
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

// The runtime pre-flight check: is `rule`'s regex matcher safe against this
// same probe battery? `safe: false` means the rule must be excluded from the
// active ruleset entirely — never registered and never silently allowed
// through.
export function checkRuleTiming(rule: Rule): { safe: boolean; worstMs: number; probe: string } {
  const { ms, probe } = worstProbeMs(rule);
  return { safe: ms < BUDGET_MS, worstMs: ms, probe };
}
