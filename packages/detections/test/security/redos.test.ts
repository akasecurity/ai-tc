import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../../src/index.ts';
import { discoverBundledRuleFiles, loadRule } from '../helpers/rules.ts';

// scan() is synchronous and runs on the hook path. A rule that backtracks
// catastrophically cannot be interrupted — the fail-open catch in the plugin
// runtime only catches throws, and a hook killed at its 10s timeout fails open,
// letting the call through UNSCANNED. So a slow rule is a detection bypass, not
// just a stall.
//
// SCOPE. This gate binds the rules in this repository only, and within them it
// proves "no bundled rule backtracks on the inputs the battery constructs" —
// not "no bundled rule can ReDoS at all". The battery mixes two probe sources:
//   1. a FIXED lowercase-and-digit alphabet (below), plus
//   2. per-rule DERIVED probes built from each pattern's own literal prefix and
//      character classes (`derivedProbes`), so a rule gated behind a literal
//      like `ghp_(...)+$` — the shape the real secret rules here use — is
//      actually exercised past its prefix on its own alphabet.
// Residual gaps, all documented rather than silently covered: backtracking that
// needs a literal (non-class) character the pattern repeats; polynomial blowup
// reachable only on a non-lowercase alphabet (the fixed polynomial tier is
// lowercase-and-digit); and any rule that arrives at runtime from a pulled or
// custom pack, which this suite never sees.
const BUDGET_MS = 100;

const bundled = discoverBundledRuleFiles().map(({ packDirAbs, ruleFile }) =>
  loadRule(packDirAbs, ruleFile),
);

// Two FIXED probe tiers, because the two failure modes need opposite inputs.
//
// Exponential backtracking blows up on SHORT input — 26 chars is already
// seconds — so a long probe would hang the run instead of failing it. Each
// unit is a near-miss run capped with a character that forces the match to
// fail, which is what drives the backtracking.
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
const EXPONENTIAL_PROBES = EXPONENTIAL_UNITS.flatMap((unit) =>
  [24, 26].map((len) => unit.repeat(Math.ceil(len / unit.length)).slice(0, len) + '!'),
);

// Quadratic backtracking only shows up at scale — this is the tier the two
// named regressions below were caught by (a 40KB paste, >1400ms before the fix).
const POLYNOMIAL_PROBES = ['abc-', 'a.', 'a ', 'a=', 'x', '0', 'a@', 'a/', 'ab'].map(
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
// repeated group to fail and backtrack. Exponential-scale only (26/28 chars) —
// a long derived probe would false-positive on rules that are linear-but-slow
// on a big input of their own alphabet (e.g. stack-trace at ~800ms on 40KB).
function derivedProbes(pattern: string): string[] {
  const prefix = literalPrefix(pattern);
  const fuel = fuelChars(pattern);
  const terminators = ['!', '#', '~', '\n'];
  const probes: string[] = [];
  for (const f of fuel) {
    for (const term of terminators) {
      if (term === f) continue;
      for (const len of [26, 28]) probes.push(prefix + f.repeat(len) + term);
    }
  }
  return probes;
}

// Fixed short probes and per-rule derived probes run FIRST (both cheap on a safe
// rule, budget-blowing on a bad one); the fixed 40KB polynomial tier runs last.
// The ordering matters: a pattern that backtracks catastrophically on a short
// probe takes geological time on a 40KB one, so it must fail on a short probe
// before the polynomial tier is ever reached — for a bundled rule here and for
// the self-test below that deliberately supplies one. `scan()` cannot be
// interrupted mid-exec, so the walk stops at the first over-budget probe.
function probesFor(rule: Rule): string[] {
  const derived = rule.matcher.type === 'regex' ? derivedProbes(rule.matcher.pattern) : [];
  return [...derived, ...EXPONENTIAL_PROBES, ...POLYNOMIAL_PROBES];
}

/** The slowest probe against `rule`, in ms; stops early once one blows the budget. */
function worstProbeMs(rule: Rule): { ms: number; probe: string } {
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

describe('bundled rules survive adversarial input', () => {
  it('discovers every bundled rule', () => {
    // Guards against the suite silently shrinking to zero if discovery breaks.
    expect(bundled.length).toBeGreaterThan(90);
  });

  it.each(bundled.map((rule) => [rule.id, rule] as const))(
    '%s stays within the scan budget',
    (id, rule) => {
      const { ms, probe } = worstProbeMs(rule);
      expect(
        ms,
        `Rule "${id}" took ${ms.toFixed(1)}ms on a ${String(probe.length)}-char probe ` +
          `(budget ${String(BUDGET_MS)}ms). A rule this slow can exhaust the hook's 10s timeout, ` +
          `which fails open and lets the call through unscanned. Rewrite the pattern to ` +
          `remove the ambiguity — usually a quantified group whose body can match the same ` +
          `text more than one way, e.g. (a+)+ or (\\s*\\w+)*.`,
      ).toBeLessThan(BUDGET_MS);
    },
  );
});

function parseRegexRule(pattern: string) {
  return Rule.safeParse({
    specVersion: 1,
    id: 'test-pack/evil',
    name: 'evil',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern, flags: 'g' },
  });
}

// Catastrophic patterns meet two defences, and which one fires is not obvious.
describe('the schema rejects catastrophic patterns that can match empty', () => {
  // `matchesEmptyString` exists to stop an empty-match rule spinning the
  // matcher, but it also turns away a whole class of ReDoS: an outer `*`
  // quantifier means the pattern matches '' and never reaches the engine.
  // These never make it to the probe battery, so do not "fix" them by adding
  // probes — assert the earlier defence instead.
  it.each([
    ['nested star', '(a*)*$'],
    ['nested class quantifier', '([a-zA-Z]+)*$'],
    ['whitespace/word ambiguity', '(\\s*\\w+)*$'],
    ['identical alternation', '(a|a)*$'],
    ['overlapping alternation', '(a|ab)*$'],
  ])('rejects %s', (_label, pattern) => {
    const parsed = parseRegexRule(pattern);
    expect(parsed.success).toBe(false);
  });

  it('but a captureGroup re-opens every one of them', () => {
    // The refine is `captureGroup !== undefined || !matchesEmptyString(...)`,
    // so setting a captureGroup skips the empty-string check entirely — and the
    // schema comment explicitly invites `*`/`?` around a capture. So the "assert
    // the schema, not a probe" note above holds ONLY while captureGroup is
    // absent; with one, these shapes parse and the probe battery becomes the
    // only defence again.
    const parsed = Rule.safeParse({
      specVersion: 1,
      id: 'test-pack/evil',
      name: 'evil',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: '(a*)*$', flags: 'g', captureGroup: 1 },
    });
    expect(parsed.success).toBe(true);
  });
});

describe('the probe battery itself', () => {
  // Without this, the suite above passes trivially if the probes stop being
  // adversarial (a refactor drops the terminator, shrinks the lengths, …) —
  // 101 green tests that check nothing.
  //
  // A pattern belongs here only if it blows the budget on an early SHORT probe.
  // The assertion is a lower bound on time, so the case runs for as long as the
  // pattern is slow, and how slow is hardware-dependent: `(.*a){20}$` costs
  // ~1.2s on one machine and over 5s on the Windows runner, where it exceeded
  // the test timeout. It proved nothing the two below do not, so it is not
  // worth a multi-second case. Add a pattern here only after checking what its
  // first matching probe costs.
  it.each([
    ['nested quantifier', '^(a+)+$'],
    ['adjacent quantifiers in a quantified group', '(x+x+)+y'],
  ])('catches a catastrophic pattern the schema admits: %s', (_label, pattern) => {
    const parsed = parseRegexRule(pattern);
    // Both require at least one character, so `matchesEmptyString` lets them
    // through. Nothing analyses pattern complexity — this suite is the only
    // thing standing between one of these and `rules/`.
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(worstProbeMs(parsed.data).ms).toBeGreaterThan(BUDGET_MS);
  });

  // The fixed lowercase-and-digit alphabet cannot see these: a literal prefix
  // (`ghp_`, `eyJ`) gates the catastrophic tail, or the vulnerable class is
  // uppercase-only (`[B-Z]`). They are the exact shape the real secret rules in
  // this repo use, and each one runs for seconds on a tailored input — past the
  // hook's 10s timeout for the JWT case. `derivedProbes` is what closes them.
  it.each([
    ['github-PAT-shaped literal prefix', 'ghp_([A-Za-z0-9]+)+$'],
    ['AWS-key-shaped literal prefix', 'AKIA([A-Z0-9]+)+$'],
    ['uppercase-only class, no prefix', '\\b([B-Z]+)+#'],
    ['JWT-shaped literal prefix', 'eyJ([A-Za-z0-9_-]+)+\\.'],
  ])('catches an alphabet-specific catastrophic pattern: %s', (_label, pattern) => {
    const parsed = parseRegexRule(pattern);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(worstProbeMs(parsed.data).ms).toBeGreaterThan(BUDGET_MS);
  });

  it('the fixed alphabet alone would miss the alphabet-specific patterns', () => {
    // Pins WHY the per-rule derivation is load-bearing: without it, a
    // github-PAT-shaped rule sails through in microseconds. If a refactor makes
    // the fixed probes somehow cover these, this test fails loudly and the
    // derivation can be reconsidered — it should not silently become redundant.
    const parsed = parseRegexRule('ghp_([A-Za-z0-9]+)+$');
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    let worstFixed = 0;
    for (const text of [...EXPONENTIAL_PROBES, ...POLYNOMIAL_PROBES]) {
      const start = performance.now();
      scan(text, [parsed.data]);
      worstFixed = Math.max(worstFixed, performance.now() - start);
    }
    expect(worstFixed).toBeLessThan(BUDGET_MS);
  });
});
