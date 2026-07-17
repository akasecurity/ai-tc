import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../../src/index.ts';

// scan() is synchronous and runs on the hook path. A rule that backtracks
// catastrophically cannot be interrupted — the fail-open catch in the plugin
// runtime only catches throws, and a hook killed at its 10s timeout fails open,
// letting the call through UNSCANNED. So a slow rule is a detection bypass, not
// just a stall.
//
// This gate binds the rules in this repository only. A rule reaching the engine
// at runtime from a pulled or custom pack is not covered by it.
const BUDGET_MS = 100;

const RULES_DIR = resolve(__dirname, '../../../../rules');

function loadBundledRules(): Rule[] {
  const rules: Rule[] = [];
  for (const packDir of readdirSync(RULES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)) {
    const manifestPath = resolve(RULES_DIR, packDir, 'manifest.json');
    if (!existsSync(manifestPath)) continue;
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8')) as { rules: string[] };
    for (const ruleFile of manifest.rules) {
      const raw: unknown = JSON.parse(
        readFileSync(resolve(RULES_DIR, packDir, `${ruleFile}.json`), 'utf-8'),
      );
      rules.push(Rule.parse(raw));
    }
  }
  return rules;
}

// Two probe tiers, because the two failure modes need opposite inputs.
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

// Exponential probes run FIRST and the walk stops at the first over-budget
// probe. Both halves of that matter: a pattern that backtracks catastrophically
// at 26 chars takes geological time on a 40KB probe, so reaching the polynomial
// tier at all would hang the run instead of failing it — for a bad rule here,
// and for the self-test below that deliberately supplies one.
const PROBES = [...EXPONENTIAL_PROBES, ...POLYNOMIAL_PROBES];

/** The slowest probe against `rule`, in ms; stops early once one blows the budget. */
function worstProbeMs(rule: Rule): { ms: number; probe: string } {
  let ms = 0;
  let probe = '';
  for (const text of PROBES) {
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

const bundled = loadBundledRules();

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
});
