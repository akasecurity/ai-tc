import { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../../src/index.ts';
import {
  backtrackRatio,
  BUDGET_MS,
  CATASTROPHIC_RATIO,
  EXPONENTIAL_PROBES,
  POLYNOMIAL_PROBES,
  worstProbeMs,
} from '../../src/security/redos-probe.ts';
import { discoverBundledRuleFiles, loadRule } from '../helpers/rules.ts';

// scan() is synchronous and runs on the hook path. A rule that backtracks
// catastrophically cannot be interrupted — the fail-open catch in the plugin
// runtime only catches throws, and a hook killed at its 10s timeout fails open,
// letting the call through UNSCANNED. So a slow rule is a detection bypass, not
// just a stall.
//
// SCOPE. This gate binds the rules in this repository only, and within them it
// proves "no bundled rule backtracks on the inputs the battery constructs" —
// not "no bundled rule can ReDoS at all". The probe battery
// (packages/detections/src/security/redos-probe.ts) mixes a FIXED
// lowercase-and-digit alphabet with per-rule DERIVED probes built from each
// pattern's own literal prefix and character classes, so a rule gated behind a
// literal like `ghp_(...)+$` is actually exercised past its prefix on its own
// alphabet. Residual gaps, all documented rather than silently covered:
// backtracking that needs a literal (non-class) character the pattern
// repeats; polynomial blowup reachable only on a non-lowercase alphabet (the
// fixed polynomial tier is lowercase-and-digit); and any rule that arrives at
// runtime from a pulled or custom pack, which this suite never sees — that
// path has its own runtime gate, built on this same battery.

const bundled = discoverBundledRuleFiles().map(({ packDirAbs, ruleFile }) =>
  loadRule(packDirAbs, ruleFile),
);

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
  // Each case proves the battery drives a catastrophic pattern to backtrack far
  // past ordinary input by asserting a RATIO — worst probe time over a
  // same-length benign baseline on the same machine — not an absolute
  // millisecond threshold. Wall-clock ms shifts with hardware and CPU load, and
  // which pattern sits closest to a fixed line shifts with it; the ratio does
  // not, because both measurements move together.
  //
  // A pattern belongs here only if `worstProbeMs` crosses BUDGET_MS on an early
  // SHORT probe. That first over-budget probe runs to completion, so its cost
  // must stay well under the vitest timeout: `(.*a){20}$` costs ~1.2s on one
  // machine and over 5s on the Windows runner, where it exceeded the timeout. It
  // proved nothing the cases below do not, so it is not worth a multi-second
  // probe. Add a pattern here only after checking what its first matching probe
  // costs.
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
    const { ratio, ms, benignMs } = backtrackRatio(parsed.data);
    expect(
      ratio,
      `worst probe ran ${ms.toFixed(1)}ms vs a ${benignMs.toFixed(3)}ms same-length ` +
        `baseline (ratio ${ratio.toFixed(0)}×); the probe battery should drive this ` +
        `pattern to backtrack orders of magnitude past ordinary input.`,
    ).toBeGreaterThan(CATASTROPHIC_RATIO);
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
    const { ratio, ms, benignMs } = backtrackRatio(parsed.data);
    expect(
      ratio,
      `worst probe ran ${ms.toFixed(1)}ms vs a ${benignMs.toFixed(3)}ms same-length ` +
        `baseline (ratio ${ratio.toFixed(0)}×); the probe battery should drive this ` +
        `pattern to backtrack orders of magnitude past ordinary input.`,
    ).toBeGreaterThan(CATASTROPHIC_RATIO);
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
