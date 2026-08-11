/**
 * `scan()` against the bundled ruleset, on a typical prompt.
 *
 * This is the number the whole performance budget hangs off. `scan()` is
 * synchronous and runs on every hook, inside the harness's 10 s timeout — and a
 * timed-out hook FAILS OPEN, letting the tool call through unscanned. So drift
 * here does not show up as a slow editor; it shows up as detection quietly
 * switching off. That is why a trend is worth tracking at all, and why the
 * harness ships with this measurement rather than with none.
 *
 * WHAT MOVES IT. Two known algorithmic costs, neither of them a bug and neither
 * previously measured: `RegexMatcher.match` constructs a fresh `RegExp` per rule
 * per call with no cache, so the cost is O(rules × text); and `requiresNearby`
 * corroboration is quadratic in the candidates inside a window.
 *
 * WHAT IS DELIBERATELY NOT HERE. The rest of the size matrix (100 KB, 1 MB,
 * 5 MB), the rule-count scaling curve, the corroboration knee, the regex-compile
 * overhead in isolation, and the isolated-versus-in-process ratio are their own
 * benchmark against their own targets. This one exists so the harness carries a
 * real product measurement from the day it lands, on the input the budget calls
 * the common case.
 *
 * NO ASSERTIONS, and there should be none: nothing in this repository gates a PR
 * on wall-clock, and a benchmark that threw would be a timing gate wearing a
 * different name. The adversarial bound is a GUARD and lives in
 * `test/security/redos.test.ts`, where it hard-fails CI. This reports a trend.
 */
import { bench, describe } from 'vitest';

import { scan } from '../src/index.ts';
import { discoverBundledRuleFiles, loadRule } from '../test/helpers/rules.ts';

// The same discovery walk the fixtures gate and the ReDoS gate use, so this
// cannot end up measuring a different ruleset than they guard. Loaded once, at
// module scope: rule parsing is not what is being timed.
const RULES = discoverBundledRuleFiles().map(({ packDirAbs, ruleFile }) =>
  loadRule(packDirAbs, ruleFile),
);

/**
 * Roughly `chars` characters of ordinary prose, deterministic and matching no
 * rule.
 *
 * Deterministic because a benchmark whose input changes per run is comparing two
 * different workloads across a trend. Matching no rule because this repository
 * is public: no fixture here may be secret-SHAPED, not even a fake one. That
 * makes this the NO-FINDINGS path — pass 1 runs every matcher and pass 2 has
 * nothing to corroborate, which is the shape the overwhelming majority of real
 * hook invocations take.
 */
function prose(chars: number): string {
  const words = [
    'refactor',
    'the',
    'session',
    'handler',
    'so',
    'a',
    'retry',
    'never',
    'reopens',
    'store',
    'and',
    'move',
    'walk',
    'off',
    'thread',
    'before',
    'deadline',
    'returns',
  ];
  const parts: string[] = [];
  let length = 0;
  let i = 0;
  while (length < chars) {
    const word = words[i % words.length] ?? 'the';
    parts.push(word);
    length += word.length + 1;
    i += 1;
  }
  return parts.join(' ');
}

// 2 KB — the budget's "typical prompt" row.
const TYPICAL_PROMPT = prose(2_048);

describe('scan', () => {
  bench('a 2 KB prompt against the bundled ruleset', () => {
    scan(TYPICAL_PROMPT, RULES);
  });
});
