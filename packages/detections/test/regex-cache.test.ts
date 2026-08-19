import type { Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../src/engine.ts';
import { KeywordMatcher } from '../src/matchers/keyword.ts';
import { MAX_MATCHES_PER_RULE } from '../src/matchers/limits.ts';
import { RegexMatcher } from '../src/matchers/regex.ts';
import { memoizedRegExp, memoizedRegExpList } from '../src/regex-cache.ts';
import { discoverBundledRuleFiles, loadRule } from './helpers/rules.ts';

// Plain objects rather than Rule.parse(), matching the matcher suites: the cache
// sits under the matchers and must behave for any pattern that reaches it,
// including flag combinations the schema does not mint.
function regexRule(pattern: string, flags: string): Rule {
  return {
    specVersion: 1,
    id: 'test-pack/test-rule',
    name: 'test',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'regex', pattern, flags },
  };
}

function keywordRule(keywords: string[]): Rule {
  return {
    specVersion: 1,
    id: 'test-pack/kw-rule',
    name: 'test',
    category: 'custom',
    severity: 'low',
    matcher: { type: 'keyword', keywords, caseSensitive: false },
  };
}

describe('memoizedRegExp — identity keying', () => {
  it('builds once per owner and returns the same object after', () => {
    const owner = {};
    let builds = 0;
    const build = (): RegExp => {
      builds++;
      return new RegExp('memo-identity');
    };
    const first = memoizedRegExp(owner, build);
    expect(memoizedRegExp(owner, build)).toBe(first);
    expect(builds).toBe(1);
  });

  // Identity, not pattern text. Two rules carrying the same pattern compile
  // separately — the trade that buys the lookup its speed, and the reason
  // nothing here hashes a pattern string.
  it('keeps separate entries for separate owners of an identical pattern', () => {
    const a = memoizedRegExp({}, () => new RegExp('memo-same-text'));
    const b = memoizedRegExp({}, () => new RegExp('memo-same-text'));
    expect(b).not.toBe(a);
    expect(b.source).toBe(a.source);
  });

  it('records nothing when the builder throws', () => {
    const owner = {};
    expect(() =>
      memoizedRegExp(owner, () => {
        throw new Error('bad pattern');
      }),
    ).toThrow('bad pattern');
    // A recorded failure would make the retry return undefined instead of
    // building, so a successful second attempt is what shows nothing was stored.
    expect(memoizedRegExp(owner, () => new RegExp('memo-after-throw')).source).toBe(
      'memo-after-throw',
    );
  });

  it('builds a list once per owner', () => {
    const owner = {};
    let builds = 0;
    const build = (): RegExp[] => {
      builds++;
      return [new RegExp('memo-list-a'), new RegExp('memo-list-b')];
    };
    const first = memoizedRegExpList('keyword', owner, build);
    expect(memoizedRegExpList('keyword', owner, build)).toBe(first);
    expect(builds).toBe(1);
  });

  // The two list caches are keyed by different objects — a rule's `matcher` and
  // its `requiresNearby` — so one shared keyspace would hand a label lookup the
  // keyword list belonging to the same owner, and corroborate against keyword
  // patterns instead of labels.
  it('keeps the keyword and label caches apart for one owner', () => {
    const owner = {};
    const keywords = memoizedRegExpList('keyword', owner, () => [new RegExp('memo-kw')]);
    const labels = memoizedRegExpList('label', owner, () => [new RegExp('memo-label')]);
    expect(labels).not.toBe(keywords);
    expect(keywords[0]?.source).toBe('memo-kw');
    expect(labels[0]?.source).toBe('memo-label');
  });

  // Identity stands in for the pattern text, so a matcher edited after first use
  // keeps the object compiled from the old text. Nothing enforces that — rules
  // are frozen by convention from `Rule.parse` onward — so the constraint is
  // pinned here rather than left to the header comment alone.
  it('does not notice a pattern edited in place after first use', () => {
    const rule = regexRule('memo-stale-before', 'g');
    expect(scan('memo-stale-before', [rule])).toHaveLength(1);

    // Type-safe mutation of a field the engine treats as frozen.
    (rule.matcher as { pattern: string }).pattern = 'memo-stale-after';
    expect(scan('memo-stale-after', [rule])).toHaveLength(0);
    expect(scan('memo-stale-before', [rule])).toHaveLength(1);
  });
});

describe('memoizedRegExp — the bound', () => {
  // The cache is bounded by liveness rather than by a size cap: entries are held
  // weakly, so they last exactly as long as the rule they were built for.
  //
  // Weakness has no direct observation short of driving a collection, which is
  // not something to assert on in a test suite. The refusal below is the one
  // place it does surface — a WeakMap will not take a primitive key, while a
  // plain Map takes it happily and then retains every entry for the life of the
  // process. So this case is what separates the two containers, and swapping in
  // a Map is what it exists to catch.
  it('refuses a key that cannot be held weakly', () => {
    expect(() => memoizedRegExp('a string' as unknown as object, () => /x/)).toThrow(TypeError);
    expect(() => memoizedRegExpList('keyword', 7 as unknown as object, () => [/x/])).toThrow(
      TypeError,
    );
  });
});

describe('cached regexes carry no state between calls', () => {
  // Every early exit in RegexMatcher's walk leaves a global pattern's lastIndex
  // pointing into the input it just gave up on. The cases below each drive one
  // of those exits and then re-run on a DIFFERENT input, which is where a shared
  // object without a reset silently returns nothing.

  it('finds matches on a second scan after the first hit the per-rule cap', () => {
    const rule = regexRule('a', 'g');
    const capped = scan('a'.repeat(MAX_MATCHES_PER_RULE * 2), [rule]);
    expect(capped).toHaveLength(MAX_MATCHES_PER_RULE);

    // Far shorter than the offset the capped walk stopped at, so a carried
    // lastIndex puts the search past the end of the input entirely.
    const next = scan('aaa', [rule]);
    expect(next.map((f) => f.span)).toEqual([
      { start: 0, end: 1 },
      { start: 1, end: 2 },
      { start: 2, end: 3 },
    ]);
  });

  it('finds matches on a second scan after a sticky pattern advanced lastIndex', () => {
    // A sticky pattern honours lastIndex without the 'g' flag, so the walk's
    // break-on-non-global exit leaves the object pointing at offset 1.
    const rule = regexRule('a', 'y');
    expect(scan('ab', [rule]).map((f) => f.span)).toEqual([{ start: 0, end: 1 }]);
    expect(scan('ab', [rule]).map((f) => f.span)).toEqual([{ start: 0, end: 1 }]);
  });

  it('finds keyword matches on a second scan after the first hit the per-rule cap', () => {
    const rule = keywordRule(['k']);
    const capped = scan('k'.repeat(MAX_MATCHES_PER_RULE * 2), [rule]);
    expect(capped).toHaveLength(MAX_MATCHES_PER_RULE);

    const next = scan('kk', [rule]);
    expect(next.map((f) => f.span)).toEqual([
      { start: 0, end: 1 },
      { start: 1, end: 2 },
    ]);
  });

  it('resets every entry of a list, not only the first', () => {
    // The cap is shared across a rule's keywords, so the walk can stop partway
    // through the list — and the entry it stops on is not the one it started on.
    // The fixture is built so the FIRST keyword finishes cleanly (one match,
    // well under the cap) and the SECOND is the one that breaks mid-input: a
    // reset covering only the head of the list leaves that second pattern
    // pointing past the end of the next call's text, and this rule silently
    // stops matching 'q' on every scan that follows.
    const rule = keywordRule(['p', 'q']);
    expect(scan(`p${'q'.repeat(MAX_MATCHES_PER_RULE * 2)}`, [rule])).toHaveLength(
      MAX_MATCHES_PER_RULE,
    );

    const next = scan('qp', [rule]);
    expect(next.map((f) => f.span).sort((a, b) => a.start - b.start)).toEqual([
      { start: 0, end: 1 },
      { start: 1, end: 2 },
    ]);
  });

  it('is unaffected by a caller that leaves lastIndex dirty on the shared object', () => {
    const matcher = new RegexMatcher();
    const rule = regexRule('needle', 'g');
    // Reach the very object the matcher will use and dirty it, which is what a
    // second live user of a shared regex amounts to.
    matcher.match('needle', rule);
    memoizedRegExp(rule.matcher, () => {
      throw new Error('already cached');
    }).lastIndex = 4096;
    expect(matcher.match('a needle here', rule)).toEqual([{ start: 2, end: 8 }]);
  });

  it('is unaffected by a dirty shared object in the keyword matcher', () => {
    const matcher = new KeywordMatcher();
    const rule = keywordRule(['token']);
    matcher.match('token', rule);
    const compiled = memoizedRegExpList('keyword', rule.matcher, () => {
      throw new Error('already cached');
    });
    for (const re of compiled) if (re) re.lastIndex = 4096;
    expect(matcher.match('a token here', rule)).toEqual([{ start: 2, end: 7 }]);
  });
});

describe('compiled state never rides on a rule', () => {
  // A ruleset crosses to the isolated scan's worker by structured clone, and a
  // RegExp is cloneable — lastIndex and all. So a cache hung off the rule object
  // would hand a worker a half-consumed pattern, which is the one way the main
  // thread and a worker could come to share one. Keeping the compiled object in
  // a module-scoped weak map is what rules that out, and a rule that comes back
  // from a scan unchanged is how that stays true.
  it('leaves a regex rule byte-identical after scanning', () => {
    const rule = regexRule('\\d+', 'g');
    const before = structuredClone(rule);
    scan('1 22 333', [rule]);
    expect(rule).toEqual(before);
  });

  it('leaves a keyword rule byte-identical after scanning', () => {
    const rule = keywordRule(['alpha', 'beta']);
    const before = structuredClone(rule);
    scan('alpha and beta', [rule]);
    expect(rule).toEqual(before);
  });

  it('leaves a corroborated rule byte-identical after scanning', () => {
    const rule: Rule = {
      ...regexRule('\\b[A-Z]\\d{8}\\b', 'g'),
      requiresNearby: { labels: ['passport'], windowChars: 160 },
    };
    const before = structuredClone(rule);
    scan('passport: A12345678', [rule]);
    expect(rule).toEqual(before);
  });

  it('survives a rule that crosses a structured clone, as one reaching a worker does', () => {
    const rule = regexRule('\\bcloned-\\d+\\b', 'g');
    const arrived = structuredClone(rule);
    // The clone is a different object, so it compiles its own copy — and starts
    // from a clean lastIndex however hard the original was driven first.
    scan('cloned-1 cloned-2', [rule]);
    expect(scan('cloned-9', [arrived]).map((f) => f.span)).toEqual([{ start: 0, end: 8 }]);
  });
});

describe('scan() stops recompiling its ruleset', () => {
  // Counting constructions is the only way to see the cache from outside: the
  // findings are identical either way, which is the point. RegExp is resolved
  // from the global scope at each call site, so a global stand-in sees every
  // construction the engine makes, in every module.
  function countConstructions(run: () => void): number {
    const Real = globalThis.RegExp;
    let constructions = 0;
    function Counting(this: unknown, ...args: [string, string?]): RegExp {
      constructions++;
      return new Real(...args);
    }
    Counting.prototype = Real.prototype;
    Object.setPrototypeOf(Counting, Real);
    globalThis.RegExp = Counting as unknown as RegExpConstructor;
    try {
      run();
    } finally {
      globalThis.RegExp = Real;
    }
    return constructions;
  }

  const bundled = (): Rule[] =>
    discoverBundledRuleFiles().map(({ packDirAbs, ruleFile }) => loadRule(packDirAbs, ruleFile));

  it('compiles nothing on a repeat scan of the same ruleset', () => {
    const rules = bundled();
    const text = 'the quick brown fox jumps over the lazy dog. '.repeat(48);

    // The positive control: the first scan of a ruleset nothing has compiled yet
    // must construct something, or the counter is measuring nothing and the
    // assertion below holds for a reason that has nothing to do with the cache.
    const first = countConstructions(() => void scan(text, rules));
    expect(first).toBeGreaterThan(0);

    const second = countConstructions(() => void scan(text, rules));
    expect(second).toBe(0);
  });

  it('compiles per distinct label, not per gated candidate', () => {
    // Proximity labels were compiled per label per gated candidate, so this is
    // the densest construction site in the engine. Patterns unique to this case,
    // so the first run below is genuinely cold whatever ran before it.
    const rules: Rule[] = [
      {
        ...regexRule('\\b7\\d{4}\\b', 'g'),
        requiresNearby: { labels: ['cachezip'], windowChars: 160 },
      },
    ];
    const text = 'cachezip 71234 '.repeat(2000);

    let findings = 0;
    const first = countConstructions(() => {
      findings = scan(text, rules).length;
    });

    // The scan visited the label loop once per candidate, and the count says so:
    // every one of these findings reached it and corroborated there. Two
    // constructions against that many visits is the whole claim — the same run
    // built one object per visit before, and the assertion is on the ratio
    // rather than on either number alone.
    expect(findings).toBeGreaterThan(1000);
    expect(first).toBeLessThan(10);

    const second = countConstructions(() => void scan(text, rules));
    expect(second).toBe(0);
  });

  it('compiles a fresh ruleset per call when the caller rebuilds its rules', () => {
    // The cache is keyed on the rule's own matcher, so a caller that re-parses
    // its ruleset every scan gets no reuse. That is the documented trade rather
    // than a defect, and it is worth pinning: it is what keeps the weak map
    // bounded by the rules a caller actually holds.
    const text = 'the quick brown fox. '.repeat(8);
    const first = countConstructions(() => void scan(text, bundled()));
    const second = countConstructions(() => void scan(text, bundled()));
    expect(first).toBeGreaterThan(0);
    expect(second).toBeGreaterThan(0);
  });
});
