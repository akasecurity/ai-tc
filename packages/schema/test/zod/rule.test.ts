import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  PostValidatorName,
  RegexMatcher,
  Rule,
  RuleFixture,
  RuleProbeVerdict,
} from '../../src/zod/rule.ts';

// What a rejection actually SAYS, joined for assertion. Every test below checks
// the wording as well as the refusal: a rule author who gets `success: false`
// and no usable reason is in the same position these checks exist to fix, and a
// bare `success === false` would pass just as happily against a schema that
// rejected everything.
function reasons(result: { success: boolean; error?: { issues: { message: string }[] } }): string {
  return (result.error?.issues ?? []).map((i) => i.message).join(' | ');
}

// The key each issue points at, for the cases whose message names only the
// constraint ("Too small", "Invalid option") and not the field.
function issuePaths(result: {
  success: boolean;
  error?: { issues: { path: PropertyKey[] }[] };
}): string {
  return (result.error?.issues ?? []).map((i) => i.path.map(String).join('.')).join(' | ');
}

function keywordRule(matcher: Record<string, unknown>) {
  return {
    specVersion: 1,
    id: 'test-pack/test-rule',
    name: 'test',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'keyword', ...matcher },
  };
}

describe('Rule keyword matcher contract', () => {
  it('accepts a keyword rule and defaults caseSensitive to false', () => {
    const parsed = Rule.parse(keywordRule({ keywords: ['password'] }));
    expect(parsed.matcher).toEqual({
      type: 'keyword',
      keywords: ['password'],
      caseSensitive: false,
    });
  });

  it('rejects an empty keyword', () => {
    // An empty keyword matches at every position; the KeywordMatcher has no
    // per-rule match ceiling, so a large input would allocate a span per byte.
    expect(Rule.safeParse(keywordRule({ keywords: [''] })).success).toBe(false);
    expect(Rule.safeParse(keywordRule({ keywords: ['password', ''] })).success).toBe(false);
  });

  it('rejects an empty keyword list', () => {
    expect(Rule.safeParse(keywordRule({ keywords: [] })).success).toBe(false);
  });

  it('accepts keywords containing regex metacharacters', () => {
    // Bundled rules ship these verbatim — core-code-context/db-table-name has
    // "SELECT * FROM ", core-financial/salary has "i make $". The matcher
    // escapes them; the schema must not reject them.
    const parsed = Rule.parse(
      keywordRule({ keywords: ['SELECT * FROM ', 'SELECT COUNT(*) FROM ', 'i make $'] }),
    );
    expect(parsed.matcher.type).toBe('keyword');
  });
});

function regexRule(pattern: string) {
  return {
    specVersion: 1,
    id: 'test-pack/test-rule',
    name: 'test',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern, flags: 'g' },
  };
}

describe('Rule regex matcher contract', () => {
  it('rejects an empty pattern', () => {
    expect(Rule.safeParse(regexRule('')).success).toBe(false);
  });

  it('accepts a pattern at the length ceiling', () => {
    // The longest bundled pattern is ~650 chars (a multi-alternative
    // cloud-connection-string rule); 2000 is the schema's cap.
    const parsed = Rule.safeParse(regexRule('a'.repeat(2000)));
    expect(parsed.success).toBe(true);
  });

  it('rejects a pattern past the length ceiling', () => {
    // An unbounded `pattern` string lets a caller submit an absurdly long
    // regex to any endpoint that validates through this schema (e.g. a
    // rule-testing API); capping it here rejects that at the contract
    // boundary regardless of what validates patterns downstream.
    const parsed = Rule.safeParse(regexRule('a'.repeat(2001)));
    expect(parsed.success).toBe(false);
  });
});

// A minimal well-formed rule, used as the base every footgun case perturbs by
// exactly one field — so a rejection below can only be the perturbation.
function validRule(extra: Record<string, unknown> = {}) {
  return {
    specVersion: 1,
    id: 'test-pack/test-rule',
    name: 'test',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: '(\\d{3})-(\\d{2})', flags: 'g' },
    ...extra,
  };
}

// Footgun 1. A stripped key is worse than a rejected one: the rule parses,
// loads and fires, with whatever the key configured simply absent. Every object
// in the tree is checked, not just the top one — `capture_group` inside
// `matcher` and `windowChar` inside `requiresNearby` are the same mistake one
// level down, and the object they sit in is the only thing that can catch them.
describe('Rule rejects unrecognized keys at every level', () => {
  it('accepts a rule that uses every optional field it declares', () => {
    // The positive control for this whole describe. Without it, a schema that
    // rejected every input would satisfy all six cases below.
    const parsed = Rule.safeParse(
      validRule({
        matcher: { type: 'regex', pattern: 'key=(\\w+)', flags: 'g', captureGroup: 1 },
        appliesTo: { extensions: ['.py'] },
        postValidators: ['entropy', { name: 'luhn', config: { threshold: 4 } }],
        requiresNearby: { labels: ['secret'], windowChars: 40, confidenceBoost: 0.1 },
        examples: ['key=abc123'],
      }),
    );
    expect(reasons(parsed)).toBe('');
    expect(parsed.success).toBe(true);
  });

  it('rejects a singular postValidator typo instead of silently dropping it', () => {
    // The motivating case: `postValidator` for `postValidators` parsed fine and
    // vanished, so the rule shipped with its false-positive guard absent.
    const parsed = Rule.safeParse(validRule({ postValidator: ['luhn'] }));
    expect(reasons(parsed)).toContain('postValidator');
    expect(parsed.success).toBe(false);
  });

  it('rejects an unknown key inside matcher', () => {
    // `matcher` is also what the isolation boundary partitions on
    // (`matcher.type`), so a key stripped here is not only a lost setting.
    const parsed = Rule.safeParse(
      validRule({ matcher: { type: 'regex', pattern: '(\\d+)', capture_group: 1 } }),
    );
    expect(reasons(parsed)).toContain('capture_group');
    expect(parsed.success).toBe(false);
  });

  it('rejects an unknown key inside requiresNearby', () => {
    // `windowChars` has a default, so the typo'd form used to leave the gate
    // running at 160 chars while the author believed they had narrowed it.
    const parsed = Rule.safeParse(
      validRule({ requiresNearby: { labels: ['secret'], windowChar: 40 } }),
    );
    expect(reasons(parsed)).toContain('windowChar');
    expect(parsed.success).toBe(false);
  });

  it('rejects an empty appliesTo', () => {
    const parsed = Rule.safeParse(validRule({ appliesTo: {} }));
    expect(parsed.success).toBe(false);
  });

  // Both lists are `.min(1)`: an empty list would scope the rule to nothing
  // and switch it off without saying so.
  it('rejects an empty appliesTo.eventKinds', () => {
    const parsed = Rule.safeParse(validRule({ appliesTo: { eventKinds: [] } }));
    expect(issuePaths(parsed)).toContain('appliesTo.eventKinds');
    expect(parsed.success).toBe(false);
  });

  it('rejects an empty appliesTo.extensions', () => {
    const parsed = Rule.safeParse(validRule({ appliesTo: { extensions: [] } }));
    expect(issuePaths(parsed)).toContain('appliesTo.extensions');
    expect(parsed.success).toBe(false);
  });

  it('rejects an empty list even beside a valid one', () => {
    expect(
      Rule.safeParse(validRule({ appliesTo: { eventKinds: ['tool_use'], extensions: [] } }))
        .success,
    ).toBe(false);
    expect(
      Rule.safeParse(validRule({ appliesTo: { eventKinds: [], extensions: ['.sh'] } })).success,
    ).toBe(false);
  });

  it('accepts appliesTo with eventKinds alone', () => {
    expect(Rule.safeParse(validRule({ appliesTo: { eventKinds: ['tool_use'] } })).success).toBe(
      true,
    );
  });

  it('rejects an unknown capture kind in appliesTo.eventKinds', () => {
    expect(Rule.safeParse(validRule({ appliesTo: { eventKinds: ['bash'] } })).success).toBe(false);
  });

  it('rejects an unknown key inside appliesTo', () => {
    const parsed = Rule.safeParse(
      validRule({ appliesTo: { extensions: ['.py'], extension: ['.ts'] } }),
    );
    expect(reasons(parsed)).toContain('extension');
    expect(parsed.success).toBe(false);
  });

  it('rejects an unknown key inside a keyword matcher', () => {
    const parsed = Rule.safeParse(
      validRule({ matcher: { type: 'keyword', keywords: ['secret'], caseSensitve: true } }),
    );
    expect(reasons(parsed)).toContain('caseSensitve');
    expect(parsed.success).toBe(false);
  });

  it('rejects an unknown key in a fixture, including inside expectedSpans', () => {
    // A fixture's `expectedSpans` is itself a guard — it pins which characters
    // the finding covers — so `expectedSpan` silently vanishing is the same
    // class of defect one file over.
    const valid = RuleFixture.safeParse({
      label: 'l',
      text: 't',
      shouldMatch: true,
      expectedSpans: [{ start: 0, end: 1 }],
    });
    expect(valid.success).toBe(true);

    const singular = RuleFixture.safeParse({
      label: 'l',
      text: 't',
      shouldMatch: true,
      expectedSpan: [{ start: 0, end: 1 }],
    });
    expect(reasons(singular)).toContain('expectedSpan');
    expect(singular.success).toBe(false);

    const inSpan = RuleFixture.safeParse({
      label: 'l',
      text: 't',
      shouldMatch: true,
      expectedSpans: [{ start: 0, end: 1, ends: 2 }],
    });
    expect(reasons(inSpan)).toContain('ends');
    expect(inSpan.success).toBe(false);
  });

  it('accepts a fixture expectedVariableName as a name or null', () => {
    const base = { label: 'l', text: 't', shouldMatch: true };
    expect(RuleFixture.safeParse({ ...base, expectedVariableName: 'API_KEY' }).success).toBe(true);
    expect(RuleFixture.safeParse({ ...base, expectedVariableName: null }).success).toBe(true);
    expect(RuleFixture.safeParse({ ...base, expectedVariableName: 1 }).success).toBe(false);
  });

  it('accepts a fixture eventKind only when it is an EventKind', () => {
    const base = { label: 'l', text: 't', shouldMatch: true };
    for (const eventKind of ['prompt', 'response', 'code_change', 'tool_use']) {
      expect(RuleFixture.safeParse({ ...base, eventKind }).success).toBe(true);
    }

    // A typo here would scan the fixture under no kind, so a scoped rule's
    // positive would fail for a reason the author never sees.
    for (const eventKind of ['tool-use', 'bash', 'TOOL_USE', '']) {
      const parsed = RuleFixture.safeParse({ ...base, eventKind });
      expect(issuePaths(parsed)).toBe('eventKind');
      expect(parsed.success).toBe(false);
    }
  });
});

// Footgun 2. A post-validator is a false-positive guard, so an unrecognized
// name used to leave the rule firing with the check absent — noise that reads
// as the rule working. The engine keys its table on PostValidatorName, so this
// enum is the same list the engine implements, by construction.
describe('Rule rejects a validator matcher', () => {
  // A matcher PRODUCES candidate spans; a checksum can only filter spans
  // something else found. `validator` was a third arm of the union that nothing
  // implemented, so a rule declaring one parsed, loaded and then matched nothing
  // at all — the same footgun as an unimplemented post-validator name, and
  // indistinguishable from a pattern that legitimately found no secrets.
  it('refuses the matcher form of every validator name, including implemented ones', () => {
    // `luhn` and `entropy` ARE implemented as post-validators, which is exactly
    // what made the matcher form read as legitimate. The name existing is not
    // the point — there is no matcher behind any of them.
    for (const name of ['luhn', 'entropy', 'ssn-checksum']) {
      const parsed = Rule.safeParse(validRule({ matcher: { type: 'validator', name } }));
      expect(parsed.success).toBe(false);
    }
  });

  it('still accepts the two matcher kinds the engine implements', () => {
    // The positive control: without it a schema rejecting every matcher would
    // satisfy the case above.
    expect(
      Rule.safeParse(validRule({ matcher: { type: 'regex', pattern: 'x', flags: 'g' } })).success,
    ).toBe(true);
    expect(
      Rule.safeParse(
        validRule({ matcher: { type: 'keyword', keywords: ['a'], caseSensitive: false } }),
      ).success,
    ).toBe(true);
  });
});

describe('Rule rejects an unknown post-validator name', () => {
  it('accepts every name the engine implements, bare and in object form', () => {
    for (const name of PostValidatorName.options) {
      expect(Rule.safeParse(validRule({ postValidators: [name] })).success).toBe(true);
      expect(Rule.safeParse(validRule({ postValidators: [{ name }] })).success).toBe(true);
    }
  });

  it('rejects a name the engine does not implement', () => {
    // `ssn-checksum` is the sharpest case: it names a real checksum, so it reads
    // as legitimate — but nothing implements it as a post-validator, so
    // referencing it here was always a no-op.
    const parsed = Rule.safeParse(validRule({ postValidators: ['ssn-checksum'] }));
    expect(reasons(parsed)).toContain('not a valid post-validator');
    expect(parsed.success).toBe(false);
  });

  it('rejects a name that differs only in case', () => {
    const parsed = Rule.safeParse(validRule({ postValidators: ['Luhn'] }));
    expect(reasons(parsed)).toContain('not a valid post-validator');
    expect(parsed.success).toBe(false);
  });

  it('rejects an unknown name in the object form too', () => {
    const parsed = Rule.safeParse(validRule({ postValidators: [{ name: 'does-not-exist' }] }));
    expect(reasons(parsed)).toContain('not a valid post-validator');
    expect(parsed.success).toBe(false);
  });

  it('names the implemented validators in the refusal', () => {
    // The refusal has to be actionable, not merely correct — Zod's own union
    // error is "Invalid input", which leaves the author exactly where they
    // started. The list is derived from the enum, so it cannot go stale.
    const message = reasons(Rule.safeParse(validRule({ postValidators: ['nope'] })));
    for (const name of PostValidatorName.options) expect(message).toContain(name);
  });
});

// Footgun 3. `m[9]` on a one-group pattern is `undefined`, so the matcher
// records no span and the rule never fires — silently, and identically to a
// rule whose pattern simply did not match.
describe('Rule validates captureGroup against the pattern group count', () => {
  function regexMatcher(matcher: Record<string, unknown>) {
    return Rule.safeParse(
      validRule({
        matcher: { type: 'regex', pattern: '(\\d{3})-(\\d{2})', flags: 'g', ...matcher },
      }),
    );
  }

  it('accepts every group index the pattern actually declares', () => {
    // Group 0 is the whole match, so a 2-group pattern accepts 0, 1 and 2.
    for (const captureGroup of [0, 1, 2]) {
      expect(regexMatcher({ captureGroup }).success, `captureGroup ${String(captureGroup)}`).toBe(
        true,
      );
    }
  });

  it('rejects a group index one past the last group', () => {
    const parsed = regexMatcher({ captureGroup: 3 });
    expect(reasons(parsed)).toContain('out of range');
    expect(parsed.success).toBe(false);
  });

  it('rejects a group index far past the last group', () => {
    const parsed = regexMatcher({ captureGroup: 9 });
    expect(reasons(parsed)).toContain('out of range');
    expect(parsed.success).toBe(false);
  });

  it('rejects any capture group on a pattern that declares none', () => {
    const parsed = Rule.safeParse(
      validRule({ matcher: { type: 'regex', pattern: 'AKIA[A-Z0-9]{16}', captureGroup: 1 } }),
    );
    expect(reasons(parsed)).toContain('out of range');
    expect(parsed.success).toBe(false);
  });

  it('reports the pattern real group count so the author can correct it', () => {
    expect(reasons(regexMatcher({ captureGroup: 7 }))).toContain('declares 2 capture group(s)');
  });

  it('counts only capturing groups — not lookarounds or non-capturing groups', () => {
    // These are exactly what an author miscounts, so the count has to agree
    // with what the regex engine will hand the matcher at index time.
    const counted = (pattern: string, captureGroup: number) =>
      Rule.safeParse(validRule({ matcher: { type: 'regex', pattern, flags: 'g', captureGroup } }))
        .success;
    expect(counted('(?:a)(b)', 1)).toBe(true);
    expect(counted('(?:a)(b)', 2)).toBe(false);
    expect(counted('(?=a)(b)', 1)).toBe(true);
    expect(counted('(?=a)(b)', 2)).toBe(false);
    // A named group is a capturing group and is counted as one.
    expect(counted('(?<value>a)', 1)).toBe(true);
    expect(counted('(?<value>a)', 2)).toBe(false);
    // Alternation does not multiply the count.
    expect(counted('(a)|(b)', 2)).toBe(true);
    expect(counted('(a)|(b)', 3)).toBe(false);
  });

  it('reports only the invalid pattern when the group count cannot be taken', () => {
    // An invalid pattern cannot be counted either, so the captureGroup check
    // has no count to compare against and must add nothing of its own.
    const parsed = RegexMatcher.safeParse({
      type: 'regex',
      pattern: '(',
      flags: 'g',
      captureGroup: 1,
    });
    expect(parsed.success).toBe(false);
    expect(issuePaths(parsed)).toBe('pattern');
    expect(reasons(parsed)).toBe('pattern/flags do not form a valid JavaScript regular expression');
    expect(reasons(parsed)).not.toContain('out of range');
  });

  it('holds captureGroup 0 to the whole-match empty-string rule', () => {
    // Group 0 IS the whole match, so `captureGroup: 0` means exactly what
    // omitting the field means — and used to sidestep the empty-string guard
    // purely by being present.
    expect(Rule.safeParse(validRule({ matcher: { type: 'regex', pattern: '\\d*' } })).success).toBe(
      false,
    );
    const withGroupZero = Rule.safeParse(
      validRule({ matcher: { type: 'regex', pattern: '\\d*', captureGroup: 0 } }),
    );
    expect(reasons(withGroupZero)).toContain('empty string');
    expect(withGroupZero.success).toBe(false);
    // A real capture still may quantify freely — the overall match advances.
    expect(
      Rule.safeParse(
        validRule({ matcher: { type: 'regex', pattern: 'key=(\\w*)', captureGroup: 1 } }),
      ).success,
    ).toBe(true);
  });
});

describe('RuleProbeVerdict', () => {
  it('accepts safe and quarantined', () => {
    expect(RuleProbeVerdict.safeParse('safe').success).toBe(true);
    expect(RuleProbeVerdict.safeParse('quarantined').success).toBe(true);
  });

  it('rejects any other value', () => {
    expect(RuleProbeVerdict.safeParse('unknown').success).toBe(false);
    expect(RuleProbeVerdict.safeParse('').success).toBe(false);
  });
});

describe('Rule.evidence', () => {
  it('accepts code or value, and is optional', () => {
    expect(Rule.safeParse(validRule()).success).toBe(true);
    expect(Rule.safeParse(validRule({ evidence: 'code' })).success).toBe(true);
    expect(Rule.safeParse(validRule({ evidence: 'value' })).success).toBe(true);
  });

  it('refuses any other evidence', () => {
    expect(Rule.safeParse(validRule({ evidence: 'snippet' })).success).toBe(false);
  });
});

// Each regex probe's answer is kept per pattern and flags for the life of the
// process, so a rule parsed a second time reuses it. These pin that the reuse
// happens, and that a reused answer is the right one: a repeated parse refuses
// what the first refused, and no pattern/flags pair is mistaken for another
// that spells the same text.
describe('Rule regex probes answer the same on a repeated parse', () => {
  const matcher = (m: Record<string, unknown>) => Rule.safeParse(validRule({ matcher: m }));

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('refuses an invalid, an empty-matching and an out-of-range rule every time', () => {
    for (let pass = 0; pass < 2; pass++) {
      expect(
        matcher({ type: 'regex', pattern: '(', flags: 'g' }).success,
        `pass ${String(pass)}`,
      ).toBe(false);
      expect(
        matcher({ type: 'regex', pattern: '\\d*', flags: 'g' }).success,
        `pass ${String(pass)}`,
      ).toBe(false);
      expect(
        matcher({ type: 'regex', pattern: 'a(b)', flags: 'g', captureGroup: 2 }).success,
        `pass ${String(pass)}`,
      ).toBe(false);
      expect(matcher({ type: 'regex', pattern: 'a(b)', flags: 'g', captureGroup: 1 }).success).toBe(
        true,
      );
    }
  });

  it('builds each probe once and reuses it on a later parse', () => {
    // Counts the RegExp objects built from one pattern no other case uses, so
    // the count is this case's own. A second parse that rebuilt its probes
    // would answer the same, which is why the count is what is asserted.
    const marker = 'memo-probe-marker';
    let built = 0;
    vi.stubGlobal(
      'RegExp',
      new Proxy(RegExp, {
        construct(target, args: [string | RegExp, string?]) {
          if (String(args[0]).includes(marker)) built += 1;
          return Reflect.construct<[string | RegExp, string?], RegExp>(target, args);
        },
      }),
    );
    const rule = { type: 'regex', pattern: `${marker}(\\w+)`, flags: 'g', captureGroup: 1 };

    expect(matcher(rule).success).toBe(true);
    const firstParse = built;
    expect(firstParse).toBeGreaterThan(0);

    expect(matcher(rule).success).toBe(true);
    expect(built).toBe(firstParse);
  });

  it('keeps flags and pattern apart', () => {
    // `x` is an invalid flag, so the first is refused; the second spells the
    // same characters with the boundary moved and is a valid rule. A key that
    // only concatenated the two would hand one the other's verdict.
    expect(matcher({ type: 'regex', pattern: 'yz', flags: 'gx' }).success).toBe(false);
    expect(matcher({ type: 'regex', pattern: 'xyz', flags: 'g' }).success).toBe(true);
    expect(matcher({ type: 'regex', pattern: 'yz', flags: 'gx' }).success).toBe(false);
  });
});
