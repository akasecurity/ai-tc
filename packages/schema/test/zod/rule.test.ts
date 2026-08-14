import { describe, expect, it } from 'vitest';

import { PostValidatorName, Rule, RuleFixture, RuleProbeVerdict } from '../../src/zod/rule.ts';

// What a rejection actually SAYS, joined for assertion. Every test below checks
// the wording as well as the refusal: a rule author who gets `success: false`
// and no usable reason is in the same position these checks exist to fix, and a
// bare `success === false` would pass just as happily against a schema that
// rejected everything.
function reasons(result: { success: boolean; error?: { issues: { message: string }[] } }): string {
  return (result.error?.issues ?? []).map((i) => i.message).join(' | ');
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
