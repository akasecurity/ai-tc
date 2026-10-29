// The matcher reports every offset a pattern matches at, not one tiling of them.
//
// A `g`-flag `exec` loop that lets the flag advance `lastIndex` past the whole match skips any
// occurrence overlapping one already taken. Two things make that observable. A rule with a
// `captureGroup` reports the group but consumes all of `m[0]`, so one match can swallow the text a
// later match needed in order to anchor; and the engine's post-validators run after the loop has
// already moved the cursor, so a rejected candidate does not give its characters back. The result
// is that the match set depends on the offset the scan began at, and for some inputs a scan of the
// complete text reports a strict subset of what the rule matches.
import type { Rule, Span } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { scan } from '../../src/engine.ts';
import { KeywordMatcher } from '../../src/matchers/keyword.ts';
import { RegexMatcher } from '../../src/matchers/regex.ts';
import { discoverBundledRuleFiles, loadRule } from '../helpers/rules.ts';

const RULES = discoverBundledRuleFiles().map(({ packDirAbs, ruleFile }) =>
  loadRule(packDirAbs, ruleFile),
);

/** The spans one rule reports over `text`, through the whole engine. */
function spansOf(ruleId: string, text: string): Span[] {
  return scan(text, RULES)
    .filter((finding) => finding.ruleId === ruleId)
    .map((finding) => finding.span);
}

function covers(spans: readonly Span[], at: number): boolean {
  return spans.some((span) => span.start <= at && at < span.end);
}

const PAYPAL_ID = '9HW7382910ABCDEF1';

/** The label repeated ahead of a real id, so one match's extent can swallow a later label. */
function repeatedLabel(times: number): string {
  return `${'PayPal transaction'.repeat(times)} ID: ${PAYPAL_ID}`;
}

describe('a rule whose match extent can swallow a later match’s anchor', () => {
  it.each([1, 2, 3, 4, 5, 10])(
    'reports the transaction id with the label repeated %i times',
    (times) => {
      const text = repeatedLabel(times);
      const at = text.indexOf(PAYPAL_ID);
      expect(covers(spansOf('core-financial/paypal', text), at)).toBe(true);
    },
  );

  // From 2 repetitions up: the scan's first character is cut, so the leading label is destroyed
  // and a later one has to anchor the match. That is the case a tiling can get wrong.
  it.each([2, 3, 4, 5, 10])(
    'reports it from a scan starting one character in, with the label repeated %i times',
    (times) => {
      const text = repeatedLabel(times);
      const at = text.indexOf(PAYPAL_ID);
      const shifted = spansOf('core-financial/paypal', text.slice(1)).map((span) => ({
        start: span.start + 1,
        end: span.end + 1,
      }));
      expect(covers(shifted, at)).toBe(true);
    },
  );

  it('reports nothing when the scan cuts into the only label the id has', () => {
    // Not a tiling question: one label, and the scan starts inside it, so the rule has no anchor
    // left. Pinned so the case above is not read as a claim about every starting offset.
    const text = repeatedLabel(1);
    expect(spansOf('core-financial/paypal', text.slice(1))).toEqual([]);
  });

  it('tiles a repeating run the same way from either offset', () => {
    const text = `0.0${'.0'.repeat(10)}`;
    const whole = spansOf('core-code-context/localhost-ref', text);
    const shifted = spansOf('core-code-context/localhost-ref', text.slice(2)).map((span) => ({
      start: span.start + 2,
      end: span.end + 2,
    }));
    // Every character the whole-text scan covers is covered by the shifted scan too, so no value
    // is reachable from one starting offset and not the other.
    for (const span of whole) {
      for (let i = span.start; i < span.end; i += 1) {
        if (i < 2) continue;
        expect(covers(shifted, i), `offset ${String(i)}`).toBe(true);
      }
    }
  });
});

describe('RegexMatcher enumerates overlapping occurrences', () => {
  it('reports both occurrences of a self-overlapping pattern', () => {
    const rule: Rule = {
      specVersion: 1,
      id: 'test/overlap',
      name: 'overlap',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: 'aba', flags: 'g' },
    };
    // 'ababa' holds 'aba' at 0 and at 2; the second starts inside the first.
    expect(new RegexMatcher().match('ababa', rule)).toEqual([
      { start: 0, end: 3 },
      { start: 2, end: 5 },
    ]);
  });

  it('still advances past a zero-length match', () => {
    const rule: Rule = {
      specVersion: 1,
      id: 'test/empty',
      name: 'empty',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: 'x*', flags: 'g' },
    };
    expect(new RegexMatcher().match('ab', rule)).toEqual([]);
  });

  it('skips a shorter reading of the match just taken', () => {
    const rule: Rule = {
      specVersion: 1,
      id: 'test/suffix',
      name: 'suffix',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: '[0-9]+', flags: 'g' },
    };
    // "23" and "3" are suffixes of "123", not separate occurrences of it.
    expect(new RegexMatcher().match('abc123', rule)).toEqual([{ start: 3, end: 6 }]);
  });

  it('reports a captured group at its own offset for each overlapping match', () => {
    const rule: Rule = {
      specVersion: 1,
      id: 'test/group',
      name: 'group',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'regex', pattern: 'a(b+)a', flags: 'g', captureGroup: 1 },
    };
    expect(new RegexMatcher().match('ababa', rule)).toEqual([
      { start: 1, end: 2 },
      { start: 3, end: 4 },
    ]);
  });
});

describe('a keyword rule keeps the `g`-advance, and why that is not the same case', () => {
  it('reports the leading occurrence of a self-bordering keyword only', () => {
    const rule: Rule = {
      specVersion: 1,
      id: 'test/keyword',
      name: 'keyword',
      category: 'custom',
      severity: 'low',
      matcher: { type: 'keyword', keywords: ['todo-secret'], caseSensitive: false },
    };
    // A keyword's span IS the literal, so the occurrence this drops leaves behind a substring of
    // the keyword itself rather than a value — the opposite of a regex rule, whose dropped match
    // hides its own captured value. `keyword.test.ts` holds the decision; this pins that the regex
    // change above did not reach the keyword walk.
    expect(new KeywordMatcher().match('todo-secretodo-secret', rule)).toEqual([
      { start: 0, end: 11 },
    ]);
  });
});
