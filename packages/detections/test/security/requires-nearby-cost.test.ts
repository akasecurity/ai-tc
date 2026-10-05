import { resolve } from 'node:path';

import { describe, expect, it, vi } from 'vitest';

import type * as FormatChars from '../../src/format-chars.ts';
import { scan } from '../../src/index.ts';
import { SOFT_HYPHEN, ZWSP } from '../helpers/format-chars.ts';
import { loadRule, RULES_DIR } from '../helpers/rules.ts';

// COUNTED, not timed (see the CLAUDE.md note on fixed wall-clock ceilings): the
// proximity gate must map a candidate into normalized coordinates once per
// candidate, never once per pair of candidates. The count is taken by wrapping
// the one function that does the mapping, with the real implementation still
// running, so no production code carries a counter and the assertion cannot
// drift from what the engine actually calls.
const calls = vi.hoisted(() => ({ mapToNormalized: 0 }));

vi.mock('../../src/format-chars.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof FormatChars>();
  return {
    ...actual,
    mapSpanToNormalized: (...args: Parameters<typeof actual.mapSpanToNormalized>) => {
      calls.mapToNormalized++;
      return actual.mapSpanToNormalized(...args);
    },
  };
});

const zip = loadRule(resolve(RULES_DIR, 'core-pii'), 'zip');
const dob = loadRule(resolve(RULES_DIR, 'core-pii'), 'dob');
const email = loadRule(resolve(RULES_DIR, 'core-pii'), 'email');

describe('the proximity gate maps each candidate into normalized coordinates once', () => {
  it('does O(n) mappings, not O(n^2), when nothing is relevant to anything else', () => {
    // N five-digit values, each followed by a soft hyphen (a \p{Cf} character an
    // HTML export leaves behind). Every value is a gated ZIP candidate, and none
    // has a home-address or an address label near it, so every pair is irrelevant.
    const N = 300;
    const text = Array.from({ length: N }, (_, i) => `${String(10000 + i)}${SOFT_HYPHEN}, `).join(
      '',
    );

    calls.mapToNormalized = 0;
    expect(scan(text, [zip])).toEqual([]);

    // One mapping per original-pass candidate; a normalized-pass candidate is
    // already in normalized coordinates and needs none. Per-pair mapping would
    // be on the order of N * N = 90,000.
    expect(calls.mapToNormalized).toBe(N);
  });

  it('stays O(n) when every candidate IS relevant to many others', () => {
    // Alternating emails and dates: each date's category corroborator is in
    // reach of several emails, so the pair loop does real distance work, and
    // that work must still not call the mapping.
    const N = 150;
    const text = Array.from(
      { length: N },
      (_, i) => `user${String(i)}@example.com ${ZWSP}1984-03-${String(10 + (i % 18))} `,
    ).join('');

    calls.mapToNormalized = 0;
    const findings = scan(text, [dob, email]);

    expect(findings.filter((f) => f.ruleId === 'core-pii/dob')).toHaveLength(N);
    // Exactly one mapping per candidate: two rules, N occurrences each.
    expect(calls.mapToNormalized).toBe(2 * N);
  });
});
