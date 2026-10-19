import type { MatchResult } from '@akasecurity/detections';
import { describe, expect, it } from 'vitest';

import { composeAtRestContent, isScanVaultable } from '../src/at-rest-vault.ts';

const PTR = 'PTR';

function hit(text: string, needle: string, overrides: Partial<MatchResult> = {}): MatchResult {
  const start = text.indexOf(needle);
  return {
    ruleId: 'test/rule',
    category: 'secret',
    severity: 'high',
    rawMatch: needle,
    confidence: 0.9,
    span: { start, end: start + needle.length },
    ...overrides,
  };
}

describe('composeAtRestContent', () => {
  it('keeps the text as read with nothing masked or vaulted', () => {
    expect(composeAtRestContent('a b c', [], new Map())).toBe('a b c');
  });

  it('places pointers and redacts masked spans around them', () => {
    const text = 'one=AAA two=BBB three=CCC';
    const a = hit(text, 'AAA');
    const b = hit(text, 'BBB', { category: 'pii' });
    const c = hit(text, 'CCC');
    expect(
      composeAtRestContent(
        text,
        [a, b],
        new Map([
          [a, `${PTR}1`],
          [c, `${PTR}2`],
        ]),
      ),
    ).toBe(`one=${PTR}1 two=[REDACTED:PII] three=${PTR}2`);
  });

  it('redacts every vaulted span one-way when a masked span overlaps one', () => {
    const text = 'k=ABCDEF';
    const vaulted = hit(text, 'ABCDEF');
    const masked = hit(text, 'CDE', { category: 'pii' });
    expect(composeAtRestContent(text, [masked], new Map([[vaulted, PTR]]))).toBe(
      'k=[REDACTED:SECRET]',
    );
  });
});

describe('isScanVaultable', () => {
  it('vaults a secret, and nothing of another category', () => {
    expect(isScanVaultable(hit('x', 'x'))).toBe(true);
    expect(isScanVaultable(hit('x', 'x', { category: 'pii' }))).toBe(false);
  });
});
