import { describe, expect, it } from 'vitest';

import { dropShieldedFindings, shieldPointers } from '../src/pointer-shield.ts';

const POINTER = `[[aka:secret:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
const SECRET = 'AKIAIOSFODNN7EXAMPLE';

describe('shieldPointers', () => {
  it('blanks pointer spans with same-length filler', () => {
    const text = `before ${POINTER} after`;
    const shielded = shieldPointers(text);
    expect(shielded.text.length).toBe(text.length);
    expect(shielded.text).toBe(`before ${' '.repeat(POINTER.length)} after`);
    expect(shielded.spans).toEqual([{ start: 7, end: 7 + POINTER.length }]);
  });

  it('keeps every non-pointer offset identical', () => {
    const text = `a ${POINTER} ${SECRET} z`;
    const shielded = shieldPointers(text);
    const secretAt = text.indexOf(SECRET);
    expect(shielded.text.slice(secretAt, secretAt + SECRET.length)).toBe(SECRET);
  });

  it('passes pointer-free text through untouched', () => {
    const shielded = shieldPointers('nothing here');
    expect(shielded.text).toBe('nothing here');
    expect(shielded.spans).toEqual([]);
  });

  it('does not blank a lookalike with an invented category', () => {
    const lookalike = `[[aka:bogus:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
    expect(shieldPointers(lookalike).spans).toEqual([]);
  });
});

describe('dropShieldedFindings', () => {
  it('drops a finding that touches a shielded span', () => {
    const findings = [
      { span: { start: 0, end: 10 } },
      { span: { start: 5, end: 25 } },
      { span: { start: 30, end: 40 } },
    ];
    expect(dropShieldedFindings(findings, [{ start: 8, end: 28 }])).toEqual([
      { span: { start: 30, end: 40 } },
    ]);
  });
});

describe('shieldPointers over sighting tokens', () => {
  const FP = 'xY_-'.repeat(10) + 'abc';
  const TOKEN = ['[[aka:fp:v', '12.', FP, ']]'].join('');

  it('blanks a sighting token like a pointer', () => {
    const text = `key ${TOKEN} and ${POINTER}.`;
    const shielded = shieldPointers(text);
    expect(shielded.text).toBe(
      `key ${' '.repeat(TOKEN.length)} and ${' '.repeat(POINTER.length)}.`,
    );
    expect(shielded.spans).toEqual([
      { start: 4, end: 4 + TOKEN.length },
      { start: 9 + TOKEN.length, end: 9 + TOKEN.length + POINTER.length },
    ]);
  });

  it('blanks a token under a previous key version exactly as one under the current', () => {
    const alias = ['[[aka:fp:v', '11.', FP, ']]'].join('');
    const text = `${TOKEN} ${alias}`;
    expect(shieldPointers(text)).toEqual({
      text: ' '.repeat(text.length),
      spans: [
        { start: 0, end: TOKEN.length },
        { start: TOKEN.length + 1, end: text.length },
      ],
    });
  });

  it('leaves a token with a malformed fingerprint visible', () => {
    const short = ['[[aka:fp:v1.', FP.slice(1), ']]'].join('');
    expect(shieldPointers(short).spans).toEqual([]);
  });
});
