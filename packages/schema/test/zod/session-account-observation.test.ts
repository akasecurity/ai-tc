import { describe, expect, it } from 'vitest';

import { SessionAccountObservation } from '../../src/zod/local.ts';

// One line of a session's account log. Each kind parses as itself, a line that
// is not work carries no account hash, and a malformed line is refused.
const T = 1_760_430_000_000;
const BD = '0123456789abcdef';
const H = 'ab'.repeat(32);
const FP = '16777220:4211000:1842:1760430000123:1760430000456';

const LINES: readonly (readonly [string, Record<string, unknown>])[] = [
  ['a work login view', { t: T, bd: BD, k: 'w', h: H }],
  ['a login view that is not work', { t: T, bd: BD, k: 'n' }],
  ['a veto', { t: T, bd: BD, k: 'v' }],
  ['an unreadable login', { t: T, k: 'u' }],
  ['a startup boundary', { t: T, b: 'startup' }],
  ['a clear boundary', { t: T, b: 'clear' }],
  ['a resume boundary', { t: T, b: 'resume' }],
  ['an inherited account', { t: T, bd: BD, inh: true }],
  ['a Codex start on an account', { t: T, bd: BD, start: 'startup', s: H, fp: FP }],
  ['a Codex fork on no account', { t: T, bd: BD, start: 'fork', s: 'none', fp: FP }],
  ['a Codex clear on an account', { t: T, bd: BD, start: 'clear', s: H, fp: FP }],
  [
    'a Codex start before its head is on disk',
    { t: T, bd: BD, start: 'startup', s: 'pending', fp: FP },
  ],
  ['a Codex resume', { t: T, bd: BD, start: 'resume', s: 'none' }],
  ['a Codex baseline', { t: T, bd: BD, s: H, fp: FP }],
  ['a Codex sticky none', { t: T, bd: BD, s: 'none' }],
];

describe('SessionAccountObservation', () => {
  it.each(LINES)('reads %s as exactly that line', (_label, line) => {
    expect(SessionAccountObservation.parse(line)).toStrictEqual(line);
  });

  it('keeps no account hash on a line that is not work, even when one is handed in', () => {
    expect(SessionAccountObservation.parse({ t: T, bd: BD, k: 'n', h: H })).toStrictEqual({
      t: T,
      bd: BD,
      k: 'n',
    });
  });

  it.each<[string, unknown]>([
    ['a work view with no hash', { t: T, bd: BD, k: 'w' }],
    ['a hash that is not 64 hex digits', { t: T, bd: BD, k: 'w', h: 'ab' }],
    ['an upper-case hash', { t: T, bd: BD, k: 'w', h: H.toUpperCase() }],
    ['a binding hash that is not 16 hex digits', { t: T, bd: 'xyz', k: 'n' }],
    ['a time that is not a whole number of milliseconds', { t: 1.5, k: 'u' }],
    ['a negative time', { t: -1, k: 'u' }],
    ['an unknown boundary', { t: T, b: 'compact' }],
    ['an unknown login view', { t: T, bd: BD, k: 'x' }],
    ['a resume on an account', { t: T, bd: BD, start: 'resume', s: H }],
    ['a resume on an account, with a fingerprint', { t: T, bd: BD, start: 'resume', s: H, fp: FP }],
    ['a pending resume', { t: T, bd: BD, start: 'resume', s: 'pending' }],
    ['a pending baseline', { t: T, bd: BD, s: 'pending', fp: FP }],
    ['a start this build does not know', { t: T, bd: BD, start: 'compact', s: H, fp: FP }],
    ['a start on an account with no fingerprint', { t: T, bd: BD, start: 'startup', s: H }],
    ['a start on no account with no fingerprint', { t: T, bd: BD, start: 'startup', s: 'none' }],
    ['an empty fingerprint', { t: T, bd: BD, s: H, fp: '' }],
    ['a value that is not a line', 'w'],
  ])('refuses %s', (_label, line) => {
    expect(SessionAccountObservation.safeParse(line).success).toBe(false);
  });
});
