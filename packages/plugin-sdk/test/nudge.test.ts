import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { claimOnboardingNudge, claimSessionStart } from '../src/nudge.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-nudge-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('claimOnboardingNudge', () => {
  it('nudges once for a session id, then suppresses repeats', () => {
    expect(claimOnboardingNudge(dir, 's1')).toBe(true);
    expect(claimOnboardingNudge(dir, 's1')).toBe(false);
    expect(claimOnboardingNudge(dir, 's1')).toBe(false);
  });

  it('nudges again for a different session id', () => {
    expect(claimOnboardingNudge(dir, 's1')).toBe(true);
    expect(claimOnboardingNudge(dir, 's2')).toBe(true);
    expect(claimOnboardingNudge(dir, 's2')).toBe(false);
  });

  it('always nudges when there is no session id (cannot dedupe)', () => {
    expect(claimOnboardingNudge(dir, undefined)).toBe(true);
    expect(claimOnboardingNudge(dir, undefined)).toBe(true);
  });
});

describe('claimSessionStart', () => {
  it('claims once per session, then suppresses repeats', () => {
    expect(claimSessionStart(dir, 's1')).toBe(true);
    expect(claimSessionStart(dir, 's1')).toBe(false);
  });

  it('claims again for a new session', () => {
    expect(claimSessionStart(dir, 's1')).toBe(true);
    expect(claimSessionStart(dir, 's2')).toBe(true);
    expect(claimSessionStart(dir, 's2')).toBe(false);
  });

  it('uses a separate marker from the onboarding nudge (independent claims)', () => {
    expect(claimOnboardingNudge(dir, 's1')).toBe(true);
    // The session-start claim is not consumed by the nudge claim above.
    expect(claimSessionStart(dir, 's1')).toBe(true);
    expect(claimSessionStart(dir, 's1')).toBe(false);
  });

  it('always runs when there is no session id (cannot dedupe)', () => {
    expect(claimSessionStart(dir, undefined)).toBe(true);
    expect(claimSessionStart(dir, undefined)).toBe(true);
  });
});

/**
 * Concurrent sessions share each marker file. It holds the most recent session
 * ids, not only the last one, so a session another session overtook is still
 * recognised and is not claimed a second time.
 */
describe('concurrent sessions', () => {
  it('does not re-nudge a session another session overtook', () => {
    expect(claimOnboardingNudge(dir, 's1')).toBe(true);
    expect(claimOnboardingNudge(dir, 's1')).toBe(false);
    expect(claimOnboardingNudge(dir, 's2')).toBe(true);
    expect(claimOnboardingNudge(dir, 's1')).toBe(false);
  });

  it('does not re-run the SessionStart pass for a displaced session', () => {
    expect(claimSessionStart(dir, 's1')).toBe(true);
    expect(claimSessionStart(dir, 's2')).toBe(true);
    expect(claimSessionStart(dir, 's1')).toBe(false);
  });

  it('claims once per session when sessions alternate', () => {
    const claims: boolean[] = [];
    for (let round = 0; round < 3; round += 1) {
      claims.push(claimOnboardingNudge(dir, 's1'), claimOnboardingNudge(dir, 's2'));
    }
    expect(claims).toStrictEqual([true, true, false, false, false, false]);
  });

  it('keeps one marker file per scheme and a bounded id list', () => {
    for (let i = 0; i < 100; i += 1) {
      claimOnboardingNudge(dir, `s${String(i)}`);
      claimSessionStart(dir, `s${String(i)}`);
    }
    expect(readdirSync(dir).sort()).toStrictEqual(['nudge-last-session', 'session-start-last']);
    const ids = readFileSync(join(dir, 'nudge-last-session'), 'utf8').split('\n');
    expect(ids).toHaveLength(32);
    expect(ids.at(-1)).toBe('s99');
  });

  it('evicts the oldest id, so a session that fell out is nudged again', () => {
    for (let i = 0; i < 100; i += 1) {
      claimOnboardingNudge(dir, `s${String(i)}`);
    }
    const ids = readFileSync(join(dir, 'nudge-last-session'), 'utf8').split('\n');
    // The cap keeps the newest 32 and drops the rest: s0 is gone, so the same
    // session id is claimed again rather than recognised.
    expect(ids).not.toContain('s0');
    expect(claimOnboardingNudge(dir, 's0')).toBe(true);
  });

  it('reads a marker written by an older build that held a single id', () => {
    writeFileSync(join(dir, 'nudge-last-session'), 's1');
    expect(claimOnboardingNudge(dir, 's1')).toBe(false);
    expect(claimOnboardingNudge(dir, 's2')).toBe(true);
  });
});
