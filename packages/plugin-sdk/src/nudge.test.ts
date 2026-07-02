import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { claimOnboardingNudge, claimSessionStart } from './nudge.ts';

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
