import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { claimOnboardingNudge } from './nudge.ts';

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
