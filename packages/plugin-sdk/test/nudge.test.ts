import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
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
 * The duplicate claim under concurrent sessions is INTENDED — pinned here so a
 * later change cannot quietly turn it into a lock.
 *
 * Each claim scheme is one shared file holding the last session id that claimed
 * it. Two concurrent Claude Code sessions therefore overwrite each other's id,
 * and a session that has already claimed can claim again. The observable
 * symptom is a second onboarding nudge, or a second store-unavailable warning,
 * with two or more sessions open.
 *
 * That is safe because every caller is idempotent: the SessionStart inventory
 * upserts are content-addressed and the audit root is INSERT OR IGNORE, so
 * re-running a pass costs a repeated no-op. The alternative — a per-session
 * marker, or a lock around the read-modify-write — buys nothing and either
 * leaks a file per session or adds a cross-process lock to a hook path whose
 * first principle is never to break the host session.
 *
 * A change that makes any assertion below fail is a behaviour change, not a bug
 * fix. If the duplicate is ever judged unacceptable, this block is where the
 * decision to reverse it gets recorded.
 */
describe('concurrent sessions — the accepted duplicate claim', () => {
  it('re-nudges a session whose marker another session overwrote', () => {
    expect(claimOnboardingNudge(dir, 's1')).toBe(true);
    // The uncontended gate works — the positive control. Without it, the
    // duplicate below would be indistinguishable from a claim that never
    // suppressed anything in the first place.
    expect(claimOnboardingNudge(dir, 's1')).toBe(false);

    // A second tab starts and claims the same shared marker.
    expect(claimOnboardingNudge(dir, 's2')).toBe(true);

    // s1 asks again and is nudged a second time, because the marker no longer
    // names it. Intended. A lock or a per-session marker would return false
    // here.
    expect(claimOnboardingNudge(dir, 's1')).toBe(true);
  });

  it('re-runs the SessionStart pass for a session another session displaced', () => {
    expect(claimSessionStart(dir, 's1')).toBe(true);
    expect(claimSessionStart(dir, 's1')).toBe(false);
    expect(claimSessionStart(dir, 's2')).toBe(true);
    expect(claimSessionStart(dir, 's1')).toBe(true);
  });

  it('lets two alternating sessions claim on every turn', () => {
    // The cost of the race stated in full: alternating sessions never suppress,
    // because each one displaces the other's id before it can ask again. Both
    // claims per round are the accepted outcome.
    for (let round = 0; round < 3; round += 1) {
      expect(claimOnboardingNudge(dir, 's1')).toBe(true);
      expect(claimOnboardingNudge(dir, 's2')).toBe(true);
    }
  });

  it('keeps one marker file per scheme however many sessions claim', () => {
    for (const session of ['s1', 's2', 's3', 's4']) {
      claimOnboardingNudge(dir, session);
      claimSessionStart(dir, session);
    }

    // Exactly two files, whatever the session count — the property that makes
    // the single-marker scheme cheap, and the one a per-session marker would
    // trade away. An exact set, not a ceiling: a floor would let a third scheme
    // appear here unnoticed.
    expect(readdirSync(dir).sort()).toStrictEqual(['nudge-last-session', 'session-start-last']);

    // Each marker holds one session id — the last claimer, not an accumulated
    // list. The two schemes track their claimers independently.
    expect(readFileSync(join(dir, 'nudge-last-session'), 'utf8')).toBe('s4');
    expect(readFileSync(join(dir, 'session-start-last'), 'utf8')).toBe('s4');
  });
});
