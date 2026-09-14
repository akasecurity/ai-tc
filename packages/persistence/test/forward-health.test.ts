import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { ATTACHED_FORWARD_STATE_FILENAME } from '../src/attached-derived.ts';
import {
  BREAKER_COOLDOWN_MS,
  isForwardPaused,
  parseForwardHealth,
  readForwardHealth,
} from '../src/forward-health.ts';

// The breaker's READ-ONLY half. It is read by three things that must agree —
// the forward path deciding whether to probe, the history drain deciding
// whether a pass is worth making, and a dashboard that renders it — and the
// whole reason it lives here is that the third may not import the package the
// first two do.
//
// The cases below are about the two ways a wrong answer is expensive, in
// opposite directions. Reading a file as OPEN when it is not silently stops a
// machine sending its organization its own telemetry. Reading one as CLOSED
// when it is open costs a bounded attempt, which is why every unparseable,
// torn or impossible file resolves that way.

const T0 = Date.parse('2026-09-12T10:00:00.000Z');

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-forward-health-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function writeState(state: unknown): void {
  writeFileSync(join(dir, ATTACHED_FORWARD_STATE_FILENAME), JSON.stringify(state));
}

/** The question a caller actually asks: is this machine sending right now? */
function pausedAt(nowMs: number): boolean {
  return isForwardPaused(readForwardHealth(dir, nowMs), nowMs);
}

describe('readForwardHealth', () => {
  // The happy path writes no file at all, so absent means "nothing has failed",
  // not "nothing has succeeded".
  it('says nothing at all when no file has been written', () => {
    expect(readForwardHealth(dir, T0)).toBeNull();
    expect(pausedAt(T0)).toBe(false);
  });

  it('reads back what the forward path recorded', () => {
    writeState({ consecutiveFailures: 3, openedAtMs: T0, lastFailure: 'unauthorized' });

    expect(readForwardHealth(dir, T0)).toEqual({
      consecutiveFailures: 3,
      openedAtMs: T0,
      lastFailure: 'unauthorized',
    });
  });

  // A hand-edited or half-written file must never resolve to open: an open
  // breaker is a decision to stop sending, and no corrupt byte on disk may make
  // that decision on an operator's behalf.
  it('reads a torn file as nothing, never as open', () => {
    writeFileSync(join(dir, ATTACHED_FORWARD_STATE_FILENAME), '{"consecutiveFailu');

    expect(readForwardHealth(dir, T0)).toBeNull();
    expect(pausedAt(T0)).toBe(false);
  });

  // `lastFailure` is rendered, so an arbitrary string from a hand-edited file
  // must not reach the output — but the COUNT beside it is still evidence, and
  // losing that would cost more than losing the cause.
  it('drops a cause it does not recognise and keeps the count', () => {
    writeState({ consecutiveFailures: 2, openedAtMs: T0, lastFailure: 'teapot' });

    expect(readForwardHealth(dir, T0)).toEqual({
      consecutiveFailures: 2,
      openedAtMs: T0,
      lastFailure: null,
    });
  });

  // A stamp this machine could not yet have written means the CLOCK moved — a
  // laptop that suspended, woke and took a correction backwards. Reading it as
  // open wedges forwarding off permanently, because nothing rewrites the file
  // on the cooling path.
  it('reads a stamp from the future as closed, not as open for ever', () => {
    writeState({ consecutiveFailures: 3, openedAtMs: T0 + 60_000, lastFailure: 'unreachable' });

    expect(readForwardHealth(dir, T0)?.openedAtMs).toBeNull();
    expect(pausedAt(T0)).toBe(false);
  });
});

describe('isForwardPaused', () => {
  it('is false for a machine that has never failed', () => {
    expect(isForwardPaused(null, T0)).toBe(false);
  });

  it('is false for failures that never tripped the breaker open', () => {
    writeState({ consecutiveFailures: 2, openedAtMs: null, lastFailure: 'unreachable' });

    expect(pausedAt(T0)).toBe(false);
  });

  it('is true from the instant the breaker opened', () => {
    writeState({ consecutiveFailures: 3, openedAtMs: T0, lastFailure: 'unreachable' });

    expect(pausedAt(T0)).toBe(true);
  });

  it('stays true for the last millisecond of the cooldown', () => {
    writeState({ consecutiveFailures: 3, openedAtMs: T0, lastFailure: 'unreachable' });

    expect(pausedAt(T0 + BREAKER_COOLDOWN_MS - 1)).toBe(true);
  });

  // THE HALF THAT IS EASY TO GET WRONG, and the expensive direction. The stamp
  // is never cleared by elapsing and the half-open probe re-stamps it before
  // every attempt, so treating any stamp as open holds a caller off through the
  // whole window in which the live path has resumed probing — and on a flaky
  // deployment each cooldown re-stamps, so the job that most needs to make
  // progress during a partial outage is the one held off indefinitely.
  it('is false the instant the cooldown elapses, not merely when the stamp clears', () => {
    writeState({ consecutiveFailures: 3, openedAtMs: T0, lastFailure: 'unreachable' });

    expect(pausedAt(T0 + BREAKER_COOLDOWN_MS)).toBe(false);
    expect(readForwardHealth(dir, T0 + BREAKER_COOLDOWN_MS)?.openedAtMs).toBe(T0);
  });
});

describe('parseForwardHealth', () => {
  // Exported because the forward path parses bytes it already has in hand, and
  // the two must agree about what a given file means. A second parse is how a
  // writer and a reader come to disagree about the clamps above.
  it('gives the same answer as the file reader, on the same bytes', () => {
    const state = { consecutiveFailures: 1, openedAtMs: T0, lastFailure: 'forbidden' };
    writeState(state);

    expect(parseForwardHealth(JSON.stringify(state), T0)).toEqual(readForwardHealth(dir, T0));
  });

  it('reads a value that is not an object at all as nothing', () => {
    expect(parseForwardHealth('42', T0)).toBeNull();
    expect(parseForwardHealth('null', T0)).toBeNull();
  });

  // A negative count is not evidence of anything, and rendering one would be
  // worse than rendering none.
  it('floors a nonsensical count rather than refusing the whole file', () => {
    expect(
      parseForwardHealth(JSON.stringify({ consecutiveFailures: -5, openedAtMs: T0 }), T0),
    ).toEqual({ consecutiveFailures: 0, openedAtMs: T0, lastFailure: null });
  });
});
