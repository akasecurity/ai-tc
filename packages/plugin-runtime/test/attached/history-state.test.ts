import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  historySyncStatePath,
  readHistorySyncState,
  writeHistorySyncState,
} from '../../src/attached/history-state.ts';

let dir: string;

const STATE = {
  phase: 'filling' as const,
  lastOutcome: 'ok' as const,
  lastPassAtMs: 1_756_400_000_000,
  sentTotal: 12_431,
  pendingTotal: 39_659,
  skippedTotal: 3,
  startedAtMs: 1_756_300_000_000,
  completedAtMs: null,
};

const corrupt = (body: string): void => {
  writeFileSync(historySyncStatePath(dir), body);
};

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-history-state-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('history sync state', () => {
  it('round-trips what a pass recorded', () => {
    writeHistorySyncState(dir, STATE);
    expect(readHistorySyncState(dir)).toEqual({ specVersion: 1, ...STATE });
  });

  it('reads as absent when no pass has run', () => {
    expect(readHistorySyncState(dir)).toBeNull();
  });

  it('keeps a completion stamp when one is recorded', () => {
    writeHistorySyncState(dir, {
      ...STATE,
      phase: 'complete',
      pendingTotal: 0,
      completedAtMs: 1_756_500_000_000,
    });
    expect(readHistorySyncState(dir)?.completedAtMs).toBe(1_756_500_000_000);
  });
});

describe('history sync state — what it refuses to render', () => {
  // This file is RENDERED. A hand-edited or half-written one must produce
  // silence, never a wrong number and never an arbitrary string on screen.
  it('refuses a file that is not JSON', () => {
    corrupt('{not json');
    expect(readHistorySyncState(dir)).toBeNull();
  });

  it('refuses a file that is not an object', () => {
    corrupt('"a string"');
    expect(readHistorySyncState(dir)).toBeNull();
  });

  // Downgrade-safe in the direction that matters: a state written by a newer
  // build says nothing here rather than being read with the wrong meaning.
  it('refuses a version this build does not know', () => {
    writeHistorySyncState(dir, STATE);
    corrupt(JSON.stringify({ specVersion: 2, ...STATE }));
    expect(readHistorySyncState(dir)).toBeNull();
  });

  it('refuses a phase outside the known set', () => {
    corrupt(JSON.stringify({ specVersion: 1, ...STATE, phase: 'halfway' }));
    expect(readHistorySyncState(dir)).toBeNull();
  });

  it('refuses an outcome outside the known set', () => {
    corrupt(JSON.stringify({ specVersion: 1, ...STATE, lastOutcome: 'exploded' }));
    expect(readHistorySyncState(dir)).toBeNull();
  });

  it('refuses a count that is not a count', () => {
    corrupt(JSON.stringify({ specVersion: 1, ...STATE, sentTotal: 'lots' }));
    expect(readHistorySyncState(dir)).toBeNull();
    corrupt(JSON.stringify({ specVersion: 1, ...STATE, pendingTotal: -1 }));
    expect(readHistorySyncState(dir)).toBeNull();
  });

  it('refuses a timestamp that is not a number or null', () => {
    corrupt(JSON.stringify({ specVersion: 1, ...STATE, startedAtMs: 'yesterday' }));
    expect(readHistorySyncState(dir)).toBeNull();
  });

  it('accepts a null completion stamp, which is the unfinished state', () => {
    corrupt(JSON.stringify({ specVersion: 1, ...STATE, completedAtMs: null }));
    expect(readHistorySyncState(dir)?.completedAtMs).toBeNull();
  });

  // Bookkeeping must never fail the drain that produced it.
  it('does not throw when the directory cannot be written', () => {
    expect(() => {
      writeHistorySyncState(join(dir, 'no', 'such', '\0bad'), STATE);
    }).not.toThrow();
  });
});
