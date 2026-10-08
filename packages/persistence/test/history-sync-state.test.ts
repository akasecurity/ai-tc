import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { AttachmentMode } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  historySyncStatePath,
  readHistorySyncState,
  writeHistorySyncState,
} from '../src/history-sync-state.ts';
import { frozenReadHistorySyncState } from './helpers/frozen-history-sync-state-reader-3c5f21f6.ts';

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

// WHICH ROWS the counts cover. A pass that knows records it; a build from
// before the marker records nothing, and its file must still read, with the
// same numbers and no invented marker.
describe('history sync state — the counts scope marker', () => {
  // Over the ENUM, not a copy of it: a mode added to AttachmentMode that the
  // reader does not keep fails here, rather than being dropped from every file.
  it.each(AttachmentMode.options)('round-trips a %s marker', (countsScope) => {
    writeHistorySyncState(dir, { ...STATE, countsScope });
    expect(readHistorySyncState(dir)).toStrictEqual({ specVersion: 1, ...STATE, countsScope });
  });

  it('reads a file an older build wrote, with no marker, and invents none', () => {
    corrupt(`${JSON.stringify({ specVersion: 1, ...STATE })}\n`);
    expect(readHistorySyncState(dir)).toStrictEqual({ specVersion: 1, ...STATE });
  });

  it('writes no marker when the pass has none, the file an older build wrote', () => {
    writeHistorySyncState(dir, { ...STATE, countsScope: undefined });
    expect(readFileSync(historySyncStatePath(dir), 'utf8')).toBe(
      `${JSON.stringify({ specVersion: 1, ...STATE })}\n`,
    );
  });

  it('reads the same counts with or without a marker', () => {
    writeHistorySyncState(dir, STATE);
    const unmarked = readHistorySyncState(dir);
    expect(unmarked).not.toBeNull();
    for (const countsScope of AttachmentMode.options) {
      writeHistorySyncState(dir, { ...STATE, countsScope });
      expect(readHistorySyncState(dir)).toStrictEqual({ ...unmarked, countsScope });
    }
  });

  // DROPPED, not refused: the numbers are still well-formed, and a dropped
  // marker reads as "not recorded", which is what a reader asking for 'scoped'
  // exactly treats as machine-wide counts.
  it.each<[string, unknown]>([
    ['a mode this build does not know', 'everywhere'],
    ['a mode in another case', 'Scoped'],
    ['a number', 1],
    ['null', null],
    ['an object', { mode: 'scoped' }],
  ])('drops %s and still reads the counts', (_name, countsScope) => {
    corrupt(JSON.stringify({ specVersion: 1, ...STATE, countsScope }));
    expect(readHistorySyncState(dir)).toStrictEqual({ specVersion: 1, ...STATE });
  });
});

// What a build from before the marker makes of the file this build writes. Not
// "an unknown key is ignored" stated in prose: whatever the REAL writer leaves
// on disk, marker or not, the SHIPPED reader returns the counts it always did.
// A change that bumped the spec version, or changed a field that reader checks,
// would leave every older CLI and plugin on the machine reporting no progress
// at all, and fails here.
describe('history sync state — what a reader from before the marker reads', () => {
  it.each<[string, AttachmentMode | undefined]>([
    ['no marker', undefined],
    ['a machine marker', 'machine'],
    ['a scoped marker', 'scoped'],
  ])('reads a file written with %s as it always did', (_name, countsScope) => {
    writeHistorySyncState(dir, countsScope === undefined ? STATE : { ...STATE, countsScope });
    expect(frozenReadHistorySyncState(historySyncStatePath(dir))).toStrictEqual({
      specVersion: 1,
      ...STATE,
    });
  });

  // The copy is worth something only while it IS the shipped reader. On a file
  // with no marker the two must agree, refusals included, so a transcription
  // more lenient than the original (a check dropped) fails here instead of
  // quietly passing the cases above whatever the writer does.
  it.each<[string, string]>([
    ['a recorded pass', `${JSON.stringify({ specVersion: 1, ...STATE })}\n`],
    [
      'a completed pass',
      JSON.stringify({
        specVersion: 1,
        ...STATE,
        phase: 'complete',
        pendingTotal: 0,
        completedAtMs: 1_756_500_000_000,
      }),
    ],
    ['a file that is not JSON', '{not json'],
    ['a file that is not an object', '"a string"'],
    ['a file holding null', 'null'],
    ['a version neither knows', JSON.stringify({ specVersion: 2, ...STATE })],
    [
      'a phase outside the known set',
      JSON.stringify({ specVersion: 1, ...STATE, phase: 'halfway' }),
    ],
    [
      'an outcome outside the known set',
      JSON.stringify({ specVersion: 1, ...STATE, lastOutcome: 'exploded' }),
    ],
    ['a count that is a string', JSON.stringify({ specVersion: 1, ...STATE, sentTotal: 'lots' })],
    ['a negative count', JSON.stringify({ specVersion: 1, ...STATE, pendingTotal: -1 })],
    [
      'a timestamp that is a string',
      JSON.stringify({ specVersion: 1, ...STATE, startedAtMs: 'yesterday' }),
    ],
    [
      'a last-pass time that is a string',
      JSON.stringify({ specVersion: 1, ...STATE, lastPassAtMs: 'now' }),
    ],
    [
      'a skipped count that is a string',
      JSON.stringify({ specVersion: 1, ...STATE, skippedTotal: 'some' }),
    ],
    [
      'a completion time that is a string',
      JSON.stringify({ specVersion: 1, ...STATE, completedAtMs: 'later' }),
    ],
  ])('agrees with the live reader on %s', (_name, body) => {
    corrupt(body);
    expect(frozenReadHistorySyncState(historySyncStatePath(dir))).toStrictEqual(
      readHistorySyncState(dir),
    );
  });
});
