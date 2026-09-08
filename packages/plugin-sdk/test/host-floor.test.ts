import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  HOST_FLOORS,
  hostCeilingNotice,
  hostCompatibilityLines,
  hostFloorGaps,
  hostFloorNotice,
  hostVersionFromRecord,
  hostVersionFromTranscript,
  MAX_TESTED_HOST,
  readHostVersionCache,
  recordHostVersion,
  requiredHostVersion,
} from '../src/host-floor.ts';

// One temp root for the file with a cheap subdirectory per test, for the reason
// model-governance.test.ts states: this package also holds a timing ratio whose
// worker a couple of dozen recursive removes can starve on Windows.
let root: string;
let dir: string;
let n = 0;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-host-floor-'));
});

beforeEach(() => {
  n += 1;
  dir = join(root, `t${String(n)}`);
  mkdirSync(dir, { recursive: true });
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

/** A transcript line in the shape Claude Code really writes. */
function versionLine(version: string): string {
  return JSON.stringify({ type: 'user', message: { role: 'user' }, version });
}

/** A line the host writes that carries no version — bookkeeping, not content. */
function bookkeepingLine(): string {
  return JSON.stringify({ type: 'queue-operation', operation: 'enqueue' });
}

function writeTranscript(lines: string[]): string {
  const path = join(dir, 'transcript.jsonl');
  writeFileSync(path, `${lines.join('\n')}\n`, 'utf8');
  return path;
}

/** The floor that every row clears, and one patch below the lowest row. */
const HIGHEST_FLOOR = requiredHostVersion(
  Object.entries(HOST_FLOORS).map(([feature, row]) => ({
    feature,
    label: row.label,
    since: row.since,
  })),
);

describe('hostVersionFromRecord', () => {
  it('pulls the version off a record that carries one', () => {
    expect(hostVersionFromRecord({ type: 'user', version: '2.1.260' })).toBe('2.1.260');
  });

  it('returns undefined for a record with no version, whatever its type', () => {
    expect(hostVersionFromRecord({ type: 'queue-operation' })).toBeUndefined();
  });

  it('reads the version off ANY record type that carries one', () => {
    // Deliberately not filtered by `type`: a type allowlist goes stale the
    // moment the host adds a record kind, failing toward a silence nothing
    // would notice.
    for (const type of ['user', 'assistant', 'attachment', 'system', 'something-new']) {
      expect(hostVersionFromRecord({ type, version: '2.1.260' })).toBe('2.1.260');
    }
  });

  it('refuses a non-string or empty version rather than passing it through', () => {
    expect(hostVersionFromRecord({ version: 2.1 })).toBeUndefined();
    expect(hostVersionFromRecord({ version: '' })).toBeUndefined();
    expect(hostVersionFromRecord(null)).toBeUndefined();
    expect(hostVersionFromRecord('not an object')).toBeUndefined();
  });
});

describe('hostVersionFromTranscript', () => {
  it('reads the version from a small transcript', () => {
    expect(hostVersionFromTranscript(writeTranscript([versionLine('2.1.260')]))).toBe('2.1.260');
  });

  it('answers from the NEWEST record even when the file outgrows the tail window', () => {
    // The load-bearing case. The window is 256 KiB, so the leading filler is
    // outside it and the read is genuinely truncated; both version lines sit
    // inside it, older first. A scan that ran oldest-first would answer
    // 2.1.100 and tell a current user to update.
    const filler = JSON.stringify({ type: 'user', text: 'x'.repeat(64 * 1024) });
    const path = writeTranscript([
      ...Array.from({ length: 6 }, () => filler),
      versionLine('2.1.100'),
      filler,
      versionLine('2.1.260'),
    ]);
    expect(hostVersionFromTranscript(path)).toBe('2.1.260');
  });

  it('is silent when nothing can be read', () => {
    expect(hostVersionFromTranscript(undefined)).toBeUndefined();
    expect(hostVersionFromTranscript('')).toBeUndefined();
    expect(hostVersionFromTranscript(join(dir, 'absent.jsonl'))).toBeUndefined();
    expect(hostVersionFromTranscript(writeTranscript([]))).toBeUndefined();
    expect(hostVersionFromTranscript(writeTranscript([bookkeepingLine()]))).toBeUndefined();
  });
});

describe('hostFloorGaps', () => {
  it('reports every protection the host is too old for', () => {
    const gaps = hostFloorGaps('2.0.0');
    expect(gaps.length).toBe(Object.keys(HOST_FLOORS).length);
    expect(gaps.map((g) => g.label)).toContain('model-switch protection');
  });

  it('reports nothing once the host clears the highest floor', () => {
    expect(HIGHEST_FLOOR).toBeDefined();
    expect(hostFloorGaps(HIGHEST_FLOOR)).toEqual([]);
    expect(hostFloorGaps('9.9.9')).toEqual([]);
  });

  it('reports only the floors above the host, not every row', () => {
    // A version between two floors is the case that separates "compares each
    // row" from "warns about everything below the top".
    const gaps = hostFloorGaps('2.1.200');
    expect(gaps.map((g) => g.since)).toEqual(['2.1.251']);
  });

  it('is SILENT on a version it cannot read, rather than guessing', () => {
    // A false "update Claude Code" on a correct install costs more than a
    // missed warning, so every unknown resolves to no gaps.
    for (const bad of ['garbage', '2.1', 'v2.1.251', '', undefined]) {
      expect(hostFloorGaps(bad)).toEqual([]);
    }
  });
});

describe('the floor table', () => {
  it('is not empty', () => {
    // The positive control: without it every assertion above could be
    // satisfied by an empty table.
    expect(Object.keys(HOST_FLOORS).length).toBeGreaterThan(0);
  });

  it('gives every row a parseable `since` and at least one hook event', () => {
    // A `since` that does not parse makes its row silently never fire, because
    // the comparator answers 0 for an unparseable input and 0 is not < 0 —
    // reintroducing exactly the silent absence this module reports.
    for (const [feature, row] of Object.entries(HOST_FLOORS)) {
      expect(hostFloorGaps('0.0.1').map((g) => g.feature)).toContain(feature);
      expect(row.hookEvents.length).toBeGreaterThan(0);
      expect(row.label).not.toBe('');
    }
  });
});

describe('hostFloorNotice', () => {
  it('says nothing for a current host or an unknown one', () => {
    expect(hostFloorNotice(HIGHEST_FLOOR)).toBeNull();
    expect(hostFloorNotice(undefined)).toBeNull();
    expect(hostFloorNotice('garbage')).toBeNull();
  });

  it('names the running version and the one that clears every floor', () => {
    const notice = hostFloorNotice('2.0.0');
    expect(notice).toContain('2.0.0');
    expect(notice).toContain(String(HIGHEST_FLOOR));
    expect(notice).toContain('Update Claude Code');
  });

  it('names NO hook event, so it cannot be read as pointing at something to delete', () => {
    // This is the guard against the fix that caused the original damage: an
    // agent read the host's "unknown hook event" diagnostic and deleted the
    // entries from hooks.json rather than updating the host. Derived from the
    // table rather than a literal, so a new row is covered without an edit.
    const notice = hostFloorNotice('2.0.0') ?? '';
    expect(notice).not.toBe('');
    for (const row of Object.values(HOST_FLOORS)) {
      for (const event of row.hookEvents) {
        expect(notice).not.toContain(event);
      }
    }
  });

  it('suggests no edit, and mentions no file to edit', () => {
    const notice = (hostFloorNotice('2.0.0') ?? '').toLowerCase();
    for (const forbidden of ['hooks.json', 'remove', 'delete', 'edit', 'uninstall']) {
      expect(notice).not.toContain(forbidden);
    }
  });
});

describe('the host-version cache', () => {
  it('round-trips a version', () => {
    recordHostVersion(dir, '2.1.260');
    expect(readHostVersionCache(dir)?.version).toBe('2.1.260');
  });

  it('refuses to cache a version no comparison could act on', () => {
    recordHostVersion(dir, 'garbage');
    recordHostVersion(dir, undefined);
    expect(readHostVersionCache(dir)).toBeNull();
  });

  it('reads absent, torn and wrong-shaped caches as unknown', () => {
    expect(readHostVersionCache(dir)).toBeNull();
    writeFileSync(join(dir, 'host-version.json'), '{not json', 'utf8');
    expect(readHostVersionCache(dir)).toBeNull();
    writeFileSync(join(dir, 'host-version.json'), JSON.stringify({ version: 42 }), 'utf8');
    expect(readHostVersionCache(dir)).toBeNull();
    writeFileSync(join(dir, 'host-version.json'), JSON.stringify({ version: '2.1.1' }), 'utf8');
    expect(readHostVersionCache(dir)).toBeNull(); // no observedAt
  });

  it('is a no-op rather than a throw when the dir cannot be created', () => {
    // A FILE where the directory should be: `ensureDataDirSync` re-widens a
    // merely-tight directory back to 0700 (that is its job), so a chmod-based
    // fixture no longer exercises the failure path at all.
    const blocked = join(dir, 'blocker');
    writeFileSync(blocked, 'x', 'utf8');
    const target = join(blocked, 'data');
    expect(() => {
      recordHostVersion(target, '2.1.260');
    }).not.toThrow();
    expect(readHostVersionCache(target)).toBeNull();
  });

  it('never lets an older reading displace a newer one', () => {
    // Two installs share one machine. If the older one won, `aka status` would
    // tell a user whose host is current to update it.
    recordHostVersion(dir, '2.1.260');
    recordHostVersion(dir, '2.0.0');
    expect(readHostVersionCache(dir)?.version).toBe('2.1.260');
  });
});

describe('hostCeilingNotice', () => {
  it('says nothing at or below the tested ceiling, or on an unknown version', () => {
    expect(hostCeilingNotice(MAX_TESTED_HOST)).toBeNull();
    expect(hostCeilingNotice('0.0.1')).toBeNull();
    expect(hostCeilingNotice(undefined)).toBeNull();
    expect(hostCeilingNotice('garbage')).toBeNull();
  });

  it('hedges above the ceiling, naming both versions', () => {
    const notice = hostCeilingNotice('99.0.0') ?? '';
    expect(notice).toContain('99.0.0');
    expect(notice).toContain(MAX_TESTED_HOST);
    expect(notice).toContain("we'll look into it");
  });

  it('is not the same message as the floor notice', () => {
    // The two answer opposite questions and must not be confusable: one says
    // update, the other says this is newer than we know about.
    expect(hostCeilingNotice('99.0.0')).not.toContain('Update Claude Code');
  });

  it('has a ceiling the comparator can read', () => {
    // A ceiling that does not parse compares equal to everything, so it would
    // never fire — silently retiring the whole surface.
    expect(hostCeilingNotice('99.0.0')).not.toBeNull();
  });
});

describe('hostCompatibilityLines', () => {
  it('says NOTHING when no session has been observed', () => {
    // Not "unknown": only the Claude Code plugin writes this cache, so a
    // Codex-only or CLI-only machine would otherwise be told forever about a
    // product it does not run.
    expect(hostCompatibilityLines(null)).toEqual([]);
  });

  it('names the version, and the protections a too-old host is missing', () => {
    const lines = hostCompatibilityLines({ version: '2.0.0', observedAt: 1 }).join('\n');
    expect(lines).toContain('2.0.0');
    expect(lines).toContain('model-switch protection');
    expect(lines).toContain('update Claude Code');
  });

  it('reports a current host without any gap block', () => {
    const lines = hostCompatibilityLines({ version: MAX_TESTED_HOST, observedAt: 1 }).join('\n');
    expect(lines).toContain(MAX_TESTED_HOST);
    expect(lines).not.toContain('update Claude Code');
    expect(lines).not.toContain('newer than AKA');
  });

  it('never claims a host is both too old and newer than tested', () => {
    // The two blocks answer opposite questions; a floor above the ceiling would
    // print both and nothing else would catch it.
    for (const version of ['2.0.0', '2.1.251', MAX_TESTED_HOST, '99.0.0']) {
      const lines = hostCompatibilityLines({ version, observedAt: 1 }).join('\n');
      const tooOld = lines.includes('update Claude Code');
      const tooNew = lines.includes('newer than AKA');
      expect(tooOld && tooNew).toBe(false);
    }
  });
});
