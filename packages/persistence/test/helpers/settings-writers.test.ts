/**
 * The concurrent-writer harness's own suite.
 *
 * Every no-loss assertion in concurrency/settings-race.test.ts rests on this
 * helper doing two things: actually running the writers, and actually releasing
 * them together. Both fail silently if left unguarded — a child that never ran
 * writes nothing to lose, and a barrier that serialised them removes the race
 * the assertions are about.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { readWorkspaceSettings } from '../../src/settings.ts';
import type { ConcurrentRun, WriterJob } from './settings-writers.ts';
import { allReleasedTogether, runConcurrentSettingsWriters } from './settings-writers.ts';

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-writers-helper-'));
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function run(releasedAt: number, readies: number[]): ConcurrentRun {
  return {
    releasedAt,
    outcomes: readies.map((readyAt) => ({
      ok: true,
      readyAt,
      // Every writer starts after the release; that is true by construction and
      // is precisely why the barrier check reads readyAt instead.
      startedAt: releasedAt + 1,
      endedAt: releasedAt + 11,
    })),
  };
}

describe('runConcurrentSettingsWriters', () => {
  it('runs a writer, and it really writes', async () => {
    // Deliberately ONE writer: an outcome saying `ok` while the store stayed
    // empty would let every downstream assertion pass on nothing, and that is a
    // property of the harness. Asserting it across concurrent writers instead
    // would make this suite go red whenever the PRODUCT lost an update — a
    // harness failure reported for a defect somewhere else.
    const result = await runConcurrentSettingsWriters(base, [{ set: { policy: 'warn' } }]);
    expect(result.outcomes).toHaveLength(1);
    expect(result.outcomes[0]?.ok).toBe(true);
    expect(readWorkspaceSettings(base).policy).toBe('warn');
  });

  it('runs one writer per job and reports each one', async () => {
    const result = await runConcurrentSettingsWriters(base, [
      { set: { policy: 'warn' } },
      { set: { historicalAccess: 'full' } },
      { set: { dataSharesInPlace: false } },
    ]);
    expect(result.outcomes).toHaveLength(3);
    expect(result.outcomes.every((o) => o.ok)).toBe(true);
  });

  it('holds every writer at the line until all of them are ready', async () => {
    const result = await runConcurrentSettingsWriters(base, [
      { set: { policy: 'warn' } },
      { set: { historicalAccess: 'full' } },
      { set: { dataSharesInPlace: false } },
    ]);
    expect(allReleasedTogether(result)).toBe(true);
  });

  it('carries a revoke across the process boundary', async () => {
    // JSON.stringify drops an undefined value, so a job that cleared a field by
    // setting it to undefined would cross as `{}` — the writer applies nothing
    // and still reports success, and a test asserting the revoke stuck fails
    // looking like a product defect. `clear` names the field instead.
    await runConcurrentSettingsWriters(base, [
      {
        set: {
          modelJudgeConsent: { acknowledgedAt: '2026-01-01T00:00:00.000Z', payloadVersion: 1 },
        },
      },
    ]);
    expect(readWorkspaceSettings(base).modelJudgeConsent).toBeDefined();

    await runConcurrentSettingsWriters(base, [{ clear: ['modelJudgeConsent'] }]);
    expect(readWorkspaceSettings(base).modelJudgeConsent).toBeUndefined();
  });

  it('throws when a writer dies instead of folding it into a result', async () => {
    // A child that cannot even parse its arguments exits non-zero having written
    // nothing. Reported as a plain `ok: false` it would read as "this writer
    // lost the race", which is a legitimate outcome — so it has to be a failure
    // of the run instead.
    await expect(
      runConcurrentSettingsWriters(base, [undefined as unknown as WriterJob]),
    ).rejects.toThrow(/settings writer 0/);
  });
});

describe('allReleasedTogether', () => {
  it('is true when every writer was parked before the release', () => {
    expect(allReleasedTogether(run(100, [20, 60, 100]))).toBe(true);
  });

  it('is false when a writer was still loading at the release', () => {
    // The failure mode it exists to catch: a barrier that stopped holding, so
    // the writers ran as each finished booting, one after another — under which
    // "no answer was lost" is trivially true.
    expect(allReleasedTogether(run(100, [20, 140]))).toBe(false);
  });

  it('tolerates a writer scheduled late AFTER the release, which is not a defect', () => {
    // A released child can sit unscheduled for longer than another writer's
    // whole call on a loaded runner. Only readiness is the barrier's business,
    // so that must not read as a broken barrier — otherwise the suite fails on
    // machine load rather than on the product.
    const late = run(100, [20, 60]);
    const scheduledLate = late.outcomes.map((o, i) =>
      i === 1 ? { ...o, startedAt: 9_000, endedAt: 9_010 } : o,
    );
    expect(allReleasedTogether({ ...late, outcomes: scheduledLate })).toBe(true);
  });

  it('is false for no writers at all', () => {
    expect(allReleasedTogether(run(100, []))).toBe(false);
  });
});
