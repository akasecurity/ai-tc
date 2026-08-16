/**
 * settings.json under real concurrent writers.
 *
 * The wizard, `aka init` and the dashboard server are separate processes over
 * one ~/.aka. `applyOnboarding` is a read-modify-write, and an atomic
 * tmp+rename bounds only the write half: without a lock two writers read the
 * same bytes and the second rename discards the first one's answers, with
 * BOTH reporting success. That is the failure these tests exist to make
 * impossible — silent, and on fields that include the consent grants a user
 * can revoke.
 */
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { applyOnboarding, readWorkspaceSettings, SETTINGS_FILENAME } from '../../src/settings.ts';
import type { WriterJob } from '../helpers/settings-writers.ts';
import {
  BARRIER_HELD,
  barrierReport,
  runConcurrentSettingsWriters,
} from '../helpers/settings-writers.ts';

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-settings-race-'));
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function settingsFile(): string {
  return join(base, 'settings', SETTINGS_FILENAME);
}

// One writer per field, each setting a value that differs from that field's
// default — so a field back at its default is a lost answer and not a value
// some other writer happened to write too.
const DISTINCT_ANSWERS: { field: string; job: WriterJob; expected: unknown }[] = [
  { field: 'policy', job: { set: { policy: 'warn' } }, expected: 'warn' },
  { field: 'historicalAccess', job: { set: { historicalAccess: 'full' } }, expected: 'full' },
  { field: 'dataSharesInPlace', job: { set: { dataSharesInPlace: false } }, expected: false },
  { field: 'vaultInlineReveal', job: { set: { vaultInlineReveal: 'full' } }, expected: 'full' },
  { field: 'vaultKeyCustody', job: { set: { vaultKeyCustody: 'keychain' } }, expected: 'keychain' },
  {
    field: 'modelJudgeConsent',
    job: {
      set: {
        modelJudgeConsent: { acknowledgedAt: '2026-01-01T00:00:00.000Z', payloadVersion: 1 },
      },
    },
    expected: { acknowledgedAt: '2026-01-01T00:00:00.000Z', payloadVersion: 1 },
  },
  {
    field: 'vaultConsent',
    job: { set: { vaultConsent: { acknowledgedAt: '2026-01-01T00:00:00.000Z', version: 1 } } },
    expected: { acknowledgedAt: '2026-01-01T00:00:00.000Z', version: 1 },
  },
];

describe('concurrent applyOnboarding', () => {
  it('keeps every writer’s answer when all of them write at once', async () => {
    const run = await runConcurrentSettingsWriters(
      base,
      DISTINCT_ANSWERS.map((w) => w.job),
    );

    // Positive control on the barrier itself. Writers that ran one after
    // another would satisfy every assertion below without a race ever having
    // happened, so the contention is asserted before its consequences are.
    expect(barrierReport(run)).toBe(BARRIER_HELD);
    expect(run.outcomes.filter((o) => !o.ok).map((o) => o.error)).toEqual([]);

    const settings = readWorkspaceSettings(base);
    const lost = DISTINCT_ANSWERS.filter(
      (w) =>
        JSON.stringify((settings as unknown as Record<string, unknown>)[w.field]) !==
        JSON.stringify(w.expected),
    ).map((w) => w.field);
    expect(lost).toEqual([]);
  });

  it('does not resurrect a consent that a concurrent writer revoked', async () => {
    // A grant already on file, as it would be after the wizard's Yes path.
    applyOnboarding(
      { modelJudgeConsent: { acknowledgedAt: '2026-01-01T00:00:00.000Z', payloadVersion: 1 } },
      base,
    );
    expect(readWorkspaceSettings(base).modelJudgeConsent).toBeDefined();

    // The revoke races writers that carry no opinion about the consent at all.
    // Unlocked, any of them can have read the granted state before the revoke
    // landed and then rename its own merge — carrying the grant back — which
    // silently reinstates an egress the user just withdrew. Whichever order the
    // lock imposes, none of them can: the revoke either has not happened yet, or
    // is already in the bytes they merge over.
    const run = await runConcurrentSettingsWriters(base, [
      { clear: ['modelJudgeConsent'] },
      { set: { policy: 'warn' } },
      { set: { historicalAccess: 'full' } },
      { set: { dataSharesInPlace: false } },
      { set: { vaultInlineReveal: 'off' } },
    ]);

    expect(barrierReport(run)).toBe(BARRIER_HELD);
    expect(run.outcomes.filter((o) => !o.ok).map((o) => o.error)).toEqual([]);
    expect(readWorkspaceSettings(base).modelJudgeConsent).toBeUndefined();
    // The revoke is the only answer under test; the rest must still be there,
    // or "consent absent" could just be a settings.json nobody wrote.
    expect(readWorkspaceSettings(base).policy).toBe('warn');
    expect(readWorkspaceSettings(base).historicalAccess).toBe('full');
  });

  it('leaves settings.json owner-only, with no tmp or lock file behind', async (ctx) => {
    await runConcurrentSettingsWriters(
      base,
      DISTINCT_ANSWERS.map((w) => w.job),
    );

    const dir = join(base, 'settings');
    // The atomic write and the lock both work through sibling files; a storm
    // that leaves either behind has either failed to publish or failed to
    // release, and a leftover lock costs every later writer its stale wait.
    expect(readdirSync(dir)).toEqual([SETTINGS_FILENAME]);

    if (process.platform === 'win32') {
      ctx.skip('POSIX modes are a no-op on Windows');
      return;
    }
    expect(statSync(settingsFile()).mode & 0o777).toBe(0o600);
  });

  it('recovers a lock abandoned by a killed writer instead of wedging the file', () => {
    // A writer killed mid-section leaves its lock behind. Nothing releases it,
    // so without a stale path settings.json would be unwritable for the rest of
    // the machine's life — the lock's own availability risk, and the reason the
    // stale window sits BELOW the acquire timeout: one call has to recover it.
    const dir = join(base, 'settings');
    mkdirSync(dir, { recursive: true });
    const lock = `${settingsFile()}.lock`;
    // A lock as a killed writer leaves it: its own recorded acquire clock well
    // outside the stale window, and a pid no process here holds. Both are
    // required — age alone never evicts a holder that is merely slow.
    writeFileSync(
      lock,
      `${JSON.stringify({ pid: 0x7ffffffe, token: 'killed-writer', at: Date.now() - 60_000 })}\n`,
    );

    expect(applyOnboarding({ policy: 'warn' }, base).policy).toBe('warn');
    expect(readWorkspaceSettings(base).policy).toBe('warn');
    expect(existsSync(lock)).toBe(false);
  });

  it('merges over a file another writer published, rather than over its own read', async () => {
    // Two writers, one field each, run at once and then read back through the
    // file rather than the return value: the second one's merge has to be built
    // on bytes that already carry the first one's answer.
    const run = await runConcurrentSettingsWriters(base, [
      { set: { policy: 'warn' } },
      { set: { historicalAccess: 'full' } },
    ]);
    expect(barrierReport(run)).toBe(BARRIER_HELD);

    const raw: unknown = JSON.parse(readFileSync(settingsFile(), 'utf8'));
    expect(raw).toMatchObject({ policy: 'warn', historicalAccess: 'full' });
  });
});
