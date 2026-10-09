/**
 * Scope enrollment racing every other settings writer, each in its own process.
 *
 * An enrollment is a read-modify-write of one key in settings.json: append to
 * the stored scope list. Computed from a read taken before the settings lock,
 * two enrollments released together would each append to the list they read and
 * one would lose the other's entry. The updater form computes the append inside
 * the lock, over the file the merge lands on. This holds it to that under real
 * contention, against the writers a user actually runs beside it: a dashboard
 * save, an `/aka:setup` answer and `aka sync-history --on`. A removal is the
 * same read-modify-write in the other direction, so it races them too.
 */
import type { AttachmentScopeEntry } from '@akasecurity/schema';
import {
  HISTORY_SYNC_PAYLOAD_VERSION,
  isAttachmentScopeBoundTo,
  parseAttachmentScope,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { freshAttachmentScope } from '../../src/attachment-scope-edit.ts';
import { applyOnboarding, readWorkspaceSettings } from '../../src/settings.ts';
import type { WriterJob } from '../helpers/settings-writers.ts';
import {
  BARRIER_HELD,
  barrierReport,
  runConcurrentSettingsWriters,
} from '../helpers/settings-writers.ts';
import { useTempStore } from '../helpers/temp-store.ts';

// The writers work inside this home. It holds settings.json and no store.
const store = useTempStore('aka-enroll-race-');

const ENDPOINT = 'https://plane.example.test';
const ISO = '2026-10-07T09:00:00.000Z';
// whoami's `userEmail`; compared byte for byte, never read as an address.
const WHO = { tenantName: 'Acme Payments', userEmail: 'member-17' };
const ENROLLED = [
  'github.com/acme/payments-api',
  'github.com/acme/ledger',
  'github.com/acme/web',
  'gitlab.com/acme/platform/terraform',
] as const;
/** An entry a newer build wrote, with a kind this build cannot read. */
const NEWER_ENTRY = { kind: 'org', identity: 'acme', enrolledAt: ISO };

const enrollJob = (identity: string): WriterJob => {
  const entry: AttachmentScopeEntry = { kind: 'repo', identity, enrolledAt: ISO };
  return { enroll: { endpoint: ENDPOINT, entry } };
};

/** The identities this build reads out of the stored record, sorted. */
function enrolledIdentities(raw: unknown): string[] {
  return (parseAttachmentScope(raw)?.entries ?? []).map((entry) => entry.identity).sort();
}

/** The stored entries list as the file holds it, readable or not. */
function storedEntries(raw: unknown): readonly unknown[] {
  if (typeof raw !== 'object' || raw === null || !('entries' in raw)) {
    throw new Error('the stored scope record has no entries list');
  }
  const entries: unknown = raw.entries;
  if (!Array.isArray(entries)) throw new Error('the stored scope entries are not a list');
  return entries as readonly unknown[];
}

describe('scope enrollment among concurrent settings writers', () => {
  it('runs an enrollment writer, and it really writes', async () => {
    // One writer, so a lost entry here is the harness's fault, not the
    // product's: the positive control the race below rests on.
    const run = await runConcurrentSettingsWriters(store.home, [enrollJob(ENROLLED[0])]);

    expect(run.outcomes[0]?.ok).toBe(true);
    const scope = readWorkspaceSettings(store.home).attachmentScope;
    expect(enrolledIdentities(scope)).toEqual([ENROLLED[0]]);
    // With no record to append to, the enrollment starts an UNBOUND one.
    expect(scope).not.toHaveProperty('tenantName');
  });

  it('loses no enrollment and no other setting when every writer is released at once', async () => {
    // A bound record, to which a newer build has since added an entry this one
    // cannot read and a key on the envelope it does not know.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: ISO },
        attachmentScope: {
          ...freshAttachmentScope(ENDPOINT, WHO),
          builtBy: 'a newer build',
          entries: [NEWER_ENTRY],
        },
      },
      store.home,
      null,
    );

    const jobs: WriterJob[] = [
      ...ENROLLED.map(enrollJob),
      // A dashboard settings save.
      { set: { policy: 'warn' } },
      // An `/aka:setup` answer.
      { set: { historicalAccess: 'full' } },
      // `aka sync-history --on`.
      {
        set: {
          historySyncConsent: {
            acknowledgedAt: ISO,
            payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
            endpoint: ENDPOINT,
          },
        },
      },
    ];
    const run = await runConcurrentSettingsWriters(store.home, jobs);

    // The barrier's own positive control: every writer parked before any ran.
    expect(barrierReport(run)).toBe(BARRIER_HELD);
    expect(run.outcomes.map((outcome) => outcome.error ?? 'ok')).toEqual(jobs.map(() => 'ok'));

    const settings = readWorkspaceSettings(store.home);
    expect(enrolledIdentities(settings.attachmentScope)).toEqual([...ENROLLED].sort());
    // Nothing the newer build wrote was lost along the way.
    expect(storedEntries(settings.attachmentScope)).toContainEqual(NEWER_ENTRY);
    expect(storedEntries(settings.attachmentScope)).toHaveLength(ENROLLED.length + 1);
    expect(settings.attachmentScope).toMatchObject({ builtBy: 'a newer build' });
    expect(isAttachmentScopeBoundTo(settings.attachmentScope, ENDPOINT, WHO)).toBe(true);
    // And no other writer lost its answer to an enrollment.
    expect(settings.policy).toBe('warn');
    expect(settings.historicalAccess).toBe('full');
    expect(settings.historySyncConsent?.endpoint).toBe(ENDPOINT);
  });

  it('applies every enrollment and every removal when removals join the race', async () => {
    const entry = (identity: string): AttachmentScopeEntry => ({
      kind: 'repo',
      identity,
      enrolledAt: ISO,
    });
    const stays = ENROLLED[0];
    const leaves = [ENROLLED[1], ENROLLED[2]];
    const arrives = [ENROLLED[3], 'github.com/acme/mobile'];
    // A bound record holding the repository that stays, the two that leave, and
    // a newer build's entry no removal here names.
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: ISO },
        attachmentScope: {
          ...freshAttachmentScope(ENDPOINT, WHO),
          builtBy: 'a newer build',
          entries: [NEWER_ENTRY, entry(stays), ...leaves.map(entry)],
        },
      },
      store.home,
      null,
    );

    const jobs: WriterJob[] = [
      ...arrives.map(enrollJob),
      ...leaves.map((identity): WriterJob => ({ unenroll: { endpoint: ENDPOINT, identity } })),
      { set: { policy: 'warn' } },
      { set: { historicalAccess: 'full' } },
      {
        set: {
          historySyncConsent: {
            acknowledgedAt: ISO,
            payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
            endpoint: ENDPOINT,
          },
        },
      },
    ];
    const run = await runConcurrentSettingsWriters(store.home, jobs);

    expect(barrierReport(run)).toBe(BARRIER_HELD);
    expect(run.outcomes.map((outcome) => outcome.error ?? 'ok')).toEqual(jobs.map(() => 'ok'));

    const settings = readWorkspaceSettings(store.home);
    // Every arrival landed, every departure stuck, and the one that stays stayed.
    expect(enrolledIdentities(settings.attachmentScope)).toEqual([stays, ...arrives].sort());
    expect(storedEntries(settings.attachmentScope)).toContainEqual(NEWER_ENTRY);
    expect(storedEntries(settings.attachmentScope)).toHaveLength(arrives.length + 2);
    expect(settings.attachmentScope).toMatchObject({ builtBy: 'a newer build' });
    expect(isAttachmentScopeBoundTo(settings.attachmentScope, ENDPOINT, WHO)).toBe(true);
    expect(settings.policy).toBe('warn');
    expect(settings.historicalAccess).toBe('full');
    expect(settings.historySyncConsent?.endpoint).toBe(ENDPOINT);
  });
});
