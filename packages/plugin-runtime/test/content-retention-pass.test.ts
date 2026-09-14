/**
 * The detached child's program.
 *
 * It re-reads the setting rather than trusting the parent that spawned it, and
 * it never throws — it runs with stdio ignored and nobody watching, so a
 * rejection would be an unhandled rejection that reaches no one.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyOnboarding, dataDir, openLocalDatabase, settingsDir } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { runContentRetentionPass } from '../src/content-retention-pass.ts';

const DAY = 86_400_000;
let base: string;

function seedBody(ageDays: number, bytes = 500): void {
  const db = openLocalDatabase(dataDir(base));
  db.recordCapture(
    {
      id: `evt-${String(ageDays)}-${String(bytes)}`,
      sourceTool: 'claude-code',
      kind: 'code_change',
      occurredAt: new Date(Date.now() - ageDays * DAY).toISOString(),
      contentHash: `hash-${String(ageDays)}-${String(bytes)}`,
      content: 'x'.repeat(bytes),
      metadata: { sessionId: `sess-${String(ageDays)}`, filePath: 'src/a.ts' },
    },
    [],
  );
}

describe('runContentRetentionPass', () => {
  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-retention-pass-'));
  });
  afterEach(() => {
    removeTree(base);
  });

  it('makes no pass while the setting is off', () => {
    seedBody(60);
    expect(runContentRetentionPass({ base })).toEqual({ ran: false, reason: 'disabled' });
  });

  it('expires past the configured horizon once switched on', () => {
    seedBody(60);
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);

    const report = runContentRetentionPass({ base });
    expect(report).toEqual({ ran: true, rowsExpired: 1, bytesFreed: 500, done: true });
  });

  it('spares a body inside the horizon', () => {
    seedBody(1);
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);

    const report = runContentRetentionPass({ base });
    expect(report).toEqual({ ran: true, rowsExpired: 0, bytesFreed: 0, done: true });
  });

  it('re-reads the setting rather than trusting whoever spawned it', () => {
    seedBody(60);
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);
    // Switched back off between the spawn and the pass — which is a real window,
    // and the thing being decided is whether to destroy data.
    applyOnboarding({ bodyRetention: { enabled: false, retainDays: 30 } }, base, null);

    expect(runContentRetentionPass({ base })).toEqual({ ran: false, reason: 'disabled' });
  });

  it('reads a corrupt settings file as an unonboarded machine, so the pass is DISABLED', () => {
    // Not the `unreadable` branch, and worth pinning as its own fact because it
    // reads like one: `readUserSettings` already fails open to
    // `defaultWorkspaceSettings()` on a corrupt file, so expiry comes back off
    // and the pass declines before it ever opens a store. An enabled setting
    // written beforehand is overwritten by the corruption and does nothing.
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);
    writeFileSync(join(settingsDir(base), 'settings.json'), '{ not json');

    expect(runContentRetentionPass({ base })).toEqual({ ran: false, reason: 'disabled' });
  });

  it('reports rather than throws when the STORE cannot be opened', () => {
    // The `catch` is this function's whole safety property — it runs detached
    // with stdio ignored and nobody watching, so a throw reaches no one at all —
    // and it is the one branch nothing else reaches. Settings stay valid and
    // enabled; the store is what is broken, which is also the likelier failure
    // for an hourly background pass.
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);
    mkdirSync(join(dataDir(base), 'aka.db'), { recursive: true });

    // The exact reason, not merely `ran: false` — `disabled` is what a setup
    // that does not do what it reads as doing would report here.
    expect(runContentRetentionPass({ base })).toEqual({ ran: false, reason: 'unreadable' });
  });
});
