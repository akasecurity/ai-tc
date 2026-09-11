/**
 * The detached child's program.
 *
 * It re-reads the setting rather than trusting the parent that spawned it, and
 * it never throws — it runs with stdio ignored and nobody watching, so a
 * rejection would be an unhandled rejection that reaches no one.
 */
import { mkdtempSync, writeFileSync } from 'node:fs';
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

  it('reports rather than throws when the settings file is unreadable', () => {
    // Nobody is watching this process. A throw here reaches no one at all.
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);
    writeFileSync(join(settingsDir(base), 'settings.json'), '{ not json');
    expect(() => runContentRetentionPass({ base })).not.toThrow();
    expect(runContentRetentionPass({ base }).ran).toBe(false);
  });
});
