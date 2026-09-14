import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir,
  openLocalDatabase,
  readWorkspaceSettings,
} from '@akasecurity/persistence';
import type { WorkspaceSettings } from '@akasecurity/schema';
import { BodyRetention, HISTORY_SYNC_PAYLOAD_VERSION, isAttached } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { runPrune } from '../../src/commands/prune.ts';
import type { Prompter } from '../../src/lib/prompter.ts';

const DAY = 86_400_000;

let base: string;

function recorder(): Prompter & { output: () => string; errors: () => string } {
  const out: string[] = [];
  const err: string[] = [];
  const unscripted = (): Promise<string> => Promise.reject(new Error('unscripted prompt'));
  return {
    output: () => out.join(''),
    errors: () => err.join(''),
    out: (text) => {
      out.push(text);
    },
    err: (text) => {
      err.push(text);
    },
    isInteractive: true,
    ask: unscripted,
    askHidden: unscripted,
    readAllStdin: () => Promise.resolve(''),
  };
}

function seedBody(ageDays: number, bytes = 1000): void {
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

describe('aka prune', () => {
  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-prune-'));
  });
  afterEach(() => {
    removeTree(base);
  });

  it('refuses to run while body expiry is off', () => {
    seedBody(60);
    const io = recorder();
    runPrune(['--home', base], io);

    // Off by default, and this command is not a way around that.
    expect(io.output()).toContain('Body expiry is off');
  });

  it('--days runs a one-off pass even while the setting is off', () => {
    seedBody(60);
    const io = recorder();
    runPrune(['--home', base, '--days', '30'], io);

    expect(io.output()).toContain('Expired 1 bodies');
    expect(io.output()).toContain('1000 B');
  });

  it('--dry-run reports and changes nothing', () => {
    seedBody(60);
    const io = recorder();
    runPrune(['--home', base, '--days', '30', '--dry-run'], io);

    expect(io.output()).toContain('Would expire 1 bodies');

    // The body is still there — a dry run that expired anything would be the
    // worst possible defect in this command.
    const io2 = recorder();
    runPrune(['--home', base, '--days', '30', '--dry-run'], io2);
    expect(io2.output()).toContain('Would expire 1 bodies');
  });

  it('spares a body inside the horizon', () => {
    seedBody(1);
    const io = recorder();
    runPrune(['--home', base, '--days', '30'], io);

    expect(io.output()).toContain('Nothing to expire');
  });

  it('refuses a nonsense horizon rather than rounding it', () => {
    const io = recorder();
    runPrune(['--home', base, '--days', 'soon'], io);
    expect(io.errors()).toContain('whole number of days');

    const io2 = recorder();
    runPrune(['--home', base, '--days', '0'], io2);
    expect(io2.errors()).toContain('whole number of days');
  });

  it('respects the configured horizon once expiry is on', () => {
    seedBody(60);
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);

    const io = recorder();
    runPrune(['--home', base], io);
    expect(io.output()).toContain('Expired 1 bodies');
  });

  it('refuses --days when an administrator has locked the window', () => {
    // The lock reaches the COMMAND, not just the settings write. --days narrows
    // the window, so the bypass would expire strictly more than the pinned
    // policy allows — permanently, on a machine whose administrator locked it to
    // stop exactly that.
    seedBody(60);
    const io = recorder();
    runPrune(['--home', base, '--days', '7'], io, {
      specVersion: 1,
      organization: 'Acme',
      values: {},
      lockedFields: ['bodyRetention'],
    });

    expect(io.errors()).toContain('--days cannot override it');
    expect(io.output()).toBe('');
  });

  it('still runs a locked machine on its own pinned window', () => {
    // The control: a lock freezes what may be CHANGED, not whether the sweep
    // runs. Without this the refusal above is satisfied by a command that
    // stopped working on managed machines entirely.
    seedBody(60);
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);

    const io = recorder();
    runPrune(['--home', base], io, {
      specVersion: 1,
      organization: 'Acme',
      values: {},
      lockedFields: ['bodyRetention'],
    });

    expect(io.output()).toContain('Expired 1 bodies');
  });

  it('says the file does not shrink, because that is the next question', () => {
    seedBody(60);
    const io = recorder();
    runPrune(['--home', base, '--days', '30'], io);
    expect(io.output()).toContain('does not shrink');
  });

  it('accepts exactly the horizons the retention setting accepts', () => {
    // Read from the schema rather than written out, so this case follows the
    // setting's range instead of pinning a second copy of it.
    const { minValue, maxValue } = BodyRetention.shape.retainDays.unwrap();
    if (minValue === null || maxValue === null) throw new Error('retainDays has no bounds');
    seedBody(60);

    const over = recorder();
    runPrune(['--home', base, '--days', String(maxValue + 1)], over, null);
    expect(over.errors()).toContain(`from ${String(minValue)} to ${String(maxValue)}`);
    expect(over.output()).toBe('');

    const under = recorder();
    runPrune(['--home', base, '--days', String(minValue - 1)], under, null);
    expect(under.errors()).toContain('whole number of days');
    expect(under.output()).toBe('');

    // The ceiling itself is a legal horizon: it runs, and spares a 60-day body.
    const atCeiling = recorder();
    runPrune(['--home', base, '--days', String(maxValue)], atCeiling, null);
    expect(atCeiling.errors()).toBe('');
    expect(atCeiling.output()).toContain(`Nothing to expire older than ${String(maxValue)} days`);
  });

  describe('bodies a deployment could still claim', () => {
    const ENDPOINT = 'https://aka.example-org.internal';
    const DESCRIPTOR = { endpoint: ENDPOINT, attachedAt: '2026-08-01T00:00:00.000Z' };
    const GRANT = {
      acknowledgedAt: '2026-08-01T00:00:00.000Z',
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
      endpoint: ENDPOINT,
    };
    const HELD = '1 kept: not yet sent, and could still be owed to a deployment.\n';

    // A prompt is on the sync lane; a body there with no `synced_at` is what
    // the held-back count reports.
    function seedPrompt(ageDays: number): void {
      const db = openLocalDatabase(dataDir(base));
      db.recordCapture(
        {
          id: `prompt-${String(ageDays)}`,
          sourceTool: 'claude-code',
          kind: 'prompt',
          occurredAt: new Date(Date.now() - ageDays * DAY).toISOString(),
          contentHash: `prompt-hash-${String(ageDays)}`,
          content: 'y'.repeat(1000),
          metadata: { sessionId: `sess-prompt-${String(ageDays)}` },
        },
        [],
      );
    }

    // The three states `canSweepSyncLane` refuses, with the attached mode split
    // into its whole and its half. Only the first is attached, and the message
    // has to be true on all four.
    const STATES: [string, Partial<WorkspaceSettings>, boolean][] = [
      ['attached', { runMode: 'attached', controlPlane: DESCRIPTOR }, true],
      ['in attached mode with no deployment named', { runMode: 'attached' }, false],
      ['standalone but holding a deployment descriptor', { controlPlane: DESCRIPTOR }, false],
      ['standalone but holding a history-sync grant', { historySyncConsent: GRANT }, false],
    ];

    it.each(STATES)(
      'keeps the body on a machine %s, without claiming an attachment',
      (_, answers, attached) => {
        seedPrompt(60);
        applyOnboarding(answers, base, null);
        expect(isAttached(readWorkspaceSettings(base))).toBe(attached);

        const io = recorder();
        runPrune(['--home', base, '--days', '30'], io, null);
        expect(io.output()).toContain('Nothing to expire older than 30 days.');
        expect(io.output()).toContain(HELD);
        expect(io.output()).not.toContain('attached to');
      },
    );

    it('expires that body on a standalone machine with no sync state, and holds none back', () => {
      // The control: without it the cases above pass on a seed the sweep would
      // never have touched anyway.
      seedPrompt(60);
      const io = recorder();
      runPrune(['--home', base, '--days', '30'], io, null);
      expect(io.output()).toContain('Expired 1 bodies');
      expect(io.output()).not.toContain('kept:');
    });
  });
});
