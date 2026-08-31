import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyOnboarding, readWorkspaceSettings } from '@akasecurity/persistence';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runSyncHistory } from '../../src/commands/sync-history.ts';
import type { Prompter } from '../../src/lib/prompter.ts';

const ENDPOINT = 'https://aka.example-org.internal';

let base: string;
let exits: number[];

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

const deps = (io: ReturnType<typeof recorder>) => ({
  base,
  prompter: io,
  exit: (code: number) => exits.push(code),
});

const attach = (endpoint = ENDPOINT): void => {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint, attachedAt: new Date().toISOString(), label: 'Example Org' },
    },
    base,
  );
};

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-sync-history-'));
  exits = [];
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

describe('aka sync-history', () => {
  it('reports that an unattached machine sends nothing', async () => {
    const io = recorder();
    await runSyncHistory([], deps(io));
    expect(exits).toEqual([]);
    expect(io.output()).toContain('not attached');
  });

  // A grant names the deployment it covers, so there has to be one to name.
  it('refuses to grant on an unattached machine', async () => {
    const io = recorder();
    await runSyncHistory(['--on'], deps(io));
    expect(exits).toEqual([1]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeUndefined();
  });

  it('grants against the endpoint this machine is attached to', async () => {
    attach();
    const io = recorder();
    await runSyncHistory(['--on'], deps(io));
    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toMatchObject({
      endpoint: ENDPOINT,
      payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
    });
  });

  it('revokes what it granted', async () => {
    attach();
    await runSyncHistory(['--on'], deps(recorder()));
    const io = recorder();
    await runSyncHistory(['--off'], deps(io));
    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeUndefined();
    // Revoking stops what has not gone; it cannot unsend what has.
    expect(io.output()).toContain('already sent');
  });

  it('revokes even when nothing was granted', async () => {
    attach();
    const io = recorder();
    await runSyncHistory(['--off'], deps(io));
    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeUndefined();
  });

  // Granting and then not waiting for the next session is the natural thing to
  // ask for, and the grant message itself sets it up ("starting with your next
  // session"). Recording the grant and silently ignoring half the command is the
  // one outcome that must not happen.
  it('grants and then sends when --on and --run are given together', async () => {
    attach();
    const io = recorder();
    await runSyncHistory(['--on', '--run'], deps(io));

    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeDefined();
    // The grant message AND the state the pass left behind — --on alone prints
    // only the first.
    expect(io.output()).toContain("Sending this machine's existing activity");
    expect(io.output().trimEnd().split('\n').length).toBeGreaterThan(3);
  });

  it('revokes and still runs cleanly when --off and --run are given together', async () => {
    attach();
    await runSyncHistory(['--on'], deps(recorder()));
    const io = recorder();
    await runSyncHistory(['--off', '--run'], deps(io));

    expect(exits).toEqual([]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeUndefined();
  });

  it('refuses --on and --off together rather than picking one', async () => {
    attach();
    const io = recorder();
    await runSyncHistory(['--on', '--off'], deps(io));
    expect(exits).toEqual([2]);
    expect(readWorkspaceSettings(base).historySyncConsent).toBeUndefined();
    expect(io.errors()).toContain('not both');
  });

  it('refuses an unknown flag rather than ignoring it', async () => {
    const io = recorder();
    await runSyncHistory(['--send-everything'], deps(io));
    expect(exits).toEqual([2]);
    expect(io.errors()).toContain('Usage: aka sync-history');
  });

  it('says what is in force once granted', async () => {
    attach();
    await runSyncHistory(['--on'], deps(recorder()));
    const io = recorder();
    await runSyncHistory([], deps(io));
    expect(io.output()).toContain('Sending');
    expect(io.output()).toContain('Example Org');
  });

  // A grant given for one deployment must not read as in force after the machine
  // is pointed at another — and the difference is worth saying, because "off"
  // alone would be a state the user cannot account for.
  it('treats a grant for another deployment as not in force, and says why', async () => {
    attach();
    await runSyncHistory(['--on'], deps(recorder()));
    attach('https://elsewhere.example-org.internal');

    const io = recorder();
    await runSyncHistory([], deps(io));
    expect(io.output()).toContain('no longer');
  });
});
