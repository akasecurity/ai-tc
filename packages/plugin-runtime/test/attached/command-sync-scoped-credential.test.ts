import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type * as Remote from '@akasecurity/remote';
import type { ControlPlaneConnection } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The device-command channel on a machine whose credential file really is a
// scoped (v2) one, read by the real reader. Only the network client is faked.
// If the reader refuses the file, nothing is polled and both cases here fail.

const pollCommand = vi.fn();
const ackCommand = vi.fn();

vi.mock('@akasecurity/remote', async (importActual) => ({
  ...(await importActual<typeof Remote>()),
  createRemoteClient: () => ({ pollCommand, ackCommand }),
}));

// Imported once here, after the mock is registered, rather than inside each case:
// loaded inside a case, the import time is charged to that case's timeout, which
// a loaded machine can exceed.
const { runCommandSync } = await import('../../src/attached/command-sync.ts');

const CONNECTION: ControlPlaneConnection = {
  endpoint: 'https://aka.acme.test',
  attachedAt: '2026-09-03T10:00:00.000Z',
};
const TEST_KEY = 'not-a-real-key';
const WORK_REPO = 'github.com/acme/payments-api';
const COMMAND = {
  id: 'cmd_1',
  kind: 'shares_rescan' as const,
  issuedAt: '2026-09-03T12:00:00.000Z',
  expiresAt: '2026-09-04T12:00:00.000Z',
};
const BEFORE_DEADLINE = () => Date.parse('2026-09-04T11:59:59.000Z');

let base: string;

beforeEach(() => {
  pollCommand.mockReset();
  ackCommand.mockReset();
  ackCommand.mockResolvedValue(undefined);
  base = mkdtempSync(join(tmpdir(), 'aka-cmd-scoped-cred-'));
  mkdirSync(dataDirOf(base), { recursive: true });
});

afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function attachScoped(): void {
  applyOnboarding({ runMode: 'attached', controlPlane: CONNECTION }, base, null);
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: 2,
    mode: 'scoped',
    endpoint: CONNECTION.endpoint,
    apiKey: TEST_KEY,
  });
  const file = join(settingsDirOf(base), 'settings.json');
  const settings = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  writeFileSync(
    file,
    JSON.stringify({
      ...settings,
      attachmentScope: {
        endpoint: CONNECTION.endpoint,
        entries: [{ kind: 'repo', identity: WORK_REPO, enrolledAt: '2026-09-02T10:00:00.000Z' }],
      },
    }),
  );
}

const depsAt = (key: string, run: () => Promise<{ projects: number }>) => ({
  base,
  settingsDir: settingsDirOf(base),
  scan: { rootScopeKey: () => key, run },
  now: BEFORE_DEADLINE,
});

describe('runCommandSync — a scoped credential read from disk', () => {
  it('polls, then leaves an unenrolled root unscanned and unacknowledged', async () => {
    attachScoped();
    pollCommand.mockResolvedValue(COMMAND);
    const run = vi.fn(() => Promise.resolve({ projects: 1 }));

    await expect(runCommandSync(depsAt('github.com/someone/side-project', run))).resolves.toBe(
      'out-of-scope',
    );
    expect(pollCommand).toHaveBeenCalledTimes(1);
    expect(run).not.toHaveBeenCalled();
    expect(ackCommand).not.toHaveBeenCalled();
  });

  it('services a command whose root is enrolled', async () => {
    attachScoped();
    pollCommand.mockResolvedValue(COMMAND);
    const run = vi.fn(() => Promise.resolve({ projects: 1 }));

    await expect(runCommandSync(depsAt(WORK_REPO, run))).resolves.toBe('reported');
    expect(ackCommand).toHaveBeenCalledWith('cmd_1', { outcome: 'reported', projectsScanned: 1 });
  });
});
