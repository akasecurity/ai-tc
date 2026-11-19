import { randomUUID } from 'node:crypto';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

import { handleSessionStart } from '@akasecurity/plugin-runtime';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as Remote from '../../../../packages/remote/src/index.ts';
import {
  CREDENTIAL_LOOKUPS_FILENAME,
  saveCredentialLookups,
} from '../../src/credentials/pasted.ts';
import type { SessionStartDeps } from '../../src/hooks/session-start-run.ts';
import { runSessionStart } from '../../src/hooks/session-start-run.ts';
import type { HookOutput } from '../../src/hooks/shared.ts';
import type { Device } from '../helpers/account-fixture.ts';
import { device } from '../helpers/account-fixture.ts';
import type { Sent } from '../helpers/recording-client.ts';

const sent = vi.hoisted((): Sent => ({ captures: [], audit: [], inventory: [] }));
vi.mock('../../../../packages/remote/src/index.ts', async (importOriginal) => {
  const { recordingClient } = await import('../helpers/recording-client.ts');
  return {
    ...(await importOriginal<typeof Remote>()),
    createRemoteClient: () => recordingClient(sent),
  };
});

let dev: Device;
beforeEach(() => {
  dev = device(sent);
});
afterEach(() => {
  dev.dispose();
});

async function start(
  availableCredentials: SessionStartDeps['availableCredentials'],
  more: Partial<SessionStartDeps> = {},
): Promise<HookOutput[]> {
  const emitted: HookOutput[] = [];
  const t = dev.transcript(randomUUID());
  await runSessionStart(
    {
      session_id: t.sessionId,
      transcript_path: t.path,
      cwd: dev.personal,
      hook_event_name: 'SessionStart',
      source: 'startup',
    },
    {
      version: '0.0.0-test',
      harnessInterface: undefined,
      claudeConfigDir: undefined,
      handleSessionStart,
      triggerReconcile: () => undefined,
      emit: (output) => {
        emitted.push(output);
        return Promise.resolve();
      },
      availableCredentials,
      credentialHandlesCanBeSupplied: () => true,
      ...more,
    },
  );
  return emitted;
}

const contextOf = (emitted: HookOutput[]): string | undefined => {
  for (const output of emitted) {
    if (
      'hookSpecificOutput' in output &&
      output.hookSpecificOutput.hookEventName === 'SessionStart'
    ) {
      return output.hookSpecificOutput.additionalContext;
    }
  }
  return undefined;
};

describe('the SessionStart credential brief', () => {
  it('lists the granted handles as additional context', async () => {
    const emitted = await start(() =>
      Promise.resolve([{ slug: 'github', description: 'GitHub token' }]),
    );
    expect(contextOf(emitted)).toContain('[[aka:cred:github]]: GitHub token');
  });

  it('adds nothing when the machine is not attached or nothing is granted', async () => {
    expect(contextOf(await start(() => Promise.resolve(undefined)))).toBeUndefined();
    expect(contextOf(await start(() => Promise.resolve([])))).toBeUndefined();
  });

  it('skips the brief silently when listing fails', async () => {
    expect(contextOf(await start(() => Promise.reject(new Error('down'))))).toBeUndefined();
  });

  it('asks the attached client by default and adds nothing on a standalone machine', async () => {
    expect(contextOf(await start(undefined))).toBeUndefined();
  });
});

describe('the saved credential lookups at session start', () => {
  const lookupsFile = () => join(dev.dataDir, CREDENTIAL_LOOKUPS_FILENAME);
  const saveOne = () => {
    saveCredentialLookups(dev.dataDir, [{ slug: 'github', description: '', lookups: ['t1'] }]);
  };
  const granted = () => Promise.resolve([{ slug: 'github', description: 'GitHub token' }]);

  it('offers no handle and clears the lookups where a tool call cannot be given a value', async () => {
    saveOne();
    const emitted = await start(granted, { credentialHandlesCanBeSupplied: () => false });
    expect(contextOf(emitted) ?? '').not.toContain('[[aka:cred:github]]');
    expect(existsSync(lookupsFile())).toBe(false);
  });

  it('clears the lookups when the machine cannot reach the vault', async () => {
    saveOne();
    await start(() => Promise.resolve(undefined), { canReachVault: () => false });
    expect(existsSync(lookupsFile())).toBe(false);
  });

  it('keeps the lookups when an attached deployment did not answer', async () => {
    saveOne();
    await start(() => Promise.resolve(undefined), { canReachVault: () => true });
    expect(existsSync(lookupsFile())).toBe(true);
  });
});
