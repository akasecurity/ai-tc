import { randomUUID } from 'node:crypto';

import { handleSessionStart } from '@akasecurity/plugin-runtime';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as Remote from '../../../../packages/remote/src/index.ts';
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
