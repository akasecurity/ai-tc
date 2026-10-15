import { createHash, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

import { handleSessionStart, resolveDataGateway } from '@akasecurity/plugin-runtime';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as Remote from '../../../../packages/remote/src/index.ts';
import { reconcileSessionTail } from '../../src/history/usage.ts';
import { recordStopObservation, resolveHookAccount } from '../../src/hooks/account-stamp.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import { runSessionStart } from '../../src/hooks/session-start-run.ts';
import type { Device, Transcript } from '../helpers/account-fixture.ts';
import { device } from '../helpers/account-fixture.ts';
import type { Sent } from '../helpers/recording-client.ts';

// The hooks and the reconcile open the gateway the plugin's factory builds; only
// its transport is replaced, by one that records what it is handed.
const sent = vi.hoisted((): Sent => ({ captures: [], audit: [], inventory: [] }));
vi.mock('../../../../packages/remote/src/index.ts', async (importOriginal) => {
  const { recordingClient } = await import('../helpers/recording-client.ts');
  return {
    ...(await importOriginal<typeof Remote>()),
    createRemoteClient: () => recordingClient(sent),
  };
});

const T0 = Date.parse('2026-10-14T10:00:00.000Z');
const at = (s: number): string => new Date(T0 + s * 1_000).toISOString();
const ms = (s: number): number => T0 + s * 1_000;

/** The session-account hash an observation line carries for `accountKey`. */
const sessionAccountHash = (accountKey: string): string =>
  createHash('sha256').update(`aka-session-account:v1\n${accountKey}`).digest('hex');

/** Every file under `dir`, at any depth. */
function filesUnder(dir: string): string[] {
  return readdirSync(dir, { recursive: true, encoding: 'utf8' })
    .map((relative) => join(dir, relative))
    .filter((path) => statSync(path).isFile());
}

let dev: Device;
beforeEach(() => {
  dev = device(sent);
  dev.attach();
});
afterEach(() => {
  dev.dispose();
});

/** A whole session in `org`: start, a turn with a tool call and its hook, a file write, Stop and its reconcile. */
async function wholeSession(org: string): Promise<Transcript> {
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
      handleSessionStart,
      triggerReconcile: () => undefined,
      emit: () => Promise.resolve(),
      now: () => ms(0),
    },
  );
  t.prompt(at(1));
  t.org(org, at(2));
  t.reply(at(3), dev.personal, { name: 'Bash', input: { command: 'ls' } });
  const gateway = resolveDataGateway(dev.config());
  try {
    resolveHookAccount(gateway, {
      dataDir: dev.dataDir,
      sessionId: t.sessionId,
      transcriptPath: t.path,
      cwd: dev.personal,
      now: () => ms(4),
    });
  } finally {
    await gateway.close();
  }
  await runPreToolUse(
    {
      session_id: t.sessionId,
      transcript_path: t.path,
      cwd: dev.personal,
      hook_event_name: 'PreToolUse',
      tool_name: 'Write',
      tool_input: { file_path: join(dev.personal, 'notes.md'), content: 'hello' },
    },
    () => Promise.resolve(),
    { mode: 'hook' },
  );
  recordStopObservation(dev.config(), t.sessionId, dev.personal, () => ms(5));
  await reconcileSessionTail(dev.config(), t.sessionId, t.path, () => ms(5));
  return t;
}

describe('what a session leaves under the AKA home', () => {
  it("a personal session's full reconcile leaves no bytes of its uuid", async () => {
    dev.login({ org: dev.personalOrg, organizationType: 'claude_pro' });
    const t = await wholeSession(dev.personalOrg);
    const needles = [
      dev.personalOrg,
      dev.personalOrg.toUpperCase(),
      sessionAccountHash(`claude:${dev.personalOrg}`),
    ];
    const walked = filesUnder(dev.base).map((path) => ({
      path,
      bytes: readFileSync(path).toString('latin1'),
    }));
    // The walk read bytes, and the same search finds values they do carry, one in
    // the session's observation log and one in the store: the absences below are
    // over bytes that were read, not over an empty walk.
    const log = walked.find(({ path }) => path.endsWith(`${t.sessionId}.log`));
    expect(walked.length).toBeGreaterThan(0);
    expect((log?.bytes.length ?? 0) > 0).toBe(true);
    expect(log?.bytes.includes('"k":"n"')).toBe(true);
    expect(walked.some(({ bytes }) => bytes.includes(t.sessionId))).toBe(true);
    for (const { bytes } of walked) {
      for (const needle of needles) expect(bytes.includes(needle)).toBe(false);
    }
  });

  it('the same search finds the hash a work session writes', async () => {
    dev.login({ org: dev.workOrg });
    await wholeSession(dev.workOrg);
    const needle = sessionAccountHash(`claude:${dev.workOrg}`);
    expect(
      filesUnder(dev.base).some((path) => readFileSync(path).toString('latin1').includes(needle)),
    ).toBe(true);
  });
});
