import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as Remote from '../../../../packages/remote/src/index.ts';
import type * as ReconcileTrigger from '../../src/history/reconcile-trigger.ts';
import type * as Shared from '../../src/hooks/shared.ts';
import { parseStopPayload } from '../../src/hooks/stop-payload.ts';
import type { Device } from '../helpers/account-fixture.ts';
import { device } from '../helpers/account-fixture.ts';
import type { Sent } from '../helpers/recording-client.ts';

// The account cases open the gateway the plugin's factory builds; only its
// transport is replaced, by one that records what it is handed and sends nothing.
const sent = vi.hoisted((): Sent => ({ captures: [], audit: [], inventory: [] }));
vi.mock('../../../../packages/remote/src/index.ts', async (importOriginal) => {
  const { recordingClient } = await import('../helpers/recording-client.ts');
  return {
    ...(await importOriginal<typeof Remote>()),
    createRemoteClient: () => recordingClient(sent),
  };
});

// The Stop entry, run once in-process: stdin is the payload this holds, and the
// reconcile trigger records the session's log as it stands when Stop calls it.
const stop = vi.hoisted(() => ({ stdin: '', logAtTrigger: [] as string[] }));
vi.mock('../../src/hooks/shared.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof Shared>()),
  readStdin: () => Promise.resolve(stop.stdin),
  countFailOpen: () => undefined,
}));
vi.mock('../../src/history/reconcile-trigger.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof ReconcileTrigger>()),
  triggerReconcile: (dataDir: string, sessionId: string) => {
    const log = join(dataDir, 'session-accounts', `${sessionId}.log`);
    stop.logAtTrigger.push(existsSync(log) ? readFileSync(log, 'utf8') : '');
  },
}));

describe('parseStopPayload', () => {
  it('extracts session_id + transcript_path from a well-formed Stop payload', () => {
    const trigger = parseStopPayload({
      session_id: 'sess-abc',
      transcript_path: '/home/me/.claude/projects/p/sess-abc.jsonl',
      cwd: '/home/me/proj',
      hook_event_name: 'Stop',
      stop_hook_active: false,
    });
    expect(trigger).toEqual({
      sessionId: 'sess-abc',
      transcriptPath: '/home/me/.claude/projects/p/sess-abc.jsonl',
    });
  });

  it('returns undefined (fail-open) when transcript_path is missing', () => {
    expect(parseStopPayload({ session_id: 'sess-abc' })).toBeUndefined();
  });

  it('returns undefined (fail-open) when session_id is missing', () => {
    expect(parseStopPayload({ transcript_path: '/x.jsonl' })).toBeUndefined();
  });

  it('returns undefined for a null payload (unparseable stdin) without throwing', () => {
    expect(() => parseStopPayload(null)).not.toThrow();
    expect(parseStopPayload(null)).toBeUndefined();
  });

  it('returns undefined when a field is the wrong type (non-string)', () => {
    expect(parseStopPayload({ session_id: 123, transcript_path: '/x.jsonl' })).toBeUndefined();
    expect(parseStopPayload({ session_id: 's', transcript_path: ['x'] })).toBeUndefined();
  });
});

describe('the Stop entry', () => {
  let dev: Device;
  beforeEach(() => {
    dev = device(sent);
    dev.attach();
    dev.login({ org: dev.workOrg });
  });
  afterEach(() => {
    dev.dispose();
  });

  it('appends its login observation before it triggers the reconcile', async () => {
    const t = dev.transcript(randomUUID());
    stop.stdin = JSON.stringify({
      session_id: t.sessionId,
      transcript_path: t.path,
      cwd: dev.personal,
      hook_event_name: 'Stop',
      stop_hook_active: false,
    });
    const exit = vi
      .spyOn(process, 'exit')
      .mockImplementation((() => undefined) as typeof process.exit);
    try {
      await import('../../src/hooks/stop.ts');
    } finally {
      exit.mockRestore();
    }
    expect(stop.logAtTrigger).toHaveLength(1);
    expect(stop.logAtTrigger[0]).toMatch(/"k":"w"/);
  });
});
