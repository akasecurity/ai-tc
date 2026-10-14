import { randomUUID } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { dbPath as dbPathOf } from '@akasecurity/persistence';
import { handleSessionStart, resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { DataGateway } from '@akasecurity/plugin-sdk';
import type { AuditEventInput, ToolCallInput } from '@akasecurity/schema';
import { AccountCheckReason, SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as Remote from '../../../../packages/remote/src/index.ts';
import { readOffset } from '../../src/history/tail.ts';
import { parseTranscriptToolCalls, parseTranscriptUsage } from '../../src/history/transcripts.ts';
import {
  reconcileHistory,
  reconcileSession,
  reconcileSessionTail,
  reconcileSessionToolCalls,
} from '../../src/history/usage.ts';
import { recordStopObservation, resolveHookAccount } from '../../src/hooks/account-stamp.ts';
import { runSessionStart } from '../../src/hooks/session-start-run.ts';
import type { Device, Transcript } from '../helpers/account-fixture.ts';
import { device, isAgentKeyFor, PERSONAL_KEY, WORK_KEY } from '../helpers/account-fixture.ts';
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

// Every instant is a second count from T0. The hooks, the session start and the
// reconcile are each handed that clock, so a case orders its observations and
// its transcript lines exactly.
const T0 = Date.parse('2026-10-14T10:00:00.000Z');
const at = (s: number): string => new Date(T0 + s * 1_000).toISOString();
const ms = (s: number): number => T0 + s * 1_000;

let dev: Device;
beforeEach(() => {
  dev = device(sent);
});
afterEach(() => {
  dev.dispose();
});

async function start(
  t: Transcript,
  s: number,
  source = 'startup',
  cwd = dev.personal,
): Promise<void> {
  await runSessionStart(
    {
      session_id: t.sessionId,
      transcript_path: t.path,
      cwd,
      hook_event_name: 'SessionStart',
      source,
    },
    {
      version: '0.0.0-test',
      harnessInterface: undefined,
      handleSessionStart,
      triggerReconcile: () => undefined,
      emit: () => Promise.resolve(),
      now: () => ms(s),
    },
  );
}

/** A hook's login view and session check at second `s`, as UserPromptSubmit or PreToolUse makes it. */
async function hookAt(t: Transcript, s: number): Promise<void> {
  const gateway = resolveDataGateway(dev.config());
  try {
    resolveHookAccount(gateway, {
      dataDir: dev.dataDir,
      sessionId: t.sessionId,
      transcriptPath: t.path,
      cwd: dev.personal,
      now: () => ms(s),
    });
  } finally {
    await gateway.close();
  }
}

/** One reconcile pass at second `s`. */
const pass = (t: Transcript, s: number) =>
  reconcileSessionTail(dev.config(), t.sessionId, t.path, () => ms(s));

/** Stop at second `s`: its observation, then its reconcile pass. */
async function stopAt(t: Transcript, s: number): Promise<void> {
  recordStopObservation(dev.config(), t.sessionId, dev.personal, () => ms(s));
  await pass(t, s);
}

/**
 * A turn from second `s`: the prompt's hook, the prompt, the host's org line, a
 * reply that calls a tool, and that tool's hook, whose check validates a work
 * org. Returns the reply's uuid.
 */
async function turn(t: Transcript, s: number, org: string): Promise<string> {
  await hookAt(t, s);
  t.prompt(at(s));
  t.org(org, at(s + 1));
  const reply = t.reply(at(s + 2), dev.personal, { name: 'Bash', input: { command: 'ls' } });
  await hookAt(t, s + 3);
  return reply;
}

/** The scope keys of one session's rows of `type`, oldest first; the root for 'session'. */
function keysOf(t: Transcript, type: 'session' | 'llm_call' | 'tool_call'): (string | null)[] {
  const db = new DatabaseSync(dbPathOf(dev.base), { readOnly: true });
  try {
    const rows = db
      .prepare(
        `SELECT scope_key AS scopeKey FROM audit_events
          WHERE event_type = :type AND (id = :id OR root_session_id = :id)
          ORDER BY started_at, id`,
      )
      .all({ type, id: t.sessionId }) as { scopeKey: string | null }[];
    return rows.map((row) => row.scopeKey);
  } finally {
    db.close();
  }
}

/** The audit rows of `type` the transport was handed. */
const sentRows = (type: string) => dev.sent.audit.filter((event) => event.eventType === type);

/** An earlier session whose tool hook validated the work org, so the org is learned. */
async function learnTheWorkOrg(): Promise<void> {
  const earlier = dev.transcript(randomUUID());
  await start(earlier, 0);
  await turn(earlier, 1, dev.workOrg);
  expect(dev.learnedKeys()).toEqual([`claude:${dev.workOrg}`]);
}

describe('reconcileSessionTail — a work-subscription session', () => {
  beforeEach(() => {
    dev.attach();
    dev.login({ org: dev.workOrg });
  });

  it('heals the root the session start left with the agent key, and forwards the leaves and the inventory', async () => {
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    expect(keysOf(t, 'session')).toEqual([null]);
    expect(dev.sent.inventory).toEqual([]);
    await turn(t, 1, dev.workOrg);
    await stopAt(t, 5);
    expect(isAgentKeyFor(keysOf(t, 'session')[0], dev.workOrg)).toBe(true);
    for (const key of [...keysOf(t, 'llm_call'), ...keysOf(t, 'tool_call')]) {
      expect(isAgentKeyFor(key, dev.workOrg)).toBe(true);
    }
    expect(sentRows('session')).toHaveLength(1);
    expect(sentRows('llm_call')).toHaveLength(1);
    expect(sentRows('tool_call')).toHaveLength(1);
    expect(dev.sent.inventory).toHaveLength(1);
  });

  it('a row run in an enrolled repository keeps its repository key', async () => {
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    await hookAt(t, 1);
    t.prompt(at(1), dev.work);
    t.org(dev.workOrg, at(2));
    t.reply(at(3), dev.work, { name: 'Bash', input: { command: 'ls' } });
    await hookAt(t, 4);
    await stopAt(t, 5);
    expect(keysOf(t, 'llm_call')).toEqual([WORK_KEY]);
    expect(keysOf(t, 'tool_call')).toEqual([WORK_KEY]);
    expect(keysOf(t, 'session')).toEqual([WORK_KEY]);
  });

  it('a pass that writes stores the log offset and the carried state, and no hold', async () => {
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    await turn(t, 1, dev.workOrg);
    await stopAt(t, 5);
    const stored = readOffset(dev.dataDir, t.sessionId);
    expect(stored.offset).toBeGreaterThan(0);
    expect(stored.logOffset).toBeGreaterThan(0);
    expect(stored.carried).toMatchObject({ boundaryAt: ms(0), inherited: false });
    expect(stored.carried?.anchorAt).toBeGreaterThan(0);
    expect(stored.pending).toBeUndefined();
  });

  it('work then personal: the reply before the change is attributed, none after it', async () => {
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    await turn(t, 1, dev.workOrg);
    dev.login({ org: dev.personalOrg, organizationType: 'claude_pro' });
    await turn(t, 6, dev.personalOrg);
    await stopAt(t, 10);
    expect(isAgentKeyFor(keysOf(t, 'session')[0], dev.workOrg)).toBe(true);
    const [first, second] = keysOf(t, 'llm_call');
    expect(isAgentKeyFor(first, dev.workOrg)).toBe(true);
    expect(second).toBe(PERSONAL_KEY);
  });

  it('a resumed session inherits the org it ran under', async () => {
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    await turn(t, 1, dev.workOrg);
    await stopAt(t, 5);
    await start(t, 6, 'resume');
    expect(dev.sessionState(t.sessionId).log).toMatch(/"inh":true/);
    await hookAt(t, 7);
    t.prompt(at(7));
    t.reply(at(8));
    await stopAt(t, 9);
    const replies = keysOf(t, 'llm_call');
    expect(replies).toHaveLength(2);
    for (const key of replies) expect(isAgentKeyFor(key, dev.workOrg)).toBe(true);
  });

  it('a pass after an opt-out attributes the repository key to every record it has not attributed', async () => {
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    await turn(t, 1, dev.workOrg);
    dev.optOut();
    await stopAt(t, 5);
    expect(keysOf(t, 'session')).toEqual([PERSONAL_KEY]);
    expect(keysOf(t, 'llm_call')).toEqual([PERSONAL_KEY]);
    expect(keysOf(t, 'tool_call')).toEqual([PERSONAL_KEY]);
    expect(dev.sent.audit).toEqual([]);
  });

  it('a root the session start wrote keeps its key, while the rows take the session account', async () => {
    const t = dev.transcript(randomUUID());
    await start(t, 0, 'startup', dev.work);
    expect(keysOf(t, 'session')).toEqual([WORK_KEY]);
    await turn(t, 1, dev.workOrg);
    await stopAt(t, 5);
    expect(keysOf(t, 'session')).toEqual([WORK_KEY]);
    for (const key of [...keysOf(t, 'llm_call'), ...keysOf(t, 'tool_call')]) {
      expect(isAgentKeyFor(key, dev.workOrg)).toBe(true);
    }
  });

  it('a transcript rewritten shorter is attributed from its start, not from the state carried past the old one', async () => {
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    await turn(t, 1, dev.workOrg);
    await stopAt(t, 5);
    // The rewrite is shorter than the stored offset and puts the org line first,
    // so the position the carried state names is not the start of any org line.
    writeFileSync(t.path, '');
    await hookAt(t, 6);
    t.org(dev.workOrg, at(7));
    t.prompt(at(8));
    t.reply(at(9));
    await stopAt(t, 10);
    const replies = keysOf(t, 'llm_call');
    expect(replies).toHaveLength(2);
    for (const key of replies) expect(isAgentKeyFor(key, dev.workOrg)).toBe(true);
  });

  it('no reason or basis reaches any attribute', async () => {
    const work = dev.transcript(randomUUID());
    await start(work, 0);
    await turn(work, 1, dev.workOrg);
    await stopAt(work, 5);
    dev.login({ org: dev.personalOrg, organizationType: 'claude_pro' });
    const personal = dev.transcript(randomUUID());
    await start(personal, 20);
    await turn(personal, 21, dev.personalOrg);
    await stopAt(personal, 25);
    const forbidden = new Set<string>([
      ...AccountCheckReason.options,
      'validated',
      'remembered',
      'manual',
    ]);
    const db = new DatabaseSync(dbPathOf(dev.base), { readOnly: true });
    try {
      const rows = db
        .prepare('SELECT attributes FROM audit_events WHERE attributes IS NOT NULL')
        .all() as { attributes: string }[];
      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) {
        for (const [key, value] of Object.entries(JSON.parse(row.attributes) as object)) {
          expect(key).not.toMatch(/reason|basis|account/i);
          if (typeof value === 'string') expect(forbidden.has(value)).toBe(false);
        }
      }
    } finally {
      db.close();
    }
  });
});

describe('reconcileSessionTail — sessions that are not work subscriptions', () => {
  it("a personal session's root is written at session start, and its rows stay local", async () => {
    dev.attach();
    dev.login({ org: dev.personalOrg, organizationType: 'claude_pro' });
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    expect(keysOf(t, 'session')).toEqual([PERSONAL_KEY]);
    await turn(t, 1, dev.personalOrg);
    await stopAt(t, 5);
    expect(keysOf(t, 'session')).toEqual([PERSONAL_KEY]);
    expect(keysOf(t, 'llm_call')).toEqual([PERSONAL_KEY]);
    expect(dev.sent.audit).toEqual([]);
  });

  it('personal then work under one boundary attributes nothing', async () => {
    dev.attach();
    dev.login({ org: dev.personalOrg, organizationType: 'claude_pro' });
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    await turn(t, 1, dev.personalOrg);
    dev.login({ org: dev.workOrg });
    await turn(t, 6, dev.workOrg);
    await stopAt(t, 10);
    const keys = [...keysOf(t, 'session'), ...keysOf(t, 'llm_call'), ...keysOf(t, 'tool_call')];
    expect(keys.every((key) => key === PERSONAL_KEY)).toBe(true);
    expect(dev.sent.audit).toEqual([]);
  });

  it('reconcileHistory attributes no account in any session', async () => {
    dev.attach();
    dev.login({ org: dev.workOrg });
    await learnTheWorkOrg();
    const other = dev.transcript(randomUUID());
    dev.boundary(other);
    other.prompt(at(30));
    other.org(dev.personalOrg, at(31));
    other.reply(at(32));
    await reconcileHistory(dev.config(), {
      dir: join(dev.home, '.claude', 'projects'),
      now: ms(60),
    });
    const db = new DatabaseSync(dbPathOf(dev.base), { readOnly: true });
    try {
      const keys = (
        db
          .prepare("SELECT scope_key AS scopeKey FROM audit_events WHERE event_type = 'llm_call'")
          .all() as { scopeKey: string | null }[]
      ).map((row) => row.scopeKey);
      expect(keys.length).toBeGreaterThanOrEqual(2);
      expect(keys.every((key) => key === PERSONAL_KEY)).toBe(true);
    } finally {
      db.close();
    }
  });

  it('a session with no recorded boundary attributes none and keeps its root as written', async () => {
    dev.attach();
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    // A session start that wrote the root and recorded no boundary.
    await handleSessionStart(
      { sessionId: t.sessionId, cwd: dev.personal, tool: SOURCE_TOOL.ClaudeCode },
      dev.config(),
    );
    expect(keysOf(t, 'session')).toEqual([PERSONAL_KEY]);
    await turn(t, 1, dev.workOrg);
    await stopAt(t, 5);
    expect(keysOf(t, 'session')).toEqual([PERSONAL_KEY]);
    expect([...keysOf(t, 'llm_call'), ...keysOf(t, 'tool_call')]).toEqual([
      PERSONAL_KEY,
      PERSONAL_KEY,
    ]);
    expect(dev.learnedKeys()).toEqual([]);
    expect(dev.sent.audit).toEqual([]);
  });

  it('a session that starts before the device knows its attached user stays on the repository rule after the record arrives', async () => {
    dev.attach({ identity: false });
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    expect(keysOf(t, 'session')).toEqual([PERSONAL_KEY]);
    await turn(t, 1, dev.workOrg);
    // Writing the identity record clears every session's account state.
    dev.writeIdentity();
    await turn(t, 6, dev.workOrg);
    await stopAt(t, 10);
    const keys = [...keysOf(t, 'session'), ...keysOf(t, 'llm_call'), ...keysOf(t, 'tool_call')];
    expect(keys).toHaveLength(5);
    expect(keys.every((key) => key === PERSONAL_KEY)).toBe(true);
    expect(dev.learnedKeys()).toEqual([]);
    expect(dev.sent.audit).toEqual([]);
    // The next session is recognised from its first reply.
    const next = dev.transcript(randomUUID());
    await start(next, 20);
    await turn(next, 21, dev.workOrg);
    await stopAt(next, 25);
    expect(isAgentKeyFor(keysOf(next, 'session')[0], dev.workOrg)).toBe(true);
    expect(isAgentKeyFor(keysOf(next, 'llm_call')[0], dev.workOrg)).toBe(true);
  });
});

describe('the first-pass hold', () => {
  // A session on an org the device already learned, whose first reply no
  // observation follows yet: its root is deferred and that reply is pending.
  async function pendingSession(): Promise<Transcript> {
    dev.attach();
    dev.login({ org: dev.workOrg });
    await learnTheWorkOrg();
    const t = dev.transcript(randomUUID());
    await start(t, 100);
    await hookAt(t, 101);
    t.prompt(at(101));
    t.org(dev.workOrg, at(102));
    t.reply(at(103));
    return t;
  }

  it("a transient miss keeps leaves local only until Stop's observation lands, then forwards them", async () => {
    const t = await pendingSession();
    await pass(t, 104);
    expect(readOffset(dev.dataDir, t.sessionId)).toMatchObject({
      offset: 0,
      pending: { passes: 1 },
    });
    expect(keysOf(t, 'llm_call')).toEqual([]);
    await stopAt(t, 105);
    expect(isAgentKeyFor(keysOf(t, 'llm_call')[0], dev.workOrg)).toBe(true);
    expect(isAgentKeyFor(keysOf(t, 'session')[0], dev.workOrg)).toBe(true);
    expect(readOffset(dev.dataDir, t.sessionId).pending).toBeUndefined();
  });

  it('after three held passes it attributes none and writes the root with its repository key', async () => {
    const t = await pendingSession();
    for (const s of [104, 105, 106]) await pass(t, s);
    expect(readOffset(dev.dataDir, t.sessionId).pending?.passes).toBe(3);
    expect(keysOf(t, 'llm_call')).toEqual([]);
    await pass(t, 107);
    expect(keysOf(t, 'llm_call')).toEqual([PERSONAL_KEY]);
    expect(keysOf(t, 'session')).toEqual([PERSONAL_KEY]);
    expect(readOffset(dev.dataDir, t.sessionId).pending).toBeUndefined();
  });

  it('does not hold a reply more than fifteen minutes old', async () => {
    const t = await pendingSession();
    await pass(t, 103 + 16 * 60);
    expect(keysOf(t, 'llm_call')).toEqual([PERSONAL_KEY]);
    expect(keysOf(t, 'session')).toEqual([PERSONAL_KEY]);
  });

  it('a definitive none writes the root with its repository key at once', async () => {
    const t = await pendingSession();
    dev.login({ org: dev.personalOrg, organizationType: 'claude_pro' });
    await stopAt(t, 104);
    expect(keysOf(t, 'session')).toEqual([PERSONAL_KEY]);
    expect(keysOf(t, 'llm_call')).toEqual([PERSONAL_KEY]);
    expect(readOffset(dev.dataDir, t.sessionId).pending).toBeUndefined();
  });
});

describe('reconcile rows when a stamp fails', () => {
  it('keeps the repository key on the root and on every row', async () => {
    const sessionId = randomUUID();
    const roots: AuditEventInput[] = [];
    const leaves: { attributes?: Record<string, unknown> | undefined }[] = [];
    const gateway = {
      accountScope: () => ({
        stamp: () => {
          throw new Error('the stamp failed');
        },
        admit: () => false,
        bindingHash: 'unused',
      }),
      ensureInventory: () => Promise.resolve({}),
      recordAuditEvent: (event: AuditEventInput) => {
        roots.push(event);
        return Promise.resolve();
      },
      readSessionProvider: () => Promise.resolve(undefined),
      recordLlmCalls: (inputs: typeof leaves) => {
        leaves.push(...inputs);
        return Promise.resolve();
      },
      getPolicyBundle: () => Promise.reject(new Error('no bundle')),
      recordToolCalls: (inputs: ToolCallInput[]) => {
        leaves.push(...inputs);
        return Promise.resolve();
      },
    } as unknown as DataGateway;
    const transcript = `${JSON.stringify({
      type: 'assistant',
      sessionId,
      uuid: randomUUID(),
      timestamp: at(1),
      cwd: dev.personal,
      message: {
        id: 'msg_stamp_fault',
        model: 'claude-sonnet-4-5',
        content: [
          { type: 'tool_use', id: 'toolu_stamp_fault', name: 'Bash', input: { command: 'ls' } },
        ],
        usage: { input_tokens: 1, output_tokens: 1 },
      },
    })}\n`;
    const records = parseTranscriptUsage(transcript);
    const options = { scopeKeyOf: () => PERSONAL_KEY, accountOf: () => `claude:${dev.workOrg}` };
    await reconcileSession(gateway, sessionId, records, options);
    await reconcileSessionToolCalls(
      gateway,
      sessionId,
      parseTranscriptToolCalls(transcript),
      records,
      options,
    );
    expect(roots.map((root) => root.attributes?.scope_key)).toEqual([PERSONAL_KEY]);
    expect(leaves.map((leaf) => leaf.attributes?.scope_key)).toEqual([PERSONAL_KEY, PERSONAL_KEY]);
  });
});
