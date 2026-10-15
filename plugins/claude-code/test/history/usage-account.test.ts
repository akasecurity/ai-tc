import { randomUUID } from 'node:crypto';
import { appendFileSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { applyOnboarding, dbPath as dbPathOf } from '@akasecurity/persistence';
import {
  createPolicyStore,
  handleSessionStart,
  resolveDataGateway,
} from '@akasecurity/plugin-runtime';
import type { DataGateway } from '@akasecurity/plugin-sdk';
import type { AuditEventInput, ToolCallInput } from '@akasecurity/schema';
import { AccountCheckReason, SOURCE_TOOL, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
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

/** One session's root attributes as stored: null while the root is the stub a session start leaves. */
function rootAttributes(t: Transcript): Record<string, unknown> | null {
  const db = new DatabaseSync(dbPathOf(dev.base), { readOnly: true });
  try {
    const row = db
      .prepare("SELECT attributes FROM audit_events WHERE event_type = 'session' AND id = :id")
      .get({ id: t.sessionId }) as { attributes: string | null } | undefined;
    return row?.attributes == null ? null : (JSON.parse(row.attributes) as Record<string, unknown>);
  } finally {
    db.close();
  }
}

/** Whether a root carries the provider, harness and folder a reconcile pass writes. */
const isWrittenRoot = (root: Record<string, unknown> | null): boolean =>
  root !== null &&
  typeof root.provider === 'string' &&
  typeof root.harness === 'string' &&
  typeof root.cwd === 'string';

/** The byte size of one session's observation log. */
const logSize = (t: Transcript): number => Buffer.byteLength(dev.sessionState(t.sessionId).log);

/** An assistant line the host wrote at second `s`, with `model` and `usage` as given, calling `tool` when one is named. */
function assistantLine(
  t: Transcript,
  s: number,
  model: string,
  usage: Record<string, number>,
  tool?: { name: string; input: Record<string, unknown> },
): string {
  const uuid = randomUUID();
  const content =
    tool === undefined
      ? [{ type: 'text', text: 'done' }]
      : [
          {
            type: 'tool_use',
            id: `toolu_${randomUUID().replaceAll('-', '')}`,
            name: tool.name,
            input: tool.input,
          },
        ];
  appendFileSync(
    t.path,
    `${JSON.stringify({
      type: 'assistant',
      sessionId: t.sessionId,
      uuid,
      timestamp: at(s),
      cwd: dev.personal,
      message: { id: `msg_${uuid}`, model, content, usage },
    })}\n`,
  );
  return uuid;
}

// A value the at-rest scrub strikes, composed at run time so the file commits no key-shaped literal.
const SECRET = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

const AWS_RULE = 'secrets/aws-access-key';

/** Vault consent and a pack policy that redacts AWS keys: what the scrub of the transcript file needs to strike one. */
async function consentToStrikingAwsKeys(): Promise<void> {
  applyOnboarding(
    { vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION } },
    dev.base,
  );
  await createPolicyStore(dev.dataDir).write({
    version: 'test',
    policies: [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: AWS_RULE },
        action: 'redact',
        enabled: true,
      },
    ],
    rules: [],
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
  });
}

/** A prompt line at second `s` holding a raw secret, as the host logs a prompt even when a hook blocked it. */
function appendLeakingPrompt(t: Transcript, s: number): void {
  appendFileSync(
    t.path,
    `${JSON.stringify({
      type: 'user',
      sessionId: t.sessionId,
      uuid: randomUUID(),
      promptId: randomUUID(),
      timestamp: at(s),
      cwd: dev.personal,
      message: { role: 'user', content: `key ${SECRET}` },
    })}\n`,
  );
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
    expect(rootAttributes(t)).toBeNull();
    expect(dev.sent.inventory).toEqual([]);
    await turn(t, 1, dev.workOrg);
    await stopAt(t, 5);
    expect(isWrittenRoot(rootAttributes(t))).toBe(true);
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

  it('a login whose plan is not confirmed leaves the root to the reconcile pass, which writes it', async () => {
    dev.attach();
    dev.login({ org: dev.workOrg, organizationType: null });
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    expect(rootAttributes(t)).toBeNull();
    await turn(t, 1, dev.workOrg);
    await stopAt(t, 5);
    expect(isWrittenRoot(rootAttributes(t))).toBe(true);
    expect(keysOf(t, 'session')).toEqual([PERSONAL_KEY]);
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

  it('a held pass strikes no secret from the transcript file, and the pass that writes does', async () => {
    const t = await pendingSession();
    await consentToStrikingAwsKeys();
    appendLeakingPrompt(t, 103);
    const logged = readFileSync(t.path);
    expect(logged.includes(SECRET)).toBe(true);

    await pass(t, 104);
    expect(readOffset(dev.dataDir, t.sessionId).pending?.passes).toBe(1);
    expect(keysOf(t, 'llm_call')).toEqual([]);
    expect(readFileSync(t.path).equals(logged)).toBe(true);

    await stopAt(t, 105);
    expect(keysOf(t, 'llm_call')).toHaveLength(1);
    const struck = readFileSync(t.path);
    expect(struck.includes('[REDACTED:')).toBe(true);
    expect(struck.includes(SECRET)).toBe(false);
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

describe('the hold and the records that write no row', () => {
  const NOT_BILLED: readonly [string, string, Record<string, number>][] = [
    ['synthetic', '<synthetic>', { input_tokens: 5, output_tokens: 3 }],
    ['zero-usage', 'claude-sonnet-4-5-20250929', { input_tokens: 0, output_tokens: 0 }],
  ];

  // A session on an org the device already learned, with a prompt and the host's
  // org line, and no observation after them.
  async function sessionAwaitingReply(): Promise<Transcript> {
    dev.attach();
    dev.login({ org: dev.workOrg });
    await learnTheWorkOrg();
    const t = dev.transcript(randomUUID());
    await start(t, 100);
    await hookAt(t, 101);
    t.prompt(at(101));
    t.org(dev.workOrg, at(102));
    return t;
  }

  it.each(NOT_BILLED)(
    'an unclosed %s reply does not hold the pass',
    async (_name, model, usage) => {
      const t = await sessionAwaitingReply();
      assistantLine(t, 103, model, usage);
      await pass(t, 104);
      const stored = readOffset(dev.dataDir, t.sessionId);
      expect(stored.pending).toBeUndefined();
      expect(stored.offset).toBeGreaterThan(0);
      expect(keysOf(t, 'llm_call')).toEqual([]);
    },
  );

  it.each(NOT_BILLED)(
    'a closed reply is written although an unclosed %s reply follows it',
    async (_name, model, usage) => {
      const t = await sessionAwaitingReply();
      t.reply(at(103));
      await hookAt(t, 104);
      assistantLine(t, 105, model, usage);
      await pass(t, 106);
      expect(readOffset(dev.dataDir, t.sessionId).pending).toBeUndefined();
      const keys = keysOf(t, 'llm_call');
      expect(keys).toHaveLength(1);
      expect(isAgentKeyFor(keys[0], dev.workOrg)).toBe(true);
    },
  );

  it.each(NOT_BILLED)(
    'an unclosed reply that becomes a row still holds the pass beside an unclosed %s reply',
    async (_name, model, usage) => {
      const t = await sessionAwaitingReply();
      assistantLine(t, 103, model, usage);
      t.reply(at(104));
      await pass(t, 105);
      expect(readOffset(dev.dataDir, t.sessionId)).toMatchObject({
        offset: 0,
        pending: { passes: 1 },
      });
      expect(keysOf(t, 'llm_call')).toEqual([]);
    },
  );

  describe('a reply that calls a tool', () => {
    const TOOL = { name: 'Bash', input: { command: 'ls' } };

    // A closed reply, which writes the session root, then an unclosed `model`
    // reply that calls a tool and writes no llm_call row.
    async function sessionWithUnclosedToolReply(
      model: string,
      usage: Record<string, number>,
    ): Promise<Transcript> {
      const t = await sessionAwaitingReply();
      t.reply(at(103));
      await hookAt(t, 104);
      assistantLine(t, 105, model, usage, TOOL);
      return t;
    }

    it.each(NOT_BILLED)(
      'an unclosed %s reply holds the pass, and its tool call row takes the agent key once the reply is closed',
      async (_name, model, usage) => {
        const t = await sessionWithUnclosedToolReply(model, usage);
        await pass(t, 106);
        expect(readOffset(dev.dataDir, t.sessionId)).toMatchObject({
          offset: 0,
          pending: { passes: 1 },
        });
        expect(keysOf(t, 'llm_call')).toEqual([]);
        expect(keysOf(t, 'tool_call')).toEqual([]);

        await stopAt(t, 107);
        expect(readOffset(dev.dataDir, t.sessionId).pending).toBeUndefined();
        const replies = keysOf(t, 'llm_call');
        expect(replies).toHaveLength(1);
        expect(isAgentKeyFor(replies[0], dev.workOrg)).toBe(true);
        const tools = keysOf(t, 'tool_call');
        expect(tools).toHaveLength(1);
        expect(isAgentKeyFor(tools[0], dev.workOrg)).toBe(true);
      },
    );

    it.each(NOT_BILLED)(
      'after three held passes the tool call row of an unclosed %s reply takes its repository key',
      async (_name, model, usage) => {
        const t = await sessionWithUnclosedToolReply(model, usage);
        for (const s of [106, 107, 108]) await pass(t, s);
        expect(readOffset(dev.dataDir, t.sessionId).pending?.passes).toBe(3);
        expect(keysOf(t, 'tool_call')).toEqual([]);
        await pass(t, 109);
        expect(keysOf(t, 'tool_call')).toEqual([PERSONAL_KEY]);
        expect(readOffset(dev.dataDir, t.sessionId).pending).toBeUndefined();
      },
    );
  });
});

describe('reconcileSessionTail — an observation log that starts again', () => {
  beforeEach(() => {
    dev.attach();
    dev.login({ org: dev.workOrg });
  });

  // Four reconciled turns of a work session, so the stored log offset is long,
  // then an identity write, which clears every session's log.
  async function sessionWhoseLogWasCleared(): Promise<{
    t: Transcript;
    storedOffset: number;
    storedLogOffset: number;
  }> {
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    for (const s of [1, 6, 11, 16]) {
      await turn(t, s, dev.workOrg);
      await stopAt(t, s + 4);
    }
    const stored = readOffset(dev.dataDir, t.sessionId);
    const storedLogOffset = stored.logOffset ?? 0;
    expect(storedLogOffset).toBeGreaterThan(0);
    expect(keysOf(t, 'llm_call')).toHaveLength(4);
    dev.writeIdentity();
    expect(dev.sessionState(t.sessionId).log).toBe('');
    return { t, storedOffset: stored.offset, storedLogOffset };
  }

  it('attributes the replies after a new boundary to the agent key, although the new log is shorter than the stored offset', async () => {
    const { t, storedLogOffset } = await sessionWhoseLogWasCleared();
    await start(t, 30, 'clear');
    await turn(t, 31, dev.workOrg);
    await stopAt(t, 35);
    expect(logSize(t)).toBeLessThan(storedLogOffset);
    const keys = keysOf(t, 'llm_call');
    expect(keys).toHaveLength(5);
    for (const key of keys) expect(isAgentKeyFor(key, dev.workOrg)).toBe(true);
    expect(readOffset(dev.dataDir, t.sessionId).logOffset).toBeLessThanOrEqual(logSize(t));
  });

  it('a pass that finds no log attributes nothing and stores the log offset from the start', async () => {
    const { t } = await sessionWhoseLogWasCleared();
    t.prompt(at(30));
    t.org(dev.workOrg, at(31));
    t.reply(at(32));
    await pass(t, 33);
    const keys = keysOf(t, 'llm_call');
    expect(keys).toHaveLength(5);
    expect(keys[4]).toBe(PERSONAL_KEY);
    const stored = readOffset(dev.dataDir, t.sessionId);
    expect(stored.logOffset).toBe(0);
    expect(stored.carried?.boundaryAt).toBeUndefined();
  });

  it('a held pass after the clear stores the log offset from the start, and the next pass attributes the reply', async () => {
    const { t, storedOffset, storedLogOffset } = await sessionWhoseLogWasCleared();
    await start(t, 30, 'clear');
    await hookAt(t, 31);
    t.prompt(at(31));
    t.org(dev.workOrg, at(32));
    t.reply(at(33));
    await pass(t, 34);
    expect(logSize(t)).toBeLessThan(storedLogOffset);
    const held = readOffset(dev.dataDir, t.sessionId);
    expect(held.pending?.passes).toBe(1);
    expect(held.offset).toBe(storedOffset);
    expect(held.logOffset).toBe(0);
    expect(held.carried).toBeUndefined();
    expect(keysOf(t, 'llm_call')).toHaveLength(4);
    await stopAt(t, 35);
    const keys = keysOf(t, 'llm_call');
    expect(keys).toHaveLength(5);
    expect(isAgentKeyFor(keys[4], dev.workOrg)).toBe(true);
    expect(readOffset(dev.dataDir, t.sessionId).pending).toBeUndefined();
  });
});

describe('reconcileSessionTail — a transcript read again from its start', () => {
  beforeEach(() => {
    dev.attach();
    dev.login({ org: dev.workOrg });
  });

  async function reconciledWorkSession(): Promise<Transcript> {
    const t = dev.transcript(randomUUID());
    await start(t, 0);
    await turn(t, 1, dev.workOrg);
    await stopAt(t, 5);
    expect(isAgentKeyFor(keysOf(t, 'llm_call')[0], dev.workOrg)).toBe(true);
    expect(isAgentKeyFor(keysOf(t, 'tool_call')[0], dev.workOrg)).toBe(true);
    return t;
  }

  /** The transcript without its org line, so shorter than the stored offset, with the reply's output count set. */
  function rewriteWithoutOrgLine(t: Transcript, outputTokens: number): void {
    const kept = readFileSync(t.path, 'utf8')
      .split('\n')
      .filter((line) => line !== '' && !line.includes('credential_org'));
    const text = kept
      .join('\n')
      .replace('"output_tokens":7', `"output_tokens":${String(outputTokens)}`);
    writeFileSync(t.path, `${text}\n`);
    expect(statSync(t.path).size).toBeLessThan(readOffset(dev.dataDir, t.sessionId).offset);
  }

  it('moves a reply row to the fresh attribution when its output count grew, and keeps the tool call row', async () => {
    const t = await reconciledWorkSession();
    rewriteWithoutOrgLine(t, 9);
    await pass(t, 10);
    expect(keysOf(t, 'llm_call')).toEqual([PERSONAL_KEY]);
    const tools = keysOf(t, 'tool_call');
    expect(tools).toHaveLength(1);
    expect(isAgentKeyFor(tools[0], dev.workOrg)).toBe(true);
  });

  it('keeps the first-written key of a reply row whose output count is equal', async () => {
    const t = await reconciledWorkSession();
    rewriteWithoutOrgLine(t, 7);
    await pass(t, 10);
    const replies = keysOf(t, 'llm_call');
    expect(replies).toHaveLength(1);
    expect(isAgentKeyFor(replies[0], dev.workOrg)).toBe(true);
    expect(keysOf(t, 'tool_call')).toHaveLength(1);
  });

  it('does not notice a replaced transcript that is longer than the stored offset', async () => {
    const t = await reconciledWorkSession();
    const { offset } = readOffset(dev.dataDir, t.sessionId);
    const replacement = dev.transcript(t.sessionId);
    replacement.prompt(at(20));
    replacement.reply(at(21));
    while (statSync(t.path).size <= offset + 200) {
      appendFileSync(t.path, `${JSON.stringify({ type: 'summary', summary: 'x'.repeat(100) })}\n`);
    }
    replacement.prompt(at(22));
    replacement.reply(at(23));
    await stopAt(t, 25);
    expect(keysOf(t, 'llm_call')).toHaveLength(2);
  });

  describe('after the pass that strikes a secret', () => {
    async function strickenSession(): Promise<Transcript> {
      await consentToStrikingAwsKeys();
      const t = dev.transcript(randomUUID());
      await start(t, 0);
      appendLeakingPrompt(t, 1);
      await turn(t, 2, dev.workOrg);
      await stopAt(t, 6);
      const struck = readFileSync(t.path);
      expect(struck.includes('[REDACTED:')).toBe(true);
      expect(struck.includes(SECRET)).toBe(false);
      expect(isAgentKeyFor(keysOf(t, 'llm_call')[0], dev.workOrg)).toBe(true);
      return t;
    }

    it('stores offset 0 with no log offset and no carried state', async () => {
      const t = await strickenSession();
      const stored = readOffset(dev.dataDir, t.sessionId);
      expect(stored.offset).toBe(0);
      expect(stored.logOffset).toBeUndefined();
      expect(stored.carried).toBeUndefined();
    });

    it('moves a reply row to the fresh attribution when its output count grew', async () => {
      const t = await strickenSession();
      dev.writeIdentity();
      writeFileSync(
        t.path,
        readFileSync(t.path, 'utf8').replace('"output_tokens":7', '"output_tokens":9'),
      );
      await pass(t, 20);
      expect(keysOf(t, 'llm_call')).toEqual([PERSONAL_KEY]);
    });
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
