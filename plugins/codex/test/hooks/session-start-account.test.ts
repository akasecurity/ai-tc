import { randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  readAttachedIdentity,
  sessionAccountsDir,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import {
  handleSessionStart,
  resolveDataGateway,
  SYNC_MARKER_NAME,
} from '@akasecurity/plugin-runtime';
import {
  claimSessionStart,
  loadConfig,
  recordSessionModel,
  resolveCodexProvider,
} from '@akasecurity/plugin-sdk';
import { readObservations } from '@akasecurity/plugin-sdk/account';
import {
  agentKey,
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX,
  SOURCE_TOOL,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { writeCodexAuth } from '../../../../packages/plugin-sdk/test/helpers/fake-jwt.ts';
import { useLoopbackServer } from '../../../../packages/remote/test/helpers/loopback.ts';
import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { codexSessionStartAccount, threadAccountKey } from '../../src/hooks/account-stamp.ts';
import { handleProhibitedTurn } from '../../src/hooks/model-guard.ts';

// A learn that cannot write the identity record, on request. With `timesOut`
// the gateway's learn answers 'timeout' and the record keeps no work account.
// With `capFilledBy`, those workspaces are written first, as a parallel hook
// would write them, so the write's own cap check inside the lock refuses the
// thread's workspace. Every other case writes through the real persistence call.
const learnWrite = vi.hoisted((): { timesOut: boolean; capFilledBy: string[] } => ({
  timesOut: false,
  capFilledBy: [],
}));
vi.mock('@akasecurity/persistence', async (importOriginal) => {
  const actual = await importOriginal<typeof Persistence>();
  return {
    ...actual,
    recordValidatedWorkAccount: (
      ...args: Parameters<typeof actual.recordValidatedWorkAccount>
    ): ReturnType<typeof actual.recordValidatedWorkAccount> => {
      if (learnWrite.timesOut) return 'timeout';
      const [dataDir, input, now] = args;
      for (const key of learnWrite.capFilledBy.splice(0)) {
        actual.recordValidatedWorkAccount(dataDir, { ...input, key }, now);
      }
      return actual.recordValidatedWorkAccount(...args);
    },
  };
});

const server = useLoopbackServer();

/** Accepts every event of a batch, so the client sees a well-formed acknowledgement and keeps sending. */
const acknowledge: Parameters<typeof server.reply>[0] = (request, response) => {
  let accepted = 1;
  try {
    const body: unknown = JSON.parse(request.body);
    const events =
      typeof body === 'object' && body !== null ? (body as { events?: unknown }).events : undefined;
    if (Array.isArray(events)) accepted = events.length;
  } catch {
    // A body that is not JSON counts as one event.
  }
  response.writeHead(200, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ accepted, duplicates: 0 }));
};

const credentialValue = `test-${randomUUID()}`;
const workspace = randomUUID();
const member = `member-${randomUUID().slice(0, 8)}@example.test`;
const LOCAL_ONLY =
  'AKA: local-only (not enrolled); work in an enrolled repository is still forwarded';
const WORK_LINE =
  'AKA: forwarding this thread to Acme — signed in to a ChatGPT work subscription; it stops if the ' +
  'thread is resumed or its login changes. `aka unenroll --work-subscriptions` stops this on this device.';
const PENDING =
  "This thread's ChatGPT account is checked once more at its next prompt or tool call. If this " +
  'device then recognises it as a work subscription, or it is a workspace you enrolled by hand, the ' +
  "thread's prompts, tool calls and results are forwarded to Acme from any folder from then on. " +
  'Otherwise, including if the account still cannot be read, the thread follows the repository rule.';
const RESUMED_LINE =
  'AKA: this thread first ran under a ChatGPT workspace forwarded to Acme; from here it follows the ' +
  'repository rule, so only work in an enrolled repository is forwarded.';

let base: string;
let home: string;
let personal: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-codex-start-'));
  home = mkdtempSync(join(tmpdir(), 'aka-codex-start-home-'));
  personal = mkdtempSync(join(tmpdir(), 'aka-codex-start-personal-'));
  for (const name of ['CODEX_HOME', 'CODEX_API_KEY', 'CODEX_ACCESS_TOKEN', 'OPENAI_BASE_URL']) {
    vi.stubEnv(name, undefined);
  }
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: {
        endpoint: server.origin,
        label: 'Acme',
        attachedAt: '2026-10-01T09:00:00.000Z',
      },
      attachmentScope: {
        endpoint: server.origin,
        tenantName: 'Acme',
        userEmail: member,
        entries: [],
      },
    },
    base,
    null,
  );
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
    mode: 'scoped',
    endpoint: server.origin,
    apiKey: credentialValue,
  });
  writeAttachedIdentity(dataDirOf(base), {
    endpoint: server.origin,
    apiKey: credentialValue,
    tenantName: 'Acme',
    userEmail: member,
  });
  // A policy sync attempted just now, so the session start this suite drives
  // does not spawn the detached sync child against the loopback deployment.
  writeFileSync(join(dataDirOf(base), SYNC_MARKER_NAME), String(Date.now()));
  server.received.length = 0;
  server.reply(acknowledge);
});

afterEach(() => {
  learnWrite.timesOut = false;
  learnWrite.capFilledBy = [];
  vi.unstubAllEnvs();
  for (const dir of [base, home, personal]) removeTree(dir);
});

function rollout(sessionId: string): string {
  const path = join(personal, `rollout-${sessionId}.jsonl`);
  writeFileSync(
    path,
    `${JSON.stringify({ type: 'session_meta', payload: { session_id: sessionId, id: sessionId, model_provider: 'openai', creator_account_id: workspace } })}\n`,
  );
  return path;
}

/** The scope key the local store holds for every session root. */
function rootKeys(): (string | null)[] {
  const db = new DatabaseSync(dbPathOf(base));
  try {
    const rows = db
      .prepare("SELECT scope_key AS key FROM audit_events WHERE event_type = 'session'")
      .all() as { key: string | null }[];
    return rows.map((row) => row.key);
  } finally {
    db.close();
  }
}

function startLines(sessionId: string) {
  return readObservations(sessionAccountsDir(dataDirOf(base)), sessionId).entries.map(
    (entry) => entry.observation,
  );
}

async function start(
  source: string,
  plan: string,
  cwd = personal,
): Promise<{ line: string | null; sessionId: string; transcriptPath: string }> {
  writeCodexAuth(join(home, '.codex'), { accountId: workspace, email: member, plan });
  const sessionId = randomUUID();
  const transcriptPath = rollout(sessionId);
  const config = loadConfig(base, resolveCodexProvider);
  const fields = await codexSessionStartAccount(config, {
    sessionId,
    source,
    transcriptPath,
    cwd,
    nowMs: Date.now(),
    home,
  });
  const result = await handleSessionStart(
    { sessionId, cwd, tool: SOURCE_TOOL.Codex, homeDir: base, ...fields },
    config,
  );
  return { line: result.forwardingLine, sessionId, transcriptPath };
}

describe('Codex SessionStart on a ChatGPT work subscription', () => {
  it('roots a fresh work thread under its agent key, and says so with the opt-out', async () => {
    const { line } = await start('startup', 'business');
    const record = readAttachedIdentity(dataDirOf(base));
    if (record === undefined) throw new Error('no identity record');
    expect(rootKeys()).toEqual([agentKey(record.scopeTag, `chatgpt:${workspace}`)]);
    expect(line).toBe(WORK_LINE);
    for (const material of ['chatgpt:', 'agent:', workspace]) expect(line).not.toContain(material);
  });

  it('roots the thread under its agent key when the learn timed out, through the admission', async () => {
    learnWrite.timesOut = true;
    await start('startup', 'business');
    const record = readAttachedIdentity(dataDirOf(base));
    if (record === undefined) throw new Error('no identity record');
    expect(record.workAccounts).toEqual([]);
    expect(rootKeys()).toEqual([agentKey(record.scopeTag, `chatgpt:${workspace}`)]);
  });

  it("does not admit a thread's account when the learned-account cap refuses it", async () => {
    learnWrite.capFilledBy = Array.from(
      { length: ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX },
      () => `chatgpt:${randomUUID()}`,
    );
    const { line } = await start('startup', 'business');
    const learnedKeys = (readAttachedIdentity(dataDirOf(base))?.workAccounts ?? []).map(
      (entry) => entry.identity,
    );
    expect(learnedKeys).toHaveLength(ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX);
    expect(learnedKeys).not.toContain(`chatgpt:${workspace}`);
    expect(rootKeys()).toEqual([null]);
    expect(line).not.toBe(WORK_LINE);
  });

  it('keeps a personal login local-only, rooted by its folder', async () => {
    expect((await start('startup', 'plus')).line).toBe(LOCAL_ONLY);
    expect(rootKeys()).toEqual([null]);
  });

  it('writes a resumed thread sticky line, and roots it by its folder', async () => {
    const { line, sessionId } = await start('resume', 'business');
    expect(line).toBe(LOCAL_ONLY);
    expect(rootKeys()).toEqual([null]);
    expect(startLines(sessionId)).toEqual([
      expect.objectContaining({ start: 'resume', s: 'none' }),
    ]);
  });

  it('writes the start line whether or not the session was already claimed', async () => {
    writeCodexAuth(join(home, '.codex'), { accountId: workspace, email: member, plan: 'business' });
    const sessionId = randomUUID();
    const config = loadConfig(base, resolveCodexProvider);
    await handleSessionStart(
      { sessionId, cwd: personal, tool: SOURCE_TOOL.Codex, homeDir: base },
      config,
    );
    await codexSessionStartAccount(config, {
      sessionId,
      source: 'startup',
      transcriptPath: rollout(sessionId),
      cwd: personal,
      nowMs: Date.now(),
      home,
    });
    expect(startLines(sessionId)).toEqual([expect.objectContaining({ start: 'startup' })]);
  });
});

describe('what a recognised thread sends when its session starts', () => {
  const branch = `topic-${randomUUID().slice(0, 8)}`;
  const project = `notes-${randomUUID().slice(0, 8)}`;
  let notes: string;

  beforeEach(() => {
    notes = mkdtempSync(join(tmpdir(), 'aka-codex-start-notes-'));
    mkdirSync(join(notes, '.git'), { recursive: true });
    writeFileSync(join(notes, '.git', 'HEAD'), `ref: refs/heads/${branch}\n`);
    writeFileSync(
      join(notes, '.git', 'config'),
      `[remote "origin"]\n\turl = https://github.com/me/${project}.git\n`,
    );
  });
  afterEach(() => {
    removeTree(notes);
  });

  const sentWith = (...needles: string[]): boolean =>
    server.received.some((request) => needles.every((needle) => request.body.includes(needle)));

  it("sends the session root with the folder's project and branch names", async () => {
    const { sessionId } = await start('startup', 'business', notes);
    expect(sentWith(sessionId, branch, project)).toBe(true);
  });

  it("sends the folder's project in the inventory", async () => {
    const { sessionId } = await start('startup', 'business', notes);
    const inventory = server.received.filter(
      (request) => request.body.includes(project) && !request.body.includes(sessionId),
    );
    expect(inventory.length).toBeGreaterThan(0);
  });

  it('sends nothing of the account with the root and the inventory', async () => {
    const plan = 'enterprise_cbp_usage_based';
    await start('startup', plan, notes);
    const record = readAttachedIdentity(dataDirOf(base));
    if (record === undefined) throw new Error('no identity record');
    const sent = server.received
      .map((request) => `${request.url ?? ''} ${JSON.stringify(request.headers)} ${request.body}`)
      .join('\n');
    expect(server.received.length).toBeGreaterThan(0);
    for (const material of [
      workspace,
      'chatgpt:',
      'agent:',
      member,
      plan,
      record.attachedUserDigest,
      record.scopeTag,
    ]) {
      expect(sent).not.toContain(material);
    }
  });

  it('sends neither the root nor the inventory of a personal-plan thread', async () => {
    const { sessionId } = await start('startup', 'plus', notes);
    expect(sentWith(sessionId)).toBe(false);
    expect(sentWith(branch)).toBe(false);
    expect(sentWith(project)).toBe(false);
  });

  it('sends neither the root nor the inventory of a resumed thread', async () => {
    const { sessionId } = await start('resume', 'business', notes);
    expect(sentWith(sessionId)).toBe(false);
    expect(sentWith(project)).toBe(false);
  });

  it('sends the same without a history grant', async () => {
    expect(loadConfig(base).settings.historySyncConsent).toBeUndefined();
    const { sessionId } = await start('startup', 'business', notes);
    expect(sentWith(sessionId, branch, project)).toBe(true);
  });
});

describe('a work thread resumed once its session claim has lapsed', () => {
  /** Claims enough other sessions that the recent-session window drops the thread. */
  function lapseClaim(): void {
    for (let i = 0; i < 40; i++) claimSessionStart(dataDirOf(base), randomUUID());
  }

  it('says the thread follows the repository rule, and stamps it by that rule', async () => {
    const first = await start('startup', 'business');
    expect(first.line).toBe(WORK_LINE);
    lapseClaim();
    const config = loadConfig(base, resolveCodexProvider);
    const fields = await codexSessionStartAccount(config, {
      sessionId: first.sessionId,
      source: 'resume',
      transcriptPath: first.transcriptPath,
      cwd: personal,
      nowMs: Date.now(),
      home,
    });
    const resumed = await handleSessionStart(
      {
        sessionId: first.sessionId,
        cwd: personal,
        tool: SOURCE_TOOL.Codex,
        homeDir: base,
        ...fields,
      },
      config,
    );
    expect(resumed.forwardingLine).toBe(RESUMED_LINE);
    const gateway = resolveDataGateway(config);
    try {
      expect(
        threadAccountKey(gateway, {
          dataDir: dataDirOf(base),
          sessionId: first.sessionId,
          transcriptPath: first.transcriptPath,
          nowMs: Date.now(),
          home,
        }),
      ).toBeUndefined();
    } finally {
      await gateway.close();
    }
  });
});

describe('a thread whose first rollout line is not on disk at session start', () => {
  /** A session start whose transcript path names a file Codex has not written yet. */
  async function startWithoutHead(cwd = personal): Promise<{
    sessionId: string;
    transcriptPath: string;
    line: string | null;
  }> {
    writeCodexAuth(join(home, '.codex'), { accountId: workspace, email: member, plan: 'business' });
    const sessionId = randomUUID();
    const transcriptPath = join(personal, `rollout-${sessionId}.jsonl`);
    const config = loadConfig(base, resolveCodexProvider);
    const fields = await codexSessionStartAccount(config, {
      sessionId,
      source: 'startup',
      transcriptPath,
      cwd,
      nowMs: Date.now(),
      home,
    });
    const result = await handleSessionStart(
      { sessionId, cwd, tool: SOURCE_TOOL.Codex, homeDir: base, ...fields },
      config,
    );
    return { sessionId, transcriptPath, line: result.forwardingLine };
  }

  it('keeps the session root on its folder rule, and leaves a pending start line', async () => {
    const { sessionId, line } = await startWithoutHead();
    expect(rootKeys()).toEqual([null]);
    expect(line).toBe(`${LOCAL_ONLY}. ${PENDING}`);
    expect(startLines(sessionId)).toEqual([
      expect.objectContaining({ start: 'startup', s: 'pending' }),
    ]);
  });

  it('names the enrolled folder it starts in, then what the next check can change', async () => {
    const project = `notes-${randomUUID().slice(0, 8)}`;
    const enrolled = mkdtempSync(join(tmpdir(), 'aka-codex-start-enrolled-'));
    try {
      mkdirSync(join(enrolled, '.git'), { recursive: true });
      writeFileSync(
        join(enrolled, '.git', 'config'),
        `[remote "origin"]\n\turl = https://github.com/me/${project}.git\n`,
      );
      applyOnboarding(
        {
          attachmentScope: {
            endpoint: server.origin,
            tenantName: 'Acme',
            userEmail: member,
            entries: [
              {
                kind: 'repo',
                identity: `github.com/me/${project}`,
                enrolledAt: '2026-10-02T09:00:00.000Z',
              },
            ],
          },
        },
        base,
        null,
      );
      const { line } = await startWithoutHead(enrolled);
      expect(rootKeys()).toEqual([`github.com/me/${project}`]);
      expect(line).toBe(`AKA: forwarding to Acme (github.com/me/${project}). ${PENDING}`);
    } finally {
      removeTree(enrolled);
    }
  });

  it('still decides the thread at its next hook, though its root stays on the folder rule', async () => {
    const { sessionId, transcriptPath } = await startWithoutHead();
    rollout(sessionId);
    const gateway = resolveDataGateway(loadConfig(base, resolveCodexProvider));
    try {
      expect(
        threadAccountKey(gateway, {
          dataDir: dataDirOf(base),
          sessionId,
          transcriptPath,
          nowMs: Date.now(),
          home,
        }),
      ).toBe(`chatgpt:${workspace}`);
    } finally {
      await gateway.close();
    }
    expect(rootKeys()).toEqual([null]);
  });

  describe('on a device opted out of work subscriptions', () => {
    function optOut(enrolledByHand: string | undefined): void {
      applyOnboarding(
        {
          attachmentScope: {
            endpoint: server.origin,
            tenantName: 'Acme',
            userEmail: member,
            workSubscriptions: 'off',
            entries:
              enrolledByHand === undefined
                ? []
                : [
                    {
                      kind: 'account',
                      identity: `chatgpt:${enrolledByHand}`,
                      enrolledAt: '2026-10-02T09:00:00.000Z',
                      codingAgents: true,
                    },
                  ],
          },
        },
        base,
        null,
      );
    }

    async function nextHook(
      sessionId: string,
      transcriptPath: string,
    ): Promise<string | undefined> {
      rollout(sessionId);
      const gateway = resolveDataGateway(loadConfig(base, resolveCodexProvider));
      try {
        return threadAccountKey(gateway, {
          dataDir: dataDirOf(base),
          sessionId,
          transcriptPath,
          nowMs: Date.now(),
          home,
        });
      } finally {
        await gateway.close();
      }
    }

    it('forwards a workspace enrolled by hand at the next check, as the line says', async () => {
      optOut(workspace);
      const { sessionId, transcriptPath, line } = await startWithoutHead();
      expect(line).toBe(`${LOCAL_ONLY}. ${PENDING}`);
      expect(await nextHook(sessionId, transcriptPath)).toBe(`chatgpt:${workspace}`);
      expect(readAttachedIdentity(dataDirOf(base))?.workAccounts).toEqual([]);
    });

    it('recognises nothing at the next check when only another workspace is enrolled by hand', async () => {
      optOut(randomUUID());
      const { sessionId, transcriptPath, line } = await startWithoutHead();
      expect(line).toBe(`${LOCAL_ONLY}. ${PENDING}`);
      expect(await nextHook(sessionId, transcriptPath)).toBeUndefined();
      expect(readAttachedIdentity(dataDirOf(base))?.workAccounts).toEqual([]);
    });

    it('leaves the thread undecided, and says nothing of a next check, with no workspace enrolled by hand', async () => {
      optOut(undefined);
      const { sessionId, transcriptPath, line } = await startWithoutHead();
      expect(line).toBe(LOCAL_ONLY);
      expect(await nextHook(sessionId, transcriptPath)).toBeUndefined();
      expect(readAttachedIdentity(dataDirOf(base))?.workAccounts).toEqual([]);
    });
  });
});

describe('the prohibited-model refusal through an attached gateway', () => {
  /** The attached gateway, with only the organization's prohibition list stubbed. */
  function withProhibition(real: ReturnType<typeof resolveDataGateway>) {
    return new Proxy(real, {
      get(target, property) {
        if (property === 'getPolicyBundle') {
          return () => Promise.resolve({ prohibitedModels: ['o3'] });
        }
        const value: unknown = Reflect.get(target, property);
        return typeof value === 'function' ? (value as () => unknown).bind(target) : value;
      },
    });
  }

  async function refuse(plan: string): Promise<{ stop: boolean; refusalKeys: (string | null)[] }> {
    const { sessionId, transcriptPath } = await start('startup', plan);
    recordSessionModel(dataDirOf(base), sessionId, 'o3');
    const config = loadConfig(base, resolveCodexProvider);
    const real = resolveDataGateway(config);
    const accountKey = threadAccountKey(real, {
      dataDir: dataDirOf(base),
      sessionId,
      transcriptPath,
      nowMs: Date.now(),
      home,
    });
    const stop = await handleProhibitedTurn(
      withProhibition(real),
      dataDirOf(base),
      sessionId,
      transcriptPath,
      personal,
      accountKey,
      () => Promise.resolve(),
    );
    if (!stop) await real.close();
    const db = new DatabaseSync(dbPathOf(base));
    try {
      const rows = db
        .prepare("SELECT scope_key AS key FROM audit_events WHERE event_type = 'model_refusal'")
        .all() as { key: string | null }[];
      return { stop, refusalKeys: rows.map((row) => row.key) };
    } finally {
      db.close();
    }
  }

  it('is refused in a folder no repository rule covers, with the row keyed for the thread', async () => {
    const { stop, refusalKeys } = await refuse('business');
    const record = readAttachedIdentity(dataDirOf(base));
    if (record === undefined) throw new Error('no identity record');
    expect(stop).toBe(true);
    expect(refusalKeys).toEqual([agentKey(record.scopeTag, `chatgpt:${workspace}`)]);
  });

  it('is allowed, with no row, in the same folder outside a work thread', async () => {
    const { stop, refusalKeys } = await refuse('plus');
    expect(stop).toBe(false);
    expect(refusalKeys).toEqual([]);
  });
});
