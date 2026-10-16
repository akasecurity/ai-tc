import { randomUUID } from 'node:crypto';
import type * as Fs from 'node:fs';
import { existsSync, mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  forgetWorkAccounts,
  readAttachedIdentity,
  sessionAccountsDir,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { AccountScope, StampedScopeKey } from '@akasecurity/plugin-runtime';
import {
  accountScopeOf,
  configuredGatewayFactory,
  resolveDataGateway,
  setDefaultGatewayFactory,
} from '@akasecurity/plugin-runtime';
import { createPluginRuntime, loadConfig, recordSessionModel } from '@akasecurity/plugin-sdk';
import {
  appendObservation,
  codexAuthFingerprint,
  readObservations,
  sessionAccountHash,
} from '@akasecurity/plugin-sdk/account';
import type { SessionAccountObservation } from '@akasecurity/schema';
import {
  agentKey,
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  HISTORY_SYNC_PAYLOAD_VERSION,
  SOURCE_TOOL,
} from '@akasecurity/schema';
import { ESLint, Linter } from 'eslint';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { writeCodexAuth } from '../../../../packages/plugin-sdk/test/helpers/fake-jwt.ts';
import { useLoopbackServer } from '../../../../packages/remote/test/helpers/loopback.ts';
import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { ThreadAccount } from '../../src/hooks/account-stamp.ts';
import {
  codexSessionStartAccount,
  codexToolStamp,
  noteThreadAccount,
  startThreadAccount,
  threadAccountKey,
} from '../../src/hooks/account-stamp.ts';
import { handleProhibitedTurn } from '../../src/hooks/model-guard.ts';
import { captureScopeKey } from '../../src/hooks/shared.ts';
import { captureStamped, stampFor } from '../../src/hooks/stamped-capture.ts';

// How often the login file is opened, counted at the module every reader imports.
const opens = vi.hoisted(() => ({ loginFile: 0 }));
vi.mock('node:fs', async (importActual) => {
  const actual = await importActual<typeof Fs>();
  return {
    ...actual,
    openSync: (...args: Parameters<typeof actual.openSync>) => {
      if (String(args[0]).endsWith('auth.json')) opens.loginFile += 1;
      return actual.openSync(...args);
    },
  };
});

// The deployment is a loopback server, so what a hook forwards can be read back.
// Every identity is generated per run.
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
const otherWorkspace = randomUUID();
const chatgptKey = `chatgpt:${workspace}`;
const member = `member-${randomUUID().slice(0, 8)}@example.test`;
const someoneElse = `other-${randomUUID().slice(0, 8)}@example.test`;
const WORK_KEY = 'github.com/acme/work';

let base: string;
let home: string;
let sessions: string;
let personal: string;
let work: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-codex-account-'));
  home = mkdtempSync(join(tmpdir(), 'aka-codex-account-home-'));
  sessions = mkdtempSync(join(tmpdir(), 'aka-codex-account-sessions-'));
  personal = mkdtempSync(join(tmpdir(), 'aka-codex-account-personal-'));
  work = mkdtempSync(join(tmpdir(), 'aka-codex-account-work-'));
  mkdirSync(join(work, '.git'), { recursive: true });
  writeFileSync(
    join(work, '.git', 'config'),
    '[remote "origin"]\n\turl = https://github.com/acme/work.git\n',
  );
  // Codex's home is the one under `home`, and nothing in the environment of the
  // machine running the suite vetoes the login or moves the home.
  for (const name of ['CODEX_HOME', 'CODEX_API_KEY', 'CODEX_ACCESS_TOKEN', 'OPENAI_BASE_URL']) {
    vi.stubEnv(name, undefined);
  }
  server.received.length = 0;
  server.reply(acknowledge);
  opens.loginFile = 0;
});

afterEach(() => {
  vi.unstubAllEnvs();
  for (const dir of [base, home, sessions, personal, work]) removeTree(dir);
});

const dataDir = (): string => dataDirOf(base);
const codexHomeUnder = (dir: string): string => join(dir, '.codex');

function scope(options: { entries?: unknown[]; off?: boolean } = {}): Record<string, unknown> {
  return {
    endpoint: server.origin,
    tenantName: 'Acme',
    userEmail: member,
    entries: options.entries ?? [],
    ...(options.off === true ? { workSubscriptions: 'off' } : {}),
  };
}

// Typed by the writer's own parameter, so the version stays the literal it requires.
function credential(): Parameters<typeof writeControlPlaneCredential>[1] {
  return {
    specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
    mode: 'scoped',
    endpoint: server.origin,
    apiKey: credentialValue,
  };
}

function attachScoped(options: { entries?: unknown[]; off?: boolean } = {}): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: {
        endpoint: server.origin,
        label: 'Acme',
        attachedAt: '2026-10-01T09:00:00.000Z',
      },
      attachmentScope: scope(options),
    },
    base,
    null,
  );
  writeControlPlaneCredential(settingsDirOf(base), credential());
  writeAttachedIdentity(dataDir(), {
    endpoint: server.origin,
    apiKey: credentialValue,
    tenantName: 'Acme',
    userEmail: member,
  });
}

function manual(identity = chatgptKey) {
  return { kind: 'account', identity, enrolledAt: '2026-10-02T09:00:00.000Z', codingAgents: true };
}

/** Codex signed in under `under`; every write gives the login file a new fingerprint. */
function signIn(plan: unknown, account = workspace, email = member, under = home): void {
  writeCodexAuth(codexHomeUnder(under), {
    accountId: account,
    email,
    ...(plan === undefined ? {} : { plan }),
  });
}

function rollout(sessionId: string, options: { account?: string; provider?: string } = {}): string {
  const path = join(sessions, `rollout-${sessionId}.jsonl`);
  const head = {
    timestamp: new Date().toISOString(),
    type: 'session_meta',
    payload: {
      session_id: sessionId,
      id: sessionId,
      cwd: personal,
      originator: 'codex_cli_rs',
      model_provider: options.provider ?? 'openai',
      creator_account_id: options.account ?? workspace,
    },
  };
  writeFileSync(path, `${JSON.stringify(head)}\n`);
  return path;
}

const gatewayNow = () => resolveDataGateway(loadConfig(base));

function learned(): string[] {
  return (readAttachedIdentity(dataDir())?.workAccounts ?? []).map((entry) => entry.identity);
}

function tag(): string {
  const record = readAttachedIdentity(dataDir());
  if (record === undefined) throw new Error('no identity record');
  return record.scopeTag;
}

function threadLog(sessionId: string): SessionAccountObservation[] {
  return readObservations(sessionAccountsDir(dataDir()), sessionId).entries.map(
    (entry) => entry.observation,
  );
}

interface Thread {
  sessionId: string;
  transcriptPath: string;
  home: string;
  account: ThreadAccount;
}

async function startThread(
  source = 'startup',
  rolloutOptions: { account?: string; provider?: string } = {},
  under = home,
): Promise<Thread> {
  const sessionId = randomUUID();
  const transcriptPath = rollout(sessionId, rolloutOptions);
  const gateway = gatewayNow();
  try {
    const account = startThreadAccount(gateway, {
      dataDir: dataDir(),
      sessionId,
      source,
      transcriptPath,
      nowMs: Date.now(),
      home: under,
    });
    return { sessionId, transcriptPath, home: under, account };
  } finally {
    await gateway.close();
  }
}

async function hookAccount(thread: Thread): Promise<string | undefined> {
  const gateway = gatewayNow();
  try {
    return threadAccountKey(gateway, {
      dataDir: dataDir(),
      sessionId: thread.sessionId,
      transcriptPath: thread.transcriptPath,
      nowMs: Date.now(),
      home: thread.home,
    });
  } finally {
    await gateway.close();
  }
}

describe('a Codex thread on a ChatGPT work subscription', () => {
  it('stamps a personal folder prompt with the thread agent key, forwards it, and learns the workspace', async () => {
    attachScoped();
    signIn('business');
    const thread = await startThread();
    expect(thread.account).toEqual({ accountKey: chatgptKey, basis: 'validated' });
    expect(learned()).toEqual([chatgptKey]);
    const marker = `prompt-${randomUUID()}`;
    const gateway = gatewayNow();
    const accountKey = threadAccountKey(gateway, {
      dataDir: dataDir(),
      sessionId: thread.sessionId,
      transcriptPath: thread.transcriptPath,
      nowMs: Date.now(),
      home,
    });
    expect(accountKey).toBe(chatgptKey);
    const key = stampFor(gateway, captureScopeKey({ cwd: personal }), accountKey);
    expect(key).toBe(agentKey(tag(), chatgptKey));
    const runtime = createPluginRuntime(gateway, loadConfig(base).settings, { dataDir: dataDir() });
    try {
      await captureStamped(
        runtime,
        {
          kind: 'prompt',
          sourceTool: SOURCE_TOOL.Codex,
          text: marker,
          metadata: { sessionId: thread.sessionId },
        },
        key,
      );
    } finally {
      await runtime.close();
    }
    expect(server.received.some((request) => request.body.includes(marker))).toBe(true);
  });

  it('keeps an enrolled repository key, and gives an apply_patch with no repository the agent key', async () => {
    attachScoped({
      entries: [{ kind: 'repo', identity: WORK_KEY, enrolledAt: '2026-10-02T09:00:00.000Z' }],
    });
    signIn('business');
    const thread = await startThread();
    const accountKey = await hookAccount(thread);
    const gateway = gatewayNow();
    try {
      expect(codexToolStamp(gateway, { cwd: work }, 'Bash', accountKey)).toBe(WORK_KEY);
      expect(codexToolStamp(gateway, { cwd: work }, 'apply_patch', accountKey)).toBe(
        agentKey(tag(), chatgptKey),
      );
    } finally {
      await gateway.close();
    }
  });

  it('leaves a personal thread apply_patch keyless', async () => {
    attachScoped();
    signIn('plus');
    const thread = await startThread();
    expect(thread.account.accountKey).toBeUndefined();
    const accountKey = await hookAccount(thread);
    expect(accountKey).toBeUndefined();
    const gateway = gatewayNow();
    try {
      expect(codexToolStamp(gateway, { cwd: personal }, 'apply_patch', accountKey)).toBeUndefined();
    } finally {
      await gateway.close();
    }
    expect(learned()).toEqual([]);
  });

  it('sends nothing of the account to the deployment', async () => {
    attachScoped();
    signIn('business');
    const thread = await startThread();
    const accountKey = await hookAccount(thread);
    const gateway = gatewayNow();
    const runtime = createPluginRuntime(gateway, loadConfig(base).settings, { dataDir: dataDir() });
    const metadata = { sessionId: thread.sessionId };
    try {
      await captureStamped(
        runtime,
        { kind: 'prompt', sourceTool: SOURCE_TOOL.Codex, text: 'a prompt', metadata },
        stampFor(gateway, undefined, accountKey),
      );
      await captureStamped(
        runtime,
        { kind: 'tool_use', sourceTool: SOURCE_TOOL.Codex, text: 'ls', metadata },
        codexToolStamp(gateway, { cwd: personal }, 'Bash', accountKey),
      );
      await captureStamped(
        runtime,
        { kind: 'code_change', sourceTool: SOURCE_TOOL.Codex, text: '*** Begin Patch', metadata },
        codexToolStamp(gateway, { cwd: personal }, 'apply_patch', accountKey),
      );
    } finally {
      await runtime.close();
    }
    const record = readAttachedIdentity(dataDir());
    if (record === undefined) throw new Error('no identity record');
    const sent = server.received
      .map((r) => `${r.url ?? ''} ${JSON.stringify(r.headers)} ${r.body}`)
      .join('\n');
    expect(server.received.length).toBeGreaterThan(0);
    for (const material of [
      workspace,
      'chatgpt:',
      'agent:',
      member,
      record.attachedUserDigest,
      record.scopeTag,
    ]) {
      expect(sent).not.toContain(material);
    }
  });
});

describe('a Codex thread that keeps the repository rule', () => {
  it.each<[string, () => Promise<Thread>]>([
    ['a resumed thread', () => startThread('resume')],
    ['another provider', () => startThread('startup', { provider: 'azure' })],
    [
      'an API key in the environment',
      () => {
        vi.stubEnv('CODEX_API_KEY', `stubbed-${randomUUID()}`);
        return startThread();
      },
    ],
  ])('%s', async (_name, start) => {
    attachScoped();
    signIn('business');
    const thread = await start();
    expect(thread.account.accountKey).toBeUndefined();
    expect(await hookAccount(thread)).toBeUndefined();
    expect(learned()).toEqual([]);
  });

  it('an opted-out attachment learns nothing, and a manual key still forwards', async () => {
    attachScoped({ off: true });
    signIn('business');
    const opted = await startThread();
    expect(opted.account.accountKey).toBeUndefined();
    expect(await hookAccount(opted)).toBeUndefined();
    expect(learned()).toEqual([]);
    attachScoped({ off: true, entries: [manual()] });
    const enrolledByHand = await startThread();
    expect(enrolledByHand.account).toEqual({ accountKey: chatgptKey, basis: 'manual' });
    expect(await hookAccount(enrolledByHand)).toBe(chatgptKey);
  });

  it('no login file gives none, a manual entry included', async () => {
    attachScoped({ entries: [manual()] });
    const thread = await startThread();
    expect(thread.account.accountKey).toBeUndefined();
    expect(await hookAccount(thread)).toBeUndefined();
  });

  it('a manual key forwards only while the live login is the thread own account', async () => {
    attachScoped({ entries: [manual()] });
    signIn('plus', workspace, someoneElse);
    const own = await startThread();
    expect(own.account.accountKey).toBe(chatgptKey);
    expect(await hookAccount(own)).toBe(chatgptKey);
    signIn('business', otherWorkspace);
    const other = await startThread();
    expect(other.account.accountKey).toBeUndefined();
    expect(await hookAccount(other)).toBeUndefined();
  });
});

describe('a change to the login file inside a thread', () => {
  it('keeps forwarding after a token refresh, with a new baseline line', async () => {
    attachScoped();
    signIn('business');
    const thread = await startThread();
    signIn('business');
    expect(await hookAccount(thread)).toBe(chatgptKey);
    const baselines = threadLog(thread.sessionId).filter(
      (line) => !('start' in line) && 's' in line && line.s !== 'none',
    );
    expect(baselines).toHaveLength(1);
  });

  it.each<[string, () => void]>([
    [
      'an account switch',
      () => {
        signIn('business', otherWorkspace);
      },
    ],
    [
      'a personal plan',
      () => {
        signIn('plus');
      },
    ],
    [
      'another address',
      () => {
        signIn('business', workspace, someoneElse);
      },
    ],
  ])('ends the thread for good after %s', async (_name, change) => {
    attachScoped();
    signIn('business');
    const thread = await startThread();
    change();
    expect(await hookAccount(thread)).toBeUndefined();
    signIn('business');
    expect(await hookAccount(thread)).toBeUndefined();
  });

  it('ends the thread when the account switches after a token refresh', async () => {
    attachScoped();
    signIn('business');
    const thread = await startThread();
    signIn('business');
    expect(await hookAccount(thread)).toBe(chatgptKey);
    signIn('business', otherWorkspace);
    expect(await hookAccount(thread)).toBeUndefined();
  });

  it('opens the login file once at session start and once per change, and only checks it otherwise', async () => {
    attachScoped();
    signIn('business');
    opens.loginFile = 0;
    const thread = await startThread();
    expect(opens.loginFile).toBe(1);
    await hookAccount(thread);
    await hookAccount(thread);
    expect(opens.loginFile).toBe(1);
    signIn('business');
    opens.loginFile = 0;
    await hookAccount(thread);
    await hookAccount(thread);
    expect(opens.loginFile).toBe(1);
  });
});

describe('a thread whose first rollout line was not on disk at session start', () => {
  async function startWithoutHead(): Promise<Thread> {
    const sessionId = randomUUID();
    const transcriptPath = join(sessions, `rollout-${sessionId}.jsonl`);
    const gateway = gatewayNow();
    try {
      const account = startThreadAccount(gateway, {
        dataDir: dataDir(),
        sessionId,
        source: 'startup',
        transcriptPath,
        nowMs: Date.now(),
        home,
      });
      return { sessionId, transcriptPath, home, account };
    } finally {
      await gateway.close();
    }
  }

  it('writes a pending start line, and the next hook decides the thread once its head is there', async () => {
    attachScoped();
    signIn('business');
    const thread = await startWithoutHead();
    expect(thread.account.accountKey).toBeUndefined();
    expect(threadLog(thread.sessionId)).toEqual([
      expect.objectContaining({ start: 'startup', s: 'pending' }),
    ]);
    rollout(thread.sessionId);
    expect(await hookAccount(thread)).toBe(chatgptKey);
    expect(learned()).toEqual([chatgptKey]);
  });

  it('gives none for good when the head is still missing at the next hook', async () => {
    attachScoped();
    signIn('business');
    const thread = await startWithoutHead();
    expect(await hookAccount(thread)).toBeUndefined();
    rollout(thread.sessionId);
    expect(await hookAccount(thread)).toBeUndefined();
    expect(learned()).toEqual([]);
  });
});

describe('a validated workspace this device has not written down', () => {
  async function timedOutStart(): Promise<Thread> {
    const sessionId = randomUUID();
    const transcriptPath = rollout(sessionId);
    const gateway = gatewayNow();
    try {
      const account = accountScopeOf(gateway);
      if (account === undefined) throw new Error('no account scope');
      appendObservation(sessionAccountsDir(dataDir()), sessionId, {
        t: Date.now(),
        bd: account.bindingHash,
        start: 'startup',
        s: sessionAccountHash(chatgptKey),
        fp: codexAuthFingerprint(codexHomeUnder(home)),
      });
      return {
        sessionId,
        transcriptPath,
        home,
        account: { accountKey: undefined, basis: undefined },
      };
    } finally {
      await gateway.close();
    }
  }

  it('is learned by a later hook of the same thread', async () => {
    attachScoped();
    signIn('business');
    const thread = await timedOutStart();
    expect(learned()).toEqual([]);
    expect(await hookAccount(thread)).toBe(chatgptKey);
    expect(learned()).toEqual([chatgptKey]);
  });

  it('is learned again after an opt-out and an opt-in inside one thread, and never while opted out', async () => {
    attachScoped();
    signIn('business');
    const thread = await startThread();
    forgetWorkAccounts(dataDir(), { endpoint: server.origin, credential: credential() });
    applyOnboarding({ attachmentScope: scope({ off: true }) }, base, null);
    expect(await hookAccount(thread)).toBeUndefined();
    expect(learned()).toEqual([]);
    applyOnboarding({ attachmentScope: scope() }, base, null);
    expect(await hookAccount(thread)).toBe(chatgptKey);
    expect(learned()).toEqual([chatgptKey]);
  });

  it('learns nothing and reads no login file while opted out, even with another workspace enrolled by hand', async () => {
    const elsewhere = manual(`chatgpt:${otherWorkspace}`);
    attachScoped({ entries: [elsewhere] });
    signIn('business');
    const thread = await startThread();
    forgetWorkAccounts(dataDir(), { endpoint: server.origin, credential: credential() });
    applyOnboarding({ attachmentScope: scope({ off: true, entries: [elsewhere] }) }, base, null);
    opens.loginFile = 0;
    expect(await hookAccount(thread)).toBeUndefined();
    expect(learned()).toEqual([]);
    expect(opens.loginFile).toBe(0);
  });

  it('a thread on a manual key reads the login file only when it changes', async () => {
    attachScoped({ entries: [manual()] });
    signIn('business');
    const thread = await startThread();
    opens.loginFile = 0;
    expect(await hookAccount(thread)).toBe(chatgptKey);
    expect(await hookAccount(thread)).toBe(chatgptKey);
    expect(opens.loginFile).toBe(0);
  });
});

describe('two Codex threads on one device under two Codex homes', () => {
  it('decides each thread by its own login, and the learned workspace never stamps the other one', async () => {
    attachScoped();
    const personalHome = mkdtempSync(join(tmpdir(), 'aka-codex-account-home-personal-'));
    try {
      signIn('business');
      signIn('plus', otherWorkspace, member, personalHome);
      const workThread = await startThread();
      const personalThread = await startThread(
        'startup',
        { account: otherWorkspace },
        personalHome,
      );
      expect(workThread.account.accountKey).toBe(chatgptKey);
      expect(personalThread.account.accountKey).toBeUndefined();
      expect(learned()).toEqual([chatgptKey]);
      expect(await hookAccount(personalThread)).toBeUndefined();
      expect(await hookAccount(workThread)).toBe(chatgptKey);
      expect(threadLog(personalThread.sessionId)).toEqual([
        expect.objectContaining({ start: 'startup', s: 'none' }),
      ]);
    } finally {
      removeTree(personalHome);
    }
  });
});

describe('the prohibited-model refusal in a work thread', () => {
  const AGENT = `agent:${'0'.repeat(16)}:${chatgptKey}`;

  function refusing(recorded: { attributes: Record<string, unknown> }[]) {
    const scope: AccountScope = {
      bindingHash: '0'.repeat(16),
      context: {
        attachedUserDigest: '0'.repeat(64),
        workSubscriptionsOn: true,
        learned: [],
        manual: [],
      },
      stamp: (repoKey, accountKey) =>
        (accountKey === chatgptKey ? AGENT : repoKey) as StampedScopeKey | undefined,
      admit: () => true,
      inScope: (key) => key === AGENT,
      learn: () => 'present',
    };
    return {
      getPolicyBundle: () => Promise.resolve({ prohibitedModels: ['o3'] }),
      recordAuditEvent: (event: { attributes: Record<string, unknown> }) => {
        recorded.push(event);
        return Promise.resolve();
      },
      close: () => Promise.resolve(),
      governanceAppliesTo: (key: string | undefined) => key === AGENT,
      accountScope: () => scope,
    } as unknown as Parameters<typeof handleProhibitedTurn>[0];
  }

  it('is refused in a personal folder, with the row stamped for the thread', async () => {
    recordSessionModel(dataDir(), 's1', 'o3');
    const recorded: { attributes: Record<string, unknown> }[] = [];
    const stop = await handleProhibitedTurn(
      refusing(recorded),
      dataDir(),
      's1',
      undefined,
      personal,
      chatgptKey,
      () => Promise.resolve(),
    );
    expect(stop).toBe(true);
    expect(recorded.map((row) => row.attributes.scope_key)).toEqual([AGENT]);
  });

  it('is allowed in the same folder outside a work thread', async () => {
    recordSessionModel(dataDir(), 's1', 'o3');
    const recorded: { attributes: Record<string, unknown> }[] = [];
    const stop = await handleProhibitedTurn(
      refusing(recorded),
      dataDir(),
      's1',
      undefined,
      personal,
      undefined,
      () => Promise.resolve(),
    );
    expect(stop).toBe(false);
    expect(recorded).toEqual([]);
  });
});

describe('a recognised thread sends what it records from a folder no repository rule covers', () => {
  const KINDS = [
    ['prompt', 'prompt', undefined],
    ['tool call', 'tool_use', 'Bash'],
    ['tool result', 'response', 'Bash'],
    ['patch', 'code_change', 'apply_patch'],
  ] as const;

  let notes: string;
  beforeEach(() => {
    notes = mkdtempSync(join(tmpdir(), 'aka-codex-account-notes-'));
    mkdirSync(join(notes, '.git'), { recursive: true });
    writeFileSync(
      join(notes, '.git', 'config'),
      '[remote "origin"]\n\turl = https://github.com/me/notes.git\n',
    );
  });
  afterEach(() => {
    removeTree(notes);
  });

  /** Records one event of every kind the hooks record, stamped as the hooks stamp them. */
  async function recordEachKind(thread: Thread): Promise<Map<string, string>> {
    const accountKey = await hookAccount(thread);
    const markers = new Map<string, string>();
    const gateway = gatewayNow();
    const runtime = createPluginRuntime(gateway, loadConfig(base).settings, { dataDir: dataDir() });
    try {
      for (const [label, kind, tool] of KINDS) {
        const text = `${kind}-${randomUUID()}`;
        markers.set(label, text);
        const key =
          tool === undefined
            ? stampFor(gateway, captureScopeKey({ cwd: notes }), accountKey)
            : codexToolStamp(gateway, { cwd: notes }, tool, accountKey);
        await captureStamped(
          runtime,
          { kind, sourceTool: SOURCE_TOOL.Codex, text, metadata: { sessionId: thread.sessionId } },
          key,
        );
      }
    } finally {
      await runtime.close();
    }
    return markers;
  }

  const sent = (marker: string): boolean =>
    server.received.some((request) => request.body.includes(marker));

  it.each(KINDS.map(([label]) => label))('sends a %s', async (label) => {
    attachScoped();
    signIn('business');
    const markers = await recordEachKind(await startThread());
    expect(sent(markers.get(label) ?? '')).toBe(true);
  });

  it.each(KINDS.map(([label]) => label))(
    'keeps a %s of a personal-plan thread on the machine',
    async (label) => {
      attachScoped();
      signIn('plus');
      const markers = await recordEachKind(await startThread());
      expect(markers.has(label)).toBe(true);
      expect(sent(markers.get(label) ?? '')).toBe(false);
    },
  );

  it('sends the same events whether or not the history grant is given', async () => {
    attachScoped();
    applyOnboarding(
      {
        historySyncConsent: {
          acknowledgedAt: '2026-10-02T09:00:00.000Z',
          payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
          endpoint: server.origin,
        },
      },
      base,
      null,
    );
    expect(loadConfig(base).settings.historySyncConsent).toBeDefined();
    signIn('business');
    const markers = await recordEachKind(await startThread());
    for (const marker of markers.values()) expect(sent(marker)).toBe(true);
  });
});

describe('a thread that is not a work thread when it starts', () => {
  it('keeps a hand-enrolled workspace off a resumed thread', async () => {
    attachScoped({ entries: [manual()] });
    signIn('plus', workspace, someoneElse);
    const resumed = await startThread('resume');
    expect(resumed.account.accountKey).toBeUndefined();
    expect(await hookAccount(resumed)).toBeUndefined();
    expect(threadLog(resumed.sessionId)).toEqual([
      expect.objectContaining({ start: 'resume', s: 'none' }),
    ]);
  });

  it.each<[string, () => void]>([
    [
      'an access token in the environment',
      () => {
        vi.stubEnv('CODEX_ACCESS_TOKEN', `t-${randomUUID()}`);
      },
    ],
    [
      'a gateway base URL',
      () => {
        vi.stubEnv('OPENAI_BASE_URL', 'https://gateway.example.test/v1');
      },
    ],
    [
      'an API-key login file',
      () => {
        writeCodexAuth(codexHomeUnder(home), {
          accountId: workspace,
          email: member,
          plan: 'business',
          authMode: 'apikey',
          apiKey: `k-${randomUUID()}`,
        });
      },
    ],
  ])('keeps %s on the repository rule', async (_name, change) => {
    attachScoped();
    signIn('business');
    change();
    const thread = await startThread();
    expect(thread.account.accountKey).toBeUndefined();
    expect(await hookAccount(thread)).toBeUndefined();
    expect(learned()).toEqual([]);
  });

  it.each(['bogus', undefined])(
    'decides nothing for a session start whose source is %s',
    async (source) => {
      attachScoped();
      signIn('business');
      const sessionId = randomUUID();
      const gateway = gatewayNow();
      try {
        const account = startThreadAccount(gateway, {
          dataDir: dataDir(),
          sessionId,
          source,
          transcriptPath: rollout(sessionId),
          nowMs: Date.now(),
          home,
        });
        expect(account.accountKey).toBeUndefined();
        expect(threadLog(sessionId)).toEqual([]);
        expect(
          threadAccountKey(gateway, {
            dataDir: dataDir(),
            sessionId,
            transcriptPath: rollout(sessionId),
            nowMs: Date.now(),
            home,
          }),
        ).toBeUndefined();
      } finally {
        await gateway.close();
      }
    },
  );

  it.each(['clear', 'fork'])('starts a work thread on a %s', async (source) => {
    attachScoped();
    signIn('business');
    const thread = await startThread(source);
    expect(thread.account).toEqual({ accountKey: chatgptKey, basis: 'validated' });
    expect(threadLog(thread.sessionId)).toEqual([expect.objectContaining({ start: source })]);
  });

  it('keeps the earlier decision on a compaction, and writes no second start line', async () => {
    attachScoped();
    signIn('business');
    const thread = await startThread();
    const gateway = gatewayNow();
    try {
      const compacted = startThreadAccount(gateway, {
        dataDir: dataDir(),
        sessionId: thread.sessionId,
        source: 'compact',
        transcriptPath: thread.transcriptPath,
        nowMs: Date.now(),
        home,
      });
      expect(compacted).toEqual({ accountKey: chatgptKey, basis: 'remembered' });
    } finally {
      await gateway.close();
    }
    expect(threadLog(thread.sessionId)).toHaveLength(1);
  });
});

describe('a login change that ends a thread', () => {
  it('ends the thread when the login becomes an API key', async () => {
    attachScoped();
    signIn('business');
    const thread = await startThread();
    writeCodexAuth(codexHomeUnder(home), {
      accountId: workspace,
      email: member,
      plan: 'business',
      authMode: 'apikey',
      apiKey: `k-${randomUUID()}`,
    });
    expect(await hookAccount(thread)).toBeUndefined();
    signIn('business');
    expect(await hookAccount(thread)).toBeUndefined();
  });

  it('ends the thread when the login file goes away', async () => {
    attachScoped();
    signIn('business');
    const thread = await startThread();
    rmSync(join(codexHomeUnder(home), 'auth.json'));
    expect(await hookAccount(thread)).toBeUndefined();
    signIn('business');
    expect(await hookAccount(thread)).toBeUndefined();
  });

  it('is written to the log by the Stop check, ahead of any reconcile', async () => {
    attachScoped();
    signIn('business');
    const thread = await startThread();
    signIn('business');
    await noteThreadAccount(loadConfig(base), thread.sessionId, thread.transcriptPath, home);
    expect(threadLog(thread.sessionId)).toHaveLength(2);
    signIn('business', otherWorkspace);
    await noteThreadAccount(loadConfig(base), thread.sessionId, thread.transcriptPath, home);
    const [, , ended] = threadLog(thread.sessionId);
    expect(ended).toMatchObject({ s: 'none' });
    expect(ended && 'start' in ended).toBe(false);
  });
});

describe('session start prunes the session state nobody has written for a month', () => {
  it.each([
    ['a scoped attachment', true],
    ['a standalone machine', false],
  ])('on %s', async (_name, attached) => {
    if (attached) attachScoped();
    const dir = sessionAccountsDir(dataDir());
    mkdirSync(dir, { recursive: true });
    const stale = join(dir, 'stale.log');
    const fresh = join(dir, 'fresh.log');
    writeFileSync(stale, '');
    writeFileSync(fresh, '');
    const old = new Date(Date.now() - 31 * 24 * 60 * 60 * 1000);
    utimesSync(stale, old, old);
    const sessionId = randomUUID();
    await codexSessionStartAccount(loadConfig(base), {
      sessionId,
      source: 'startup',
      transcriptPath: rollout(sessionId),
      cwd: personal,
      nowMs: Date.now(),
      home,
    });
    expect(existsSync(stale)).toBe(false);
    expect(existsSync(fresh)).toBe(true);
  });
});

describe('a machine that is not on a scoped attachment', () => {
  it('opens no gateway to decide a thread, and decides none', async () => {
    let opened = 0;
    const restore = setDefaultGatewayFactory((config, meta) => {
      opened += 1;
      return configuredGatewayFactory(config, meta);
    });
    try {
      signIn('business');
      const sessionId = randomUUID();
      const config = loadConfig(base);
      expect(
        await codexSessionStartAccount(config, {
          sessionId,
          source: 'startup',
          transcriptPath: rollout(sessionId),
          cwd: personal,
          nowMs: Date.now(),
          home,
        }),
      ).toEqual({});
      await noteThreadAccount(config, sessionId, rollout(sessionId), home);
    } finally {
      restore();
    }
    expect(opened).toBe(0);
  });
});

describe('every account function is total', () => {
  /** A gateway whose account scope cannot be read as a context. */
  async function hostileGateway() {
    const real = gatewayNow();
    const scope = accountScopeOf(real);
    if (scope === undefined) throw new Error('no account scope');
    await real.close();
    return {
      accountScope: () => ({
        bindingHash: scope.bindingHash,
        stamp: (repoKey: string | undefined, accountKey?: string) =>
          scope.stamp(repoKey, accountKey),
        admit: (accountKey: string, bindingHash: string) => scope.admit(accountKey, bindingHash),
        learn: (accountKey: string) => scope.learn(accountKey),
        inScope: (key: string) => scope.inScope(key),
        get context(): never {
          throw new Error('unreadable context');
        },
      }),
    };
  }

  it('answers no account when the scope cannot be read', async () => {
    attachScoped();
    signIn('business');
    const gateway = await hostileGateway();
    const sessionId = randomUUID();
    const input = {
      dataDir: dataDir(),
      sessionId,
      transcriptPath: rollout(sessionId),
      nowMs: Date.now(),
      home,
    };
    expect(startThreadAccount(gateway, { ...input, source: 'startup' })).toEqual({
      accountKey: undefined,
      basis: undefined,
    });
    expect(threadAccountKey(gateway, input)).toBeUndefined();
  });

  it('answers the repository key when the gateway offers no account scope', () => {
    expect(stampFor({}, 'github.com/acme/work', chatgptKey)).toBe('github.com/acme/work');
    expect(codexToolStamp({}, { cwd: work }, 'Bash', chatgptKey)).toBe(WORK_KEY);
    expect(codexToolStamp({}, { cwd: work }, 'apply_patch', chatgptKey)).toBeUndefined();
  });

  it('answers no account when the gateway cannot be opened', async () => {
    attachScoped();
    signIn('business');
    const sessionId = randomUUID();
    const restore = setDefaultGatewayFactory(() => {
      throw new Error('no store');
    });
    try {
      await expect(
        codexSessionStartAccount(loadConfig(base), {
          sessionId,
          source: 'startup',
          transcriptPath: rollout(sessionId),
          cwd: personal,
          nowMs: Date.now(),
          home,
        }),
      ).resolves.toEqual({});
      await expect(
        noteThreadAccount(loadConfig(base), sessionId, rollout(sessionId), home),
      ).resolves.toBeUndefined();
    } finally {
      restore();
    }
    expect(threadLog(sessionId)).toEqual([]);
  });

  it('starts and checks a thread without throwing when the configuration cannot be read', async () => {
    const config = loadConfig(base);
    const hostile = new Proxy(config, {
      get() {
        throw new Error('unreadable configuration');
      },
    });
    const sessionId = randomUUID();
    await expect(
      codexSessionStartAccount(hostile, {
        sessionId,
        source: 'startup',
        transcriptPath: rollout(sessionId),
        cwd: personal,
        nowMs: Date.now(),
        home,
      }),
    ).resolves.toEqual({});
    await expect(
      noteThreadAccount(hostile, sessionId, rollout(sessionId), home),
    ).resolves.toBeUndefined();
  });
});

describe('captures, policy questions and refusal rows go through stamped-capture.ts', () => {
  const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const resolved = new Map<string, Linter.RuleEntry | undefined>();

  beforeAll(async () => {
    const eslint = new ESLint({ cwd: PLUGIN_ROOT });
    for (const file of [
      'src/hooks/post-tool-use.ts',
      'src/hooks/model-guard.ts',
      'src/hooks/stamped-capture.ts',
      'src/history/scan.ts',
    ]) {
      const config = (await eslint.calculateConfigForFile(join(PLUGIN_ROOT, file))) as {
        rules?: Record<string, Linter.RuleEntry>;
      };
      resolved.set(file, config.rules?.['no-restricted-syntax']);
    }
  }, 60_000);

  /** How many messages `code` produces under the rule `file` resolves to. */
  const fired = (file: string, code: string): number =>
    new Linter().verify(code, {
      languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
      rules: { 'no-restricted-syntax': resolved.get(file) ?? 'off' },
    }).length;

  it.each([
    ['a capture', 'runtime.capture({ text });'],
    ['a capture by a computed name', "runtime['capture']({ text });"],
    ['a capture by a computed template name', 'runtime[`capture`]({ text });'],
    ['a deferred capture', 'runtime.captureDeferred({ text });'],
    ['a destructured capture', 'const { capture } = runtime; capture({ text });'],
    ['the governance question', 'governanceApplies(gateway, key);'],
    ['the governance question through a namespace', 'sdk.governanceApplies(gateway, key);'],
    [
      'an aliased import of the governance question',
      "import { governanceApplies as ga } from 'x';",
    ],
    [
      'an import of the governance question by a string name',
      "import { 'governanceApplies' as ga } from 'x';",
    ],
    ['a refusal row', 'buildModelRefusalEvent({ id });'],
    ['a refusal row through a namespace', 'sdk.buildModelRefusalEvent({ id });'],
    [
      'an aliased import of the refusal row',
      "import { buildModelRefusalEvent as build } from 'x';",
    ],
  ])('refuses %s in a hook', (_label, code) => {
    expect(fired('src/hooks/post-tool-use.ts', code)).toBe(1);
    expect(fired('src/hooks/model-guard.ts', code)).toBe(1);
  });

  it('names the stamped door in what it refuses', () => {
    const messages = new Linter().verify('runtime.capture({ text });', {
      languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
      rules: { 'no-restricted-syntax': resolved.get('src/hooks/post-tool-use.ts') ?? 'off' },
    });
    expect(messages.map((message) => message.message)).toEqual([
      'Capture through stamped-capture.ts (captureStamped), with a stamped key.',
    ]);
  });

  it('allows a function that takes a callback named capture', () => {
    expect(
      fired('src/hooks/post-tool-use.ts', 'function scan(capture) { return capture(text); }'),
    ).toBe(0);
  });

  it('allows them in stamped-capture.ts, and outside the hooks', () => {
    const code = 'runtime.capture({ text }); governanceApplies(g, k);';
    expect(fired('src/hooks/stamped-capture.ts', code)).toBe(0);
    expect(fired('src/history/scan.ts', code)).toBe(0);
  });

  it('still refuses a dynamic Drizzle or network import in a hook', () => {
    expect(fired('src/hooks/post-tool-use.ts', "await import('drizzle-orm');")).toBe(1);
    expect(fired('src/hooks/post-tool-use.ts', "await import('node:https');")).toBe(1);
  });
});
