import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  bindingHashOf,
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  llmCallId,
  readAttachedIdentity,
  recordValidatedWorkAccount,
  settingsDir as settingsDirOf,
  toolCallId,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import type * as RemoteModule from '@akasecurity/remote';
import type { AuditEventInput, IngestBatch, WorkspaceSettings } from '@akasecurity/schema';
import { agentKey, defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { accountScopeOf, stampScopeKey } from '../../src/account-scope.ts';
import { readAccountScope, resolveGatewayForConfig } from '../../src/attached/factory.ts';
import type { AttachedClient } from '../../src/attached/gateway.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// Which rows a coding-agent session forwards, by its account and its repository,
// through the gateway the real factory builds from a real scoped credential and
// identity record, over a real local store. Only the network client is replaced,
// by a recorder for every route. Every row is stamped through `stampScopeKey`,
// the call a producer makes.

const sent = vi.hoisted(() => ({
  captures: [] as IngestBatch[],
  audit: [] as AuditEventInput[],
  auditBatches: [] as (readonly AuditEventInput[])[],
}));

vi.mock('@akasecurity/remote', async (importOriginal) => ({
  ...(await importOriginal<typeof RemoteModule>()),
  createRemoteClient: (): AttachedClient => ({
    ingestEvents: (batch) => {
      sent.captures.push(batch);
      return Promise.resolve({ accepted: batch.events.length, duplicates: 0 });
    },
    ingestInventory: () => Promise.resolve({}),
    recordAuditEvent: (body) => {
      sent.audit.push(body);
      return Promise.resolve();
    },
    recordAuditEvents: (bodies) => {
      sent.auditBatches.push(bodies);
      return Promise.resolve({ accepted: bodies.length });
    },
    reportStorePosture: () => Promise.resolve({}),
    recordProjectEgress: () => Promise.resolve({}),
  }),
}));

const ENDPOINT = 'https://aka.acme.test';
const AT = '2026-10-01T09:00:00.000Z';
const TEST_KEY = 'not-a-real-key';
const WORK_REPO = 'github.com/acme/payments-api';
const PERSONAL_REPO = 'github.com/someone/side-project';
const WORK_ACCOUNT = `claude:${randomUUID()}`;
const PERSONAL_ACCOUNT = `claude:${randomUUID()}`;
const UNSEEN_ACCOUNT = `claude:${randomUUID()}`;
const SCOPED_CREDENTIAL = {
  specVersion: 2,
  mode: 'scoped',
  endpoint: ENDPOINT,
  apiKey: TEST_KEY,
  mintedAt: AT,
} as const;

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-account-verdicts-'));
  migratedStore.seed(dataDirOf(home));
  for (const route of Object.values(sent)) route.length = 0;
});

afterEach(() => {
  removeTree(home);
});

/** Attached to ENDPOINT with the work repository enrolled, and `scope`'s envelope fields on top. */
function configFor(scope: Record<string, unknown> = {}): PluginConfig {
  const settings: WorkspaceSettings = {
    ...defaultWorkspaceSettings(),
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
    attachmentScope: {
      endpoint: ENDPOINT,
      entries: [{ kind: 'repo', identity: WORK_REPO, enrolledAt: AT }],
      ...scope,
    },
  };
  return {
    settings,
    dataDir: dataDirOf(home),
    dbPath: dbPathOf(home),
    settingsDir: settingsDirOf(home),
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

/** A scoped credential, its identity record, and WORK_ACCOUNT learned under it. */
function attachScoped(): void {
  writeControlPlaneCredential(settingsDirOf(home), SCOPED_CREDENTIAL);
  writeAttachedIdentity(dataDirOf(home), {
    endpoint: ENDPOINT,
    apiKey: TEST_KEY,
    tenantName: 'Acme',
    userEmail: ['member', 'example.test'].join('@'),
  });
  recordValidatedWorkAccount(dataDirOf(home), {
    endpoint: ENDPOINT,
    credential: SCOPED_CREDENTIAL,
    key: WORK_ACCOUNT,
  });
}

function record() {
  const stored = readAttachedIdentity(dataDirOf(home));
  if (stored === undefined) throw new Error('no identity record was written');
  return stored;
}

/** The agent key the schema's builder makes for `account` under `scopeTag`, failing the suite if none. */
function agentKeyOf(scopeTag: string, account: string): string {
  const key = agentKey(scopeTag, account);
  if (key === undefined) throw new Error(`no agent key for ${account}`);
  return key;
}

/** One session as a producer records it, every row stamped through `gateway`. */
async function produce(
  gateway: DataGateway,
  session: string,
  repoKey: string | undefined,
  account: string | undefined,
): Promise<string | undefined> {
  const key = stampScopeKey(gateway, repoKey, account);
  const keyed = key === undefined ? {} : { scope_key: key };
  const at = new Date().toISOString();
  await gateway.recordAuditEvent({
    id: session,
    eventType: 'session',
    startedAt: at,
    attributes: { harness: 'claude-code', cwd: `/work/${session}`, ...keyed },
  });
  await gateway.recordCapture({
    event: {
      id: randomUUID(),
      sourceTool: 'claude-code',
      kind: 'prompt',
      occurredAt: at,
      contentHash: `hash-${session}`,
      content: `text of ${session}`,
      metadata: { sessionId: session, repo: 'producer-slug' },
    },
    findings: [],
    ...(key === undefined ? {} : { scopeKey: key }),
  });
  await gateway.recordLlmCalls([
    {
      sessionId: session,
      messageId: `${session}-msg`,
      parentId: session,
      rootSessionId: session,
      startedAt: at,
      attributes: { model: 'example-model', input_tokens: 1, output_tokens: 1, ...keyed },
    },
  ]);
  await gateway.recordToolCalls([
    {
      sessionId: session,
      toolUseId: `${session}-tool`,
      parentId: session,
      rootSessionId: session,
      startedAt: at,
      attributes: { tool_name: 'Bash', tool_use_id: `${session}-tool`, target: 'ls', ...keyed },
      inspections: [],
    },
  ]);
  return key;
}

/** Which of `session`'s four rows reached the client. */
function forwarded(session: string) {
  const leaves = sent.auditBatches.flat();
  return {
    root: sent.audit.some((event) => event.id === session),
    capture: sent.captures.some((batch) =>
      batch.events.some((event) => event.metadata?.sessionId === session),
    ),
    llmCall: leaves.some((event) => event.id === llmCallId(session, `${session}-msg`)),
    toolCall: leaves.some((event) => event.id === toolCallId(session, `${session}-tool`)),
  };
}
const ALL = { root: true, capture: true, llmCall: true, toolCall: true };
const NONE = { root: false, capture: false, llmCall: false, toolCall: false };

/** The scope key the local store holds for a row. */
function storedKey(id: string): string | null {
  const raw = new DatabaseSync(dbPathOf(home));
  try {
    const row = raw.prepare('SELECT scope_key AS key FROM audit_events WHERE id = ?').get(id) as
      { key: string | null } | undefined;
    if (row === undefined) throw new Error(`no row ${id}`);
    return row.key;
  } finally {
    raw.close();
  }
}

/** The repository slug the forwarded capture of `session` carried, if any. */
function slugOf(session: string): unknown {
  for (const batch of sent.captures) {
    for (const event of batch.events) {
      if (event.metadata?.sessionId === session) return event.metadata.repo;
    }
  }
  throw new Error(`no capture of ${session} was forwarded`);
}

describe('the attached gateway forwards by account, repository first', () => {
  it.each<[string, string | undefined, 'work' | 'personal', 'repo' | 'agent', typeof ALL]>([
    ['a work account in an enrolled repository', WORK_REPO, 'work', 'repo', ALL],
    ['a work account in a personal repository', PERSONAL_REPO, 'work', 'agent', ALL],
    ['a work account in no repository', undefined, 'work', 'agent', ALL],
    ['a personal account in an enrolled repository', WORK_REPO, 'personal', 'repo', ALL],
    ['a personal account in a personal repository', PERSONAL_REPO, 'personal', 'repo', NONE],
    ['a personal account in no repository', undefined, 'personal', 'repo', NONE],
  ])('%s', async (_name, repoKey, who, stampedAs, expected) => {
    attachScoped();
    const account = who === 'work' ? WORK_ACCOUNT : PERSONAL_ACCOUNT;
    const gateway = resolveGatewayForConfig(configFor());
    try {
      const key = await produce(gateway, 'session-1', repoKey, account);
      expect(key).toBe(
        stampedAs === 'repo' ? repoKey : agentKeyOf(record().scopeTag, WORK_ACCOUNT),
      );
      // The stored key is the stamped one.
      expect(storedKey('session-1')).toBe(key ?? null);
    } finally {
      await gateway.close();
    }
    expect(forwarded('session-1')).toEqual(expected);
  });

  it('a work session in an enrolled repository keeps the slug', async () => {
    attachScoped();
    const gateway = resolveGatewayForConfig(configFor());
    try {
      await produce(gateway, 'in-repo', WORK_REPO, WORK_ACCOUNT);
      await produce(gateway, 'elsewhere', PERSONAL_REPO, WORK_ACCOUNT);
    } finally {
      await gateway.close();
    }
    expect(slugOf('in-repo')).toBe('payments-api');
    // An agent key names no repository, so the producer's slug is not sent either.
    expect(slugOf('elsewhere')).toBeUndefined();
  });

  it('stamps the repository key from the next hook once work subscriptions are turned off', async () => {
    attachScoped();
    const first = resolveGatewayForConfig(configFor());
    try {
      await produce(first, 'before', PERSONAL_REPO, WORK_ACCOUNT);
    } finally {
      await first.close();
    }
    const next = resolveGatewayForConfig(configFor({ workSubscriptions: 'off' }));
    try {
      expect(await produce(next, 'after', PERSONAL_REPO, WORK_ACCOUNT)).toBe(PERSONAL_REPO);
    } finally {
      await next.close();
    }
    expect(forwarded('before')).toEqual(ALL);
    expect(forwarded('after')).toEqual(NONE);
  });
});

describe('a leaf is held to its session root', () => {
  it('forwards the account-keyed reply under an account-keyed root, and under no other root', async () => {
    attachScoped();
    const gateway = resolveGatewayForConfig(configFor());
    try {
      const byAccount = stampScopeKey(gateway, PERSONAL_REPO, WORK_ACCOUNT);
      const byRepository = stampScopeKey(gateway, PERSONAL_REPO);
      expect(byAccount).toBe(agentKeyOf(record().scopeTag, WORK_ACCOUNT));
      expect(byRepository).toBe(PERSONAL_REPO);
      for (const [session, rootKey] of [
        ['rooted-by-account', byAccount],
        ['rooted-by-repository', byRepository],
      ] as const) {
        await gateway.recordAuditEvent({
          id: session,
          eventType: 'session',
          startedAt: new Date().toISOString(),
          attributes: { harness: 'claude-code', scope_key: rootKey },
        });
        await gateway.recordLlmCalls(
          (
            [
              ['account', byAccount],
              ['repository', byRepository],
            ] as const
          ).map(([name, key]) => ({
            sessionId: session,
            messageId: `${session}-${name}`,
            parentId: session,
            rootSessionId: session,
            startedAt: new Date().toISOString(),
            attributes: { model: 'example-model', scope_key: key },
          })),
        );
      }
    } finally {
      await gateway.close();
    }
    expect(sent.audit.map((event) => event.id)).toEqual(['rooted-by-account']);
    expect(sent.auditBatches.flat().map((event) => event.id)).toEqual([
      llmCallId('rooted-by-account', 'rooted-by-account-account'),
    ]);
  });
});

describe('admit, on the gateway the factory builds', () => {
  it("names the identity record's binding", async () => {
    attachScoped();
    const gateway = resolveGatewayForConfig(configFor());
    try {
      const stored = record();
      expect(accountScopeOf(gateway)?.bindingHash).toBe(
        bindingHashOf(stored.endpoint, stored.credentialDigest, stored.attachedUserDigest),
      );
    } finally {
      await gateway.close();
    }
  });

  it("forwards a just-validated account's rows from the same process", async () => {
    attachScoped();
    const gateway = resolveGatewayForConfig(configFor());
    try {
      const scope = accountScopeOf(gateway);
      if (scope === undefined) throw new Error('the gateway offers no account scope');
      expect(await produce(gateway, 'unseen', PERSONAL_REPO, UNSEEN_ACCOUNT)).toBe(PERSONAL_REPO);
      expect(scope.admit(UNSEEN_ACCOUNT, scope.bindingHash)).toBe(true);
      expect(await produce(gateway, 'admitted', PERSONAL_REPO, UNSEEN_ACCOUNT)).toBe(
        agentKeyOf(record().scopeTag, UNSEEN_ACCOUNT),
      );
    } finally {
      await gateway.close();
    }
    expect(forwarded('unseen')).toEqual(NONE);
    expect(forwarded('admitted')).toEqual(ALL);
  });

  it('refuses an account offered under another binding', async () => {
    attachScoped();
    const gateway = resolveGatewayForConfig(configFor());
    try {
      const scope = accountScopeOf(gateway);
      if (scope === undefined) throw new Error('the gateway offers no account scope');
      expect(scope.admit(UNSEEN_ACCOUNT, 'another-binding-hash')).toBe(false);
      expect(await produce(gateway, 'refused', PERSONAL_REPO, UNSEEN_ACCOUNT)).toBe(PERSONAL_REPO);
    } finally {
      await gateway.close();
    }
    expect(forwarded('refused')).toEqual(NONE);
  });

  it('an opted-out gateway never admits a learned key', async () => {
    attachScoped();
    const gateway = resolveGatewayForConfig(configFor({ workSubscriptions: 'off' }));
    try {
      const scope = accountScopeOf(gateway);
      if (scope === undefined) throw new Error('the gateway offers no account scope');
      expect(scope.admit(WORK_ACCOUNT, scope.bindingHash)).toBe(false);
      expect(scope.admit(UNSEEN_ACCOUNT, scope.bindingHash)).toBe(false);
      expect(await produce(gateway, 'opted-out', PERSONAL_REPO, WORK_ACCOUNT)).toBe(PERSONAL_REPO);
    } finally {
      await gateway.close();
    }
    expect(forwarded('opted-out')).toEqual(NONE);
  });
});

describe('which gateways offer an account scope', () => {
  it('a scoped credential with an identity record bound to it offers one', async () => {
    attachScoped();
    const gateway = resolveGatewayForConfig(configFor());
    try {
      expect(accountScopeOf(gateway)).toBeDefined();
    } finally {
      await gateway.close();
    }
  });

  it('a scoped credential with no identity record offers none, and stamps the repository key', async () => {
    writeControlPlaneCredential(settingsDirOf(home), SCOPED_CREDENTIAL);
    const gateway = resolveGatewayForConfig(configFor());
    try {
      expect(accountScopeOf(gateway)).toBeUndefined();
      expect(stampScopeKey(gateway, PERSONAL_REPO, WORK_ACCOUNT)).toBe(PERSONAL_REPO);
    } finally {
      await gateway.close();
    }
  });

  it('a scoped credential with no identity record forwards a session in an enrolled repository only', async () => {
    writeControlPlaneCredential(settingsDirOf(home), SCOPED_CREDENTIAL);
    const gateway = resolveGatewayForConfig(configFor());
    try {
      expect(await produce(gateway, 'enrolled', WORK_REPO, WORK_ACCOUNT)).toBe(WORK_REPO);
      expect(await produce(gateway, 'elsewhere', PERSONAL_REPO, WORK_ACCOUNT)).toBe(PERSONAL_REPO);
    } finally {
      await gateway.close();
    }
    expect(forwarded('enrolled')).toEqual(ALL);
    expect(forwarded('elsewhere')).toEqual(NONE);
  });

  it('a machine credential offers none, and stamps the repository key whatever the account', async () => {
    attachScoped();
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: TEST_KEY,
      mintedAt: AT,
    });
    const gateway = resolveGatewayForConfig(configFor());
    try {
      expect(accountScopeOf(gateway)).toBeUndefined();
      expect(stampScopeKey(gateway, PERSONAL_REPO, WORK_ACCOUNT)).toBe(PERSONAL_REPO);
      expect(stampScopeKey(gateway, undefined, WORK_ACCOUNT)).toBeUndefined();
    } finally {
      await gateway.close();
    }
  });

  it('the local gateway offers none', async () => {
    const gateway = new StandaloneDataGateway(dataDirOf(home));
    try {
      expect(accountScopeOf(gateway)).toBeUndefined();
      expect(stampScopeKey(gateway, PERSONAL_REPO, WORK_ACCOUNT)).toBe(PERSONAL_REPO);
    } finally {
      await gateway.close();
    }
  });
});

describe('learn and context, on the gateway the factory builds', () => {
  it('writes a validated account to the identity record once, and admits nothing by itself', async () => {
    attachScoped();
    const gateway = resolveGatewayForConfig(configFor());
    try {
      const scope = accountScopeOf(gateway);
      if (scope === undefined) throw new Error('the gateway offers no account scope');
      expect(scope.learn(UNSEEN_ACCOUNT)).toBe('written');
      expect(scope.learn(UNSEEN_ACCOUNT)).toBe('present');
      expect(
        record()
          .workAccounts.map((entry) => entry.identity)
          .sort(),
      ).toEqual([WORK_ACCOUNT, UNSEEN_ACCOUNT].sort());
      // Learning alone forwards nothing; only an admit does.
      expect(stampScopeKey(gateway, PERSONAL_REPO, UNSEEN_ACCOUNT)).toBe(PERSONAL_REPO);
    } finally {
      await gateway.close();
    }
  });

  it('learn refuses while work subscriptions are off', async () => {
    attachScoped();
    const gateway = resolveGatewayForConfig(configFor({ workSubscriptions: 'off' }));
    try {
      expect(accountScopeOf(gateway)?.learn(UNSEEN_ACCOUNT)).toBe('refused');
    } finally {
      await gateway.close();
    }
    expect(record().workAccounts.map((entry) => entry.identity)).toEqual([WORK_ACCOUNT]);
  });

  it('learn refuses a ninth account', async () => {
    attachScoped();
    for (let i = 0; i < 7; i += 1) {
      recordValidatedWorkAccount(dataDirOf(home), {
        endpoint: ENDPOINT,
        credential: SCOPED_CREDENTIAL,
        key: `claude:${randomUUID()}`,
      });
    }
    expect(record().workAccounts).toHaveLength(8);
    const gateway = resolveGatewayForConfig(configFor());
    try {
      expect(accountScopeOf(gateway)?.learn(UNSEEN_ACCOUNT)).toBe('refused');
    } finally {
      await gateway.close();
    }
    expect(record().workAccounts).toHaveLength(8);
  });

  it("hands a hook the bound record's context and the manual coding entries", async () => {
    attachScoped();
    const manual = `claude:${randomUUID()}`;
    const gateway = resolveGatewayForConfig(
      configFor({
        entries: [
          { kind: 'repo', identity: WORK_REPO, enrolledAt: AT },
          { kind: 'account', identity: manual, enrolledAt: AT, codingAgents: true },
          { kind: 'account', identity: `claude:${randomUUID()}`, enrolledAt: AT },
        ],
      }),
    );
    try {
      const context = accountScopeOf(gateway)?.context;
      expect(context?.attachedUserDigest).toBe(record().attachedUserDigest);
      expect(context?.workSubscriptionsOn).toBe(true);
      expect(context?.learned.map((entry) => entry.identity)).toEqual([WORK_ACCOUNT]);
      // An account entry with no coding marker covers web chats only.
      expect(context?.manual).toEqual([manual]);
    } finally {
      await gateway.close();
    }
  });

  it('reads the same context and binding hash without a gateway, and none off a scoped attachment', async () => {
    attachScoped();
    const config = configFor();
    const gateway = resolveGatewayForConfig(config);
    try {
      const scope = accountScopeOf(gateway);
      if (scope === undefined) throw new Error('the gateway offers no account scope');
      expect(readAccountScope(config)).toEqual({
        context: scope.context,
        bindingHash: scope.bindingHash,
      });
    } finally {
      await gateway.close();
    }
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: TEST_KEY,
      mintedAt: AT,
    });
    expect(readAccountScope(configFor())).toBeUndefined();
  });
});
