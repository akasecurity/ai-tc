import { randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import {
  agentKey,
  defaultWorkspaceSettings,
  MANAGED_SETTINGS_FILENAME,
  SOURCE_TOOL,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { UNSAFE_TEST_ONLY_setManagedSettingsPaths } from '../../../persistence/src/managed-settings.ts';
import type { AccountScopeContext } from '../../src/account-scope.ts';
import { createAccountScope } from '../../src/account-scope.ts';
import { createForwardPolicy } from '../../src/attached/forward-policy.ts';
import type { ForwardingScope, ForwardingSession } from '../../src/attached/forwarding-line.ts';
import {
  forwardingLine,
  workSubscriptionOptOutOffered,
} from '../../src/attached/forwarding-line.ts';
import type { AttachedClient } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';
import { handleSessionStart } from '../../src/handle-session-start.ts';
import { setDefaultGatewayFactory } from '../../src/resolve.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// The line is read off whatever gateway the session start wrote through, so
// each case hands it a gateway that answers `forwardingScope` one way. The
// attached gateway's own answers are pinned in gateway.test.ts, and the two are
// driven together, from real credential files, in
// session-start-scoped-credential.test.ts.

const LOCAL_ONLY =
  'AKA: local-only (not enrolled); work in an enrolled repository is still forwarded';
const WORK_KEY = 'github.com/acme/work';

function answering(scope: ForwardingScope | null): object {
  return { forwardingScope: () => scope };
}

describe('forwardingLine', () => {
  it('says everything forwards on a machine attachment', () => {
    expect(forwardingLine(answering({ deploymentName: 'Acme', mode: 'machine' }), 's1')).toBe(
      'AKA: forwarding everything to Acme (machine-wide)',
    );
  });

  it('names the stored root key when the gateway forwards the root', () => {
    const scope: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: WORK_KEY,
      rootForwards: true,
    };
    expect(forwardingLine(answering(scope), 's1')).toBe(`AKA: forwarding to Acme (${WORK_KEY})`);
  });

  // The gateway's verdict decides, not the key's presence: a keyed root the
  // gateway holds local is local-only.
  it('says local-only when the gateway holds a keyed root local', () => {
    const scope: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: 'github.com/me/personal',
      rootForwards: false,
    };
    expect(forwardingLine(answering(scope), 's1')).toBe(LOCAL_ONLY);
  });

  it('says local-only when the store holds no key for the root', () => {
    const scope: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: undefined,
      rootForwards: false,
    };
    expect(forwardingLine(answering(scope), 's1')).toBe(LOCAL_ONLY);
  });

  it('strips control characters from the stored key', () => {
    const scope: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: 'github.com/acme/\u001b[31mwork',
      rootForwards: true,
    };
    expect(forwardingLine(answering(scope), 's1')).toBe(
      'AKA: forwarding to Acme (github.com/acme/[31mwork)',
    );
  });

  it('asks about the root it is given', () => {
    const asked: string[] = [];
    const gateway = {
      forwardingScope: (rootId: string): ForwardingScope => {
        asked.push(rootId);
        return { deploymentName: 'Acme', mode: 'machine' };
      },
    };
    forwardingLine(gateway, 'session-7');
    expect(asked).toEqual(['session-7']);
  });

  // A gateway that does not offer the capability forwards nothing as far as
  // the line can tell: the local gateway, or one an embedder installed.
  it('says nothing for a gateway that offers no forwarding scope', () => {
    expect(forwardingLine({ close: () => Promise.resolve() }, 's1')).toBeNull();
  });

  it('says nothing for a gateway that answers null', () => {
    expect(forwardingLine(answering(null), 's1')).toBeNull();
  });
});

// The line is read in the session start's `finally`, beside the store close. A
// throw out of it would cost the session every notice, so it answers null
// instead, the same answer a machine that forwards nothing gets.
describe('forwardingLine fails open', () => {
  it('answers null when the gateway throws', () => {
    const gateway = {
      forwardingScope: (): ForwardingScope => {
        throw new Error('scope unreadable');
      },
    };
    expect(forwardingLine(gateway, 's1')).toBeNull();
  });

  it('answers null when the scope it returns cannot be read', () => {
    // A scope whose name throws on access stands for any malformed answer.
    const scope = Object.defineProperty({ mode: 'machine' }, 'deploymentName', {
      get: () => {
        throw new Error('name unreadable');
      },
    }) as ForwardingScope;
    expect(forwardingLine(answering(scope), 's1')).toBeNull();
  });

  it('names the deployment when nothing throws', () => {
    // The control: the same shapes without the fault reach the line, so the
    // nulls above are the faults' doing.
    expect(forwardingLine(answering({ deploymentName: 'Acme', mode: 'machine' }), 's1')).toBe(
      'AKA: forwarding everything to Acme (machine-wide)',
    );
  });
});

const OPT_OUT = '`aka unenroll --work-subscriptions` stops this on this device.';
const MANUAL_STOP =
  'Enrolled by hand; `aka unenroll --account` with its key stops this (`aka status` lists it).';
const WORK_LINE = 'AKA: forwarding this session to Acme — signed in to a work subscription.';
const WORK_LINE_BY_HAND =
  'AKA: forwarding this session to Acme — signed in to an account you enrolled by hand.';
const KEYED_LINE = 'AKA: forwarding this session to Acme — for the account it first ran under.';
const PENDING_LINE =
  'AKA: this session forwards to Acme once Claude confirms the work subscription, from its first reply.';
const PENDING_BY_HAND =
  'AKA: this session forwards to Acme once Claude confirms it is signed in to an account you enrolled by hand, from its first reply.';
const OTHER_FOLDERS =
  'This session also sends its work in other folders, because it is signed in to a work subscription.';
const OTHER_FOLDERS_MANUAL =
  'This session also sends its work in other folders, because it is signed in to an account you enrolled by hand.';
const ENDPOINT = 'https://plane.example.test';
const SCOPE_TAG = randomUUID().replaceAll('-', '').slice(0, 16);

/** A well-formed agent key for a fresh Claude organization. */
function agentKeyForTest(): string {
  const key = agentKey(SCOPE_TAG, `claude:${randomUUID()}`);
  if (key === undefined) throw new Error('the test agent key did not form');
  return key;
}
const AGENT = agentKeyForTest();
const ORG = randomUUID();
const ACCOUNT_KEY = `claude:${ORG}`;
const MANUAL_ACCOUNT = `claude:${randomUUID()}`;

type Basis = ForwardingSession['basis'];
const accountScope = (basis: Basis, managed = false): ForwardingScope => ({
  deploymentName: 'Acme',
  mode: 'account',
  rootKey: AGENT,
  basis,
  managed,
});
const pendingScope = (
  basis: Basis,
  managed = false,
  workSubscriptionsOn = true,
): ForwardingScope => ({
  deploymentName: 'Acme',
  mode: 'account-pending',
  basis,
  managed,
  workSubscriptionsOn,
});
const inWork = (work?: { basis: NonNullable<Basis>; managed: boolean }): ForwardingScope => ({
  deploymentName: 'Acme',
  mode: 'scoped',
  rootKey: WORK_KEY,
  rootForwards: true,
  ...(work === undefined ? {} : { work }),
});

describe('forwardingLine — a work-subscription session', () => {
  it.each(['validated', 'remembered'] as const)(
    'a %s work session names the deployment and the command that stops it',
    (basis) => {
      expect(forwardingLine(answering(accountScope(basis)), 's1')).toBe(`${WORK_LINE} ${OPT_OUT}`);
    },
  );

  it('a root left to the reconcile names the deployment and the command that stops it', () => {
    expect(forwardingLine(answering(pendingScope(undefined)), 's1')).toBe(
      `${PENDING_LINE} ${OPT_OUT}`,
    );
  });

  it('a manual session names the account enrolled by hand and the command that stops it', () => {
    expect(forwardingLine(answering(accountScope('manual')), 's1')).toBe(
      `${WORK_LINE_BY_HAND} ${MANUAL_STOP}`,
    );
    expect(forwardingLine(answering(pendingScope('manual')), 's1')).toBe(
      `${PENDING_BY_HAND} ${MANUAL_STOP}`,
    );
    for (const scope of [accountScope('manual'), pendingScope('manual')]) {
      const line = forwardingLine(answering(scope), 's1');
      expect(line).not.toContain('--work-subscriptions');
      expect(line).not.toContain('work subscription');
    }
  });

  it('a session in an agent-keyed root names the account enrolled by hand when that is its basis', () => {
    const forwardedAgentRoot = (work: {
      basis: NonNullable<Basis>;
      managed: boolean;
    }): ForwardingScope => ({
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: AGENT,
      rootForwards: true,
      work,
    });
    expect(
      forwardingLine(answering(forwardedAgentRoot({ basis: 'manual', managed: false })), 's1'),
    ).toBe(`${WORK_LINE_BY_HAND} ${MANUAL_STOP}`);
    expect(
      forwardingLine(answering(forwardedAgentRoot({ basis: 'validated', managed: false })), 's1'),
    ).toBe(`${WORK_LINE} ${OPT_OUT}`);
  });

  it('a root left to the reconcile names the account enrolled by hand when work subscriptions are off', () => {
    for (const basis of [undefined, 'manual'] as const) {
      for (const managed of [false, true]) {
        expect(forwardingLine(answering(pendingScope(basis, managed, false)), 's1')).toBe(
          `${PENDING_BY_HAND} ${MANUAL_STOP}`,
        );
      }
    }
  });

  it('a work session in a repository is told about its other folders', () => {
    expect(forwardingLine(answering(inWork({ basis: 'validated', managed: false })), 's1')).toBe(
      `AKA: forwarding to Acme (${WORK_KEY}). ${OTHER_FOLDERS} ${OPT_OUT}`,
    );
    expect(forwardingLine(answering(inWork({ basis: 'manual', managed: false })), 's1')).toBe(
      `AKA: forwarding to Acme (${WORK_KEY}). ${OTHER_FOLDERS_MANUAL} ${MANUAL_STOP}`,
    );
    expect(forwardingLine(answering(inWork()), 's1')).toBe(`AKA: forwarding to Acme (${WORK_KEY})`);
  });

  it('no command the device refuses is offered', () => {
    expect(forwardingLine(answering(accountScope('validated', true)), 's1')).toBe(WORK_LINE);
    expect(forwardingLine(answering(pendingScope(undefined, true)), 's1')).toBe(PENDING_LINE);
    expect(forwardingLine(answering(inWork({ basis: 'validated', managed: true })), 's1')).toBe(
      `AKA: forwarding to Acme (${WORK_KEY}). ${OTHER_FOLDERS}`,
    );
    expect(forwardingLine(answering(accountScope('manual', true)), 's1')).toBe(
      `${WORK_LINE_BY_HAND} ${MANUAL_STOP}`,
    );
  });

  it('a session forwarded under an agent key, with no login basis, claims no work subscription and offers no stop command', () => {
    const forwardedAgentRoot: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: AGENT,
      rootForwards: true,
    };
    const scopes = [accountScope(undefined), accountScope(undefined, true), forwardedAgentRoot];
    for (const scope of scopes) {
      const line = forwardingLine(answering(scope), 's1');
      expect(line).toBe(KEYED_LINE);
      expect(line).not.toContain('work subscription');
      expect(line).not.toContain('--work-subscriptions');
      expect(line).not.toContain('--account');
    }
  });

  it('never prints an agent key, an account key or an org id', () => {
    const org = AGENT.split(':').pop() ?? '';
    const forwardedAgentRoot: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: AGENT,
      rootForwards: true,
    };
    const expected = [
      [accountScope('validated'), `${WORK_LINE} ${OPT_OUT}`],
      [accountScope(undefined), KEYED_LINE],
      [forwardedAgentRoot, KEYED_LINE],
    ] as const;
    for (const [scope, want] of expected) {
      const line = forwardingLine(answering(scope), 's1');
      expect(line).toBe(want);
      for (const needle of ['agent:', 'claude:', org]) expect(line).not.toContain(needle);
    }
  });

  it('prints no key for a root key that names neither a repository nor an agent', () => {
    for (const rootKey of [ACCOUNT_KEY, 'not-a-repository']) {
      const scope: ForwardingScope = {
        deploymentName: 'Acme',
        mode: 'scoped',
        rootKey,
        rootForwards: true,
      };
      const line = forwardingLine(answering(scope), 's1');
      expect(line === 'AKA: forwarding to Acme').toBe(true);
      expect(line?.includes(rootKey)).toBe(false);
    }
  });

  it('a root key that names no repository keeps the sentence about other folders for a work login', () => {
    const scope: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: ACCOUNT_KEY,
      rootForwards: true,
      work: { basis: 'validated', managed: false },
    };
    const line = forwardingLine(answering(scope), 's1');
    expect(line === `AKA: forwarding to Acme. ${OTHER_FOLDERS} ${OPT_OUT}`).toBe(true);
    expect(line?.includes(ORG)).toBe(false);
  });

  it('a personal session and an opted-out one keep the local-only line', () => {
    const local: ForwardingScope = {
      deploymentName: 'Acme',
      mode: 'scoped',
      rootKey: 'github.com/me/personal',
      rootForwards: false,
    };
    expect(forwardingLine(answering(local), 's1')).toBe(LOCAL_ONLY);
    expect(
      forwardingLine(answering({ deploymentName: 'Acme', mode: 'machine' }), 's1', {
        rootDeferred: true,
        basis: 'validated',
        managed: false,
      }),
    ).toBe('AKA: forwarding everything to Acme (machine-wide)');
  });

  it('hands the gateway the session it is given', () => {
    const asked: [string, ForwardingSession | undefined][] = [];
    const gateway = {
      forwardingScope: (rootId: string, session?: ForwardingSession): ForwardingScope => {
        asked.push([rootId, session]);
        return { deploymentName: 'Acme', mode: 'machine' };
      },
    };
    const session: ForwardingSession = { rootDeferred: true, basis: 'remembered', managed: false };
    forwardingLine(gateway, 's1', session);
    forwardingLine(gateway, 's2');
    expect(asked).toEqual([
      ['s1', session],
      ['s2', undefined],
    ]);
  });
});

// A client that accepts every write and sends nothing.
const client: AttachedClient = {
  ingestEvents: (batch) => Promise.resolve({ accepted: batch.events.length, duplicates: 0 }),
  ingestInventory: () => Promise.resolve({}),
  recordAuditEvent: () => Promise.resolve(),
  recordAuditEvents: (events) => Promise.resolve({ accepted: events.length }),
  reportStorePosture: () => Promise.resolve({}),
  recordProjectEgress: () => Promise.resolve({}),
};

/**
 * An attached gateway over `dataDir`. With `withAccount`, it also offers an
 * account scope over the same keys, as the factory builds one for a scoped
 * attachment whose identity record holds; the session start defers a root only
 * on such a gateway.
 */
function attachedOver(
  dataDir: string,
  mode: 'scoped' | 'machine',
  keys: readonly string[],
  withAccount = false,
  context: Partial<AccountScopeContext> = {},
): AttachedDataGateway {
  const keySet = new Set(keys);
  const account = createAccountScope({
    keys: keySet,
    scopeTag: SCOPE_TAG,
    bindingHash: 'b'.repeat(16),
    context: {
      attachedUserDigest: 'a'.repeat(64),
      workSubscriptionsOn: true,
      learned: [],
      manual: [],
      ...context,
    },
    learn: () => 'refused',
  });
  return new AttachedDataGateway({
    local: new StandaloneDataGateway(dataDir, bundledDetections()),
    client,
    dataDir,
    readCachedBundle: () => Promise.resolve(null),
    forward: createForwardPolicy({ dir: dataDir }),
    attachment: { mode, keys: keySet },
    deploymentName: 'Acme',
    ...(withAccount ? { account } : {}),
  });
}

describe('AttachedDataGateway.forwardingScope — a work-subscription session', () => {
  let tmp: string;
  let dataDir: string;
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'aka-forwarding-account-'));
    dataDir = join(tmp, 'data');
    migratedStore.seed(dataDir);
  });
  afterEach(() => {
    removeTree(tmp);
  });

  const root = (id: string, scopeKey: string) => ({
    id,
    eventType: 'session' as const,
    startedAt: new Date().toISOString(),
    attributes: { scope_key: scopeKey },
  });
  const work: ForwardingSession = { rootDeferred: false, basis: 'validated', managed: false };

  it('answers account for a root it forwards under an agent key, with the session’s basis', async () => {
    const gateway = attachedOver(dataDir, 'scoped', [AGENT]);
    try {
      await gateway.recordAuditEvent(root('s1', AGENT));
      expect(gateway.forwardingScope('s1', work)).toEqual(accountScope('validated'));
      expect(gateway.forwardingScope('s1')).toEqual(accountScope(undefined));
    } finally {
      await gateway.close();
    }
  });

  it('says the account a root forwards under, and no work subscription, when the session has no login basis', async () => {
    const gateway = attachedOver(dataDir, 'scoped', [AGENT]);
    try {
      await gateway.recordAuditEvent(root('s8', AGENT));
      expect(forwardingLine(gateway, 's8', { ...work, basis: undefined })).toBe(KEYED_LINE);
      expect(forwardingLine(gateway, 's8', work)).toBe(`${WORK_LINE} ${OPT_OUT}`);
    } finally {
      await gateway.close();
    }
  });

  it('answers account-pending for a root the session start left to the reconcile, and null when it did not', async () => {
    const gateway = attachedOver(dataDir, 'scoped', [AGENT]);
    try {
      expect(gateway.forwardingScope('s2', { ...work, rootDeferred: true, managed: true })).toEqual(
        pendingScope('validated', true),
      );
      expect(gateway.forwardingScope('s2', work)).toBeNull();
    } finally {
      await gateway.close();
    }
  });

  it('reports in an account-pending answer whether its account scope has work subscriptions on', async () => {
    const deferred: ForwardingSession = { ...work, rootDeferred: true, basis: undefined };
    for (const workSubscriptionsOn of [true, false]) {
      const gateway = attachedOver(dataDir, 'scoped', [WORK_KEY], true, { workSubscriptionsOn });
      try {
        expect(gateway.forwardingScope('s6', deferred)).toEqual(
          pendingScope(undefined, false, workSubscriptionsOn),
        );
      } finally {
        await gateway.close();
      }
    }
  });

  it('keeps a root it holds local out of account, even under an agent key', async () => {
    const gateway = attachedOver(dataDir, 'scoped', [WORK_KEY]);
    try {
      await gateway.recordAuditEvent(root('s5', AGENT));
      expect(gateway.forwardingScope('s5', work)).toMatchObject({
        mode: 'scoped',
        rootKey: AGENT,
        rootForwards: false,
      });
      expect(forwardingLine(gateway, 's5', work)).toBe(LOCAL_ONLY);
    } finally {
      await gateway.close();
    }
  });

  it('prints no key for a forwarded root whose stored key names neither a repository nor an agent', async () => {
    const gateway = attachedOver(dataDir, 'scoped', [ACCOUNT_KEY]);
    try {
      await gateway.recordAuditEvent(root('s7', ACCOUNT_KEY));
      const scope = gateway.forwardingScope('s7');
      expect(scope?.mode === 'scoped' && scope.rootForwards).toBe(true);
      const line = forwardingLine(gateway, 's7');
      expect(line === 'AKA: forwarding to Acme').toBe(true);
    } finally {
      await gateway.close();
    }
  });

  it('adds work to a repository root only for a work login, and keeps machine mode', async () => {
    const scoped = attachedOver(dataDir, 'scoped', [WORK_KEY]);
    try {
      await scoped.recordAuditEvent(root('s3', WORK_KEY));
      expect(scoped.forwardingScope('s3', work)).toEqual(
        inWork({ basis: 'validated', managed: false }),
      );
      expect(scoped.forwardingScope('s3', { ...work, basis: undefined })).toEqual(inWork());
    } finally {
      await scoped.close();
    }
    const machine = attachedOver(dataDir, 'machine', []);
    try {
      expect(machine.forwardingScope('s4', { ...work, rootDeferred: true })).toEqual({
        deploymentName: 'Acme',
        mode: 'machine',
      });
    } finally {
      await machine.close();
    }
  });
});

describe('workSubscriptionOptOutOffered and handleSessionStart', () => {
  let tmp: string;
  let home: string;
  let restore: () => void;
  let accountContext: Partial<AccountScopeContext>;
  let enrolledKeys: readonly string[];
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'aka-forwarding-session-'));
    home = join(tmp, 'home');
    mkdirSync(join(tmp, 'scratch'), { recursive: true });
    migratedStore.seed(join(home, 'data'));
    accountContext = {};
    enrolledKeys = [WORK_KEY];
    // The session start defers a root only on a gateway that offers an account scope.
    restore = setDefaultGatewayFactory((config) =>
      attachedOver(config.dataDir, 'scoped', enrolledKeys, true, accountContext),
    );
  });
  afterEach(() => {
    restore();
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([]);
    removeTree(tmp);
  });

  /** An administrator's file pinning this machine's deployment, the shape a fleet overlay ships. */
  function manage(): void {
    const file = join(tmp, MANAGED_SETTINGS_FILENAME);
    writeFileSync(
      file,
      JSON.stringify({
        specVersion: 1,
        organization: 'Example IT',
        values: { controlPlane: { endpoint: ENDPOINT, label: 'Example' } },
      }),
    );
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);
  }

  function config(): PluginConfig {
    return {
      settings: {
        ...defaultWorkspaceSettings(),
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: new Date().toISOString() },
      },
      dataDir: join(home, 'data'),
      dbPath: join(home, 'data', 'aka.db'),
      settingsDir: join(home, 'settings'),
      onboarded: true,
      provider: { provider: 'anthropic' },
    };
  }

  async function deferredLine(
    accountBasis: NonNullable<Basis> = 'validated',
    recordSession?: boolean,
  ): Promise<string | null> {
    const result = await handleSessionStart(
      {
        sessionId: randomUUID(),
        cwd: join(tmp, 'scratch'),
        tool: SOURCE_TOOL.ClaudeCode,
        homeDir: home,
        rootAwaitsAccount: true,
        accountBasis,
        recordSession,
      },
      config(),
    );
    return result.forwardingLine;
  }

  /** A session start whose login cannot be read, in a folder outside every enrolled repository. */
  async function undeterminedLine(): Promise<string | null> {
    const result = await handleSessionStart(
      {
        sessionId: randomUUID(),
        cwd: join(tmp, 'scratch'),
        tool: SOURCE_TOOL.ClaudeCode,
        homeDir: home,
        rootAwaitsAccount: true,
        accountBasis: undefined,
      },
      config(),
    );
    return result.forwardingLine;
  }

  it('offers the opt-out on an unmanaged device, and not where an administrator manages the connection', () => {
    expect(workSubscriptionOptOutOffered(join(home, 'settings'))).toBe(true);
    manage();
    expect(workSubscriptionOptOutOffered(join(home, 'settings'))).toBe(false);
  });

  it('offers the opt-out when the managed file cannot be read', () => {
    const file = join(tmp, MANAGED_SETTINGS_FILENAME);
    writeFileSync(file, 'this is not a settings file');
    UNSAFE_TEST_ONLY_setManagedSettingsPaths([file]);
    expect(workSubscriptionOptOutOffered(join(home, 'settings'))).toBe(true);
  });

  it('offers the opt-out when the settings directory cannot be resolved', () => {
    expect(workSubscriptionOptOutOffered(undefined as unknown as string)).toBe(true);
  });

  it('prints the pending line with the opt-out for a root the session start left to the reconcile', async () => {
    expect(await deferredLine()).toBe(`${PENDING_LINE} ${OPT_OUT}`);
  });

  it('drops the opt-out from that line where an administrator manages the connection', async () => {
    manage();
    expect(await deferredLine()).toBe(PENDING_LINE);
  });

  it('names the command that stops an account enrolled by hand, for a root left to the reconcile', async () => {
    expect(await deferredLine('manual')).toBe(`${PENDING_BY_HAND} ${MANUAL_STOP}`);
  });

  it('prints no line for a session the device does not record', async () => {
    expect(await deferredLine('validated', false)).toBeNull();
  });

  it('keeps the work-subscription line, with the opt-out, for an unreadable login while recognition is on', async () => {
    accountContext = { manual: [MANUAL_ACCOUNT] };
    expect(await undeterminedLine()).toBe(`${PENDING_LINE} ${OPT_OUT}`);
  });

  it('names the account enrolled by hand, and no work subscription, when recognition is off and the login cannot be read', async () => {
    accountContext = { workSubscriptionsOn: false, manual: [MANUAL_ACCOUNT] };
    const line = await undeterminedLine();
    expect(line === null).toBe(false);
    expect(line?.includes('work subscription')).toBe(false);
    expect(line?.includes('--work-subscriptions')).toBe(false);
    expect(line?.includes('aka unenroll --account')).toBe(true);
    expect(line === `${PENDING_BY_HAND} ${MANUAL_STOP}`).toBe(true);
  });

  it('names the account enrolled by hand where an administrator manages the connection too', async () => {
    manage();
    accountContext = { workSubscriptionsOn: false, manual: [MANUAL_ACCOUNT] };
    expect((await undeterminedLine()) === `${PENDING_BY_HAND} ${MANUAL_STOP}`).toBe(true);
  });

  /** A resumed session: its root was keyed under an agent key by an earlier run, and its login now shows no work account. */
  async function resumedLine(): Promise<string | null> {
    const sessionId = randomUUID();
    enrolledKeys = [AGENT];
    const earlier = attachedOver(join(home, 'data'), 'scoped', [AGENT], true);
    try {
      await earlier.recordAuditEvent({
        id: sessionId,
        eventType: 'session',
        startedAt: new Date().toISOString(),
        attributes: { scope_key: AGENT },
      });
    } finally {
      await earlier.close();
    }
    const result = await handleSessionStart(
      {
        sessionId,
        cwd: join(tmp, 'scratch'),
        tool: SOURCE_TOOL.ClaudeCode,
        homeDir: home,
        accountBasis: undefined,
      },
      config(),
    );
    return result.forwardingLine;
  }

  it('says the account a resumed session was keyed under, and no work subscription, when its login shows none', async () => {
    expect(await resumedLine()).toBe(KEYED_LINE);
  });

  it('says that too where an administrator manages the connection, and offers no stop command', async () => {
    manage();
    const line = await resumedLine();
    expect(line).toBe(KEYED_LINE);
    expect(line).not.toContain('--work-subscriptions');
    expect(line).not.toContain('--account');
  });
});

describe('forwardingLine — a Codex thread on a work subscription', () => {
  const STOPS = 'it stops if the thread is resumed or its login changes.';
  const CODEX_WORK_LINE = `AKA: forwarding this thread to Acme — signed in to a ChatGPT work subscription; ${STOPS}`;
  const CODEX_BY_HAND =
    'AKA: forwarding this thread to Acme — signed in to a ChatGPT workspace you enrolled by hand; it stops if the thread is resumed or switches to another workspace or login mode.';
  const CODEX_KEYED =
    'AKA: this thread first ran under a ChatGPT workspace forwarded to Acme; from here it follows the repository rule, so only work in an enrolled repository is forwarded.';
  const WORKSPACE = randomUUID();

  function codexRootKey(): string {
    const key = agentKey(SCOPE_TAG, `chatgpt:${WORKSPACE}`);
    if (key === undefined) throw new Error('the test agent key did not form');
    return key;
  }

  function codexAccount(basis: Basis, managed = false): ForwardingScope {
    return {
      deploymentName: 'Acme',
      mode: 'account',
      rootKey: codexRootKey(),
      basis,
      managed,
    };
  }

  const codexForwardedRoot = (work?: {
    basis: NonNullable<Basis>;
    managed: boolean;
  }): ForwardingScope => ({
    deploymentName: 'Acme',
    mode: 'scoped',
    rootKey: codexRootKey(),
    rootForwards: true,
    ...(work === undefined ? {} : { work }),
  });

  it.each(['validated', 'remembered'] as const)(
    'names the thread and the ChatGPT work subscription, then the opt-out, for a %s thread',
    (basis) => {
      expect(forwardingLine(answering(codexAccount(basis)), 's1')).toBe(
        `${CODEX_WORK_LINE} ${OPT_OUT}`,
      );
    },
  );

  it('leaves the opt-out out where an administrator manages the connection', () => {
    expect(forwardingLine(answering(codexAccount('validated', true)), 's1')).toBe(CODEX_WORK_LINE);
  });

  it('names the workspace enrolled by hand and the command that removes it, never a work subscription', () => {
    for (const managed of [false, true]) {
      const line = forwardingLine(answering(codexAccount('manual', managed)), 's1');
      expect(line).toBe(`${CODEX_BY_HAND} ${MANUAL_STOP}`);
      expect(line).not.toContain('work subscription');
      expect(line).not.toContain('--work-subscriptions');
    }
  });

  it('claims no work subscription and offers no stop command for a thread with no login basis', () => {
    for (const scope of [
      codexAccount(undefined),
      codexAccount(undefined, true),
      codexForwardedRoot(),
    ]) {
      const line = forwardingLine(answering(scope), 's1');
      expect(line).toBe(CODEX_KEYED);
      expect(line).not.toContain('work subscription');
      expect(line).not.toContain('--work-subscriptions');
      expect(line).not.toContain('--account');
    }
  });

  it('words a forwarded agent-keyed root the same way', () => {
    expect(
      forwardingLine(answering(codexForwardedRoot({ basis: 'validated', managed: false })), 's1'),
    ).toBe(`${CODEX_WORK_LINE} ${OPT_OUT}`);
    expect(
      forwardingLine(answering(codexForwardedRoot({ basis: 'manual', managed: false })), 's1'),
    ).toBe(`${CODEX_BY_HAND} ${MANUAL_STOP}`);
  });

  it('prints no key, workspace id or tag', () => {
    for (const basis of ['validated', 'remembered', 'manual', undefined] as const) {
      const line = forwardingLine(answering(codexAccount(basis)), 's1') ?? '';
      for (const material of [WORKSPACE, 'chatgpt:', 'agent:', SCOPE_TAG]) {
        expect(line).not.toContain(material);
      }
    }
  });

  it('keeps the Claude Code wording for a Claude account', () => {
    expect(forwardingLine(answering(accountScope('validated')), 's1')).toBe(
      `${WORK_LINE} ${OPT_OUT}`,
    );
    expect(forwardingLine(answering(accountScope('manual')), 's1')).toBe(
      `${WORK_LINE_BY_HAND} ${MANUAL_STOP}`,
    );
    expect(forwardingLine(answering(accountScope(undefined)), 's1')).toBe(KEYED_LINE);
  });
});

describe('forwardingLine — a Codex thread whose ChatGPT account is not decided yet', () => {
  const PENDING =
    "This thread's ChatGPT account is checked once more at its next prompt or tool call. If this device then recognises it as a work subscription, or it is a workspace you enrolled by hand, the thread's prompts, tool calls and results are forwarded to Acme from any folder from then on. Otherwise, including if the account still cannot be read, the thread follows the repository rule.";
  const pendingSession: ForwardingSession = {
    rootDeferred: false,
    basis: undefined,
    managed: false,
    threadAccountPending: true,
  };
  const localRoot: ForwardingScope = {
    deploymentName: 'Acme',
    mode: 'scoped',
    rootKey: 'github.com/me/notes',
    rootForwards: false,
  };
  const enrolledRoot: ForwardingScope = {
    deploymentName: 'Acme',
    mode: 'scoped',
    rootKey: WORK_KEY,
    rootForwards: true,
  };

  it('ends the local-only line with what the next check can change', () => {
    expect(forwardingLine(answering(localRoot), 's1', pendingSession)).toBe(
      `${LOCAL_ONLY}. ${PENDING}`,
    );
    expect(
      forwardingLine(answering({ ...localRoot, rootKey: undefined }), 's1', pendingSession),
    ).toBe(`${LOCAL_ONLY}. ${PENDING}`);
  });

  it('ends the line of an enrolled folder the same way', () => {
    expect(forwardingLine(answering(enrolledRoot), 's1', pendingSession)).toBe(
      `AKA: forwarding to Acme (${WORK_KEY}). ${PENDING}`,
    );
  });

  it.each<[string, ForwardingSession | undefined]>([
    ['no session', undefined],
    ['a session that is not pending', { ...pendingSession, threadAccountPending: false }],
    ['a session that does not say', { rootDeferred: false, basis: undefined, managed: false }],
  ])('leaves the line as it is for %s', (_name, session) => {
    expect(forwardingLine(answering(localRoot), 's1', session)).toBe(LOCAL_ONLY);
    expect(forwardingLine(answering(enrolledRoot), 's1', session)).toBe(
      `AKA: forwarding to Acme (${WORK_KEY})`,
    );
  });

  it('prints no key, workspace id or tag', () => {
    const line = forwardingLine(answering(localRoot), 's1', pendingSession) ?? '';
    for (const material of ['chatgpt:', 'agent:', SCOPE_TAG]) expect(line).not.toContain(material);
  });

  it('makes the forwarding conditional on the next check and names what happens otherwise', () => {
    const line = forwardingLine(answering(localRoot), 's1', pendingSession) ?? '';
    const sentence = line.slice(line.indexOf("This thread's"));
    expect(sentence).toBe(PENDING);
    expect(sentence.replace('recognises it as a work subscription', '')).not.toContain(
      'work subscription',
    );
    expect(sentence.indexOf('If this device then recognises')).toBeGreaterThan(-1);
    expect(sentence.indexOf('If this device then recognises')).toBeLessThan(
      sentence.indexOf('are forwarded'),
    );
    expect(sentence.endsWith('the thread follows the repository rule.')).toBe(true);
  });
});
