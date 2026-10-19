import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { createPluginRuntime } from '@akasecurity/plugin-sdk';
import type * as RemoteModule from '@akasecurity/remote';
import type {
  AttachmentMode,
  Policy,
  PolicyBundle,
  ResolvedAttachmentScope,
  WorkspaceSettings,
} from '@akasecurity/schema';
import { defaultWorkspaceSettings, Rule, SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy.ts';
import type { AttachedClient } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';
import type { GovernanceScope } from '../../src/index.ts';
import { governanceApplies, offersGovernanceScope, resolveDataGateway } from '../../src/index.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// Where the organization's model policy applies, and what that answer must not
// reach.
//
// The question is the one a model-guard site asks once it has decided to refuse
// a prohibited model: does the organization govern the event in hand? The
// attached gateway answers from the attachment it holds: a machine-wide one
// governs every event, a scoped one only an event keyed to an enrolled
// repository. Any other gateway is governed, as every gateway was before the
// question existed.
//
// The other half is what the answer must NOT reach. Detections, their actions,
// the organization's raise-only policies and its keyword rules come from the
// policy bundle, which is the same on either attachment, so they still apply in
// a personal repository. Those cases pass with or without the capability: they
// hold the line that scoping governance never scopes detection.
//
// The helper cases use plain objects. The gateway and detection cases build the
// attached gateway by hand over a real local store, with a recording client and
// the organization's bundle in its cache. The factory cases read real credential
// files from a temporary home, with the client factory faked. Nothing here sends
// a request anywhere.

vi.mock('@akasecurity/remote', async (importOriginal) => ({
  ...(await importOriginal<typeof RemoteModule>()),
  // The factory builds a client for an attached credential. Nothing in this
  // suite sends through it: the hand-built gateways carry their own recorder.
  createRemoteClient: () => ({}),
}));

const ENDPOINT = 'https://aka.acme.test';
const OTHER_ENDPOINT = 'https://aka.old.test';
const AT = '2026-10-08T09:00:00.000Z';
const TEST_KEY = 'not-a-real-key';
const WORK_REPO = 'github.com/acme/payments-api';
const PERSONAL_REPO = 'github.com/someone/side-project';
const PROHIBITED = ['example-frontier-model'];

const MACHINE: ResolvedAttachmentScope = { mode: 'machine', keys: new Set<string>() };
const SCOPED: ResolvedAttachmentScope = { mode: 'scoped', keys: new Set([WORK_REPO]) };

// A marker the device's OWN bundle detects, with the device's action for its
// category set to warn. The organization raises that one rule to block.
const MARKER = 'GOVERNANCE_SCOPE_SECRET_MARKER';
const MARKER_RULE_ID = 'governance-scope/secret-marker';
// A keyword only the ORGANIZATION ships, as a keyword rule in its bundle: the
// form in which an organization's keyword reaches this device's detection.
const ORG_KEYWORD = 'ORCHID-LANTERN';
const ORG_KEYWORD_RULE_ID = 'org-keywords/project-codename';

const MARKER_RULE = Rule.parse({
  specVersion: 1,
  id: MARKER_RULE_ID,
  name: 'Governance scope secret marker',
  category: 'secret',
  severity: 'critical',
  matcher: { type: 'keyword', keywords: [MARKER] },
});

const ORG_KEYWORD_RULE = Rule.parse({
  specVersion: 1,
  id: ORG_KEYWORD_RULE_ID,
  name: 'Organization project codename',
  category: 'custom',
  severity: 'high',
  matcher: { type: 'keyword', keywords: [ORG_KEYWORD] },
});

const policy = (target: Policy['target'], action: Policy['action']): Policy => ({
  id: randomUUID(),
  scope: 'global',
  target,
  action,
  enabled: true,
});

const LOCAL_BUNDLE: PolicyBundle = {
  version: 'local',
  policies: [policy({ category: 'secret' }, 'warn')],
  rules: [MARKER_RULE],
  customKeywords: ['local-word'],
  fetchedAt: AT,
};

const ORG_BUNDLE: PolicyBundle = {
  version: 'org-1',
  policies: [
    policy({ ruleId: MARKER_RULE_ID }, 'block'),
    policy({ ruleId: ORG_KEYWORD_RULE_ID }, 'block'),
  ],
  rules: [ORG_KEYWORD_RULE],
  customKeywords: [ORG_KEYWORD],
  prohibitedModels: PROHIBITED,
  fetchedAt: AT,
};

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-governance-scope-'));
  // Schema by file copy rather than a migration per test.
  migratedStore.seed(dataDirOf(home));
});

afterEach(() => {
  removeTree(home);
});

/**
 * The device's own store, real, with its policy bundle fixed and two of its reads
 * counted: the attached gateway's governance answer must come from neither.
 */
class LocalStore extends StandaloneDataGateway {
  readonly rootReads: string[] = [];
  bundleReads = 0;
  private readonly bundle: PolicyBundle;

  constructor(dataDir: string, bundle: PolicyBundle = LOCAL_BUNDLE) {
    super(dataDir);
    this.bundle = bundle;
  }

  override getPolicyBundle(): Promise<PolicyBundle> {
    this.bundleReads += 1;
    return Promise.resolve(this.bundle);
  }

  override readSessionScopeKey(sessionId: string): string | undefined {
    this.rootReads.push(sessionId);
    return super.readSessionScopeKey(sessionId);
  }
}

/** A client that answers every call and records which ones were made. */
function recordingClient(sent: string[]): AttachedClient {
  const record = <T>(name: string, value: T): Promise<T> => {
    sent.push(name);
    return Promise.resolve(value);
  };
  return {
    ingestEvents: (batch) =>
      record('ingestEvents', { accepted: batch.events.length, duplicates: 0 }),
    ingestInventory: () => record('ingestInventory', {}),
    recordAuditEvent: () => record('recordAuditEvent', undefined),
    recordAuditEvents: (events) => record('recordAuditEvents', { accepted: events.length }),
    reportStorePosture: () => record('reportStorePosture', {}),
    recordProjectEgress: () => record('recordProjectEgress', {}),
  };
}

const passthrough = (): ForwardPolicy => ({
  run: async <T>(op: () => Promise<T>): Promise<ForwardResult<T>> => {
    try {
      return { ok: true, value: await op() };
    } catch {
      return { ok: false, reason: 'unreachable' };
    }
  },
});

/** An attached gateway over `local`, with the organization's bundle in its cache. */
function attachedOver(local: LocalStore, attachment: ResolvedAttachmentScope) {
  const sent: string[] = [];
  const readCachedBundle = vi.fn((): Promise<PolicyBundle | null> => Promise.resolve(ORG_BUNDLE));
  const gateway = new AttachedDataGateway({
    dataDir: dataDirOf(home),
    local,
    client: recordingClient(sent),
    readCachedBundle,
    forward: passthrough(),
    attachment,
  });
  return { gateway, sent, readCachedBundle };
}

function configWith(settings: WorkspaceSettings): PluginConfig {
  return {
    settings,
    dataDir: dataDirOf(home),
    dbPath: dbPathOf(home),
    settingsDir: settingsDirOf(home),
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

/** A credential on disk in `mode`, and settings attached to its endpoint. */
function attachedConfig(mode: AttachmentMode, scope?: unknown): PluginConfig {
  writeControlPlaneCredential(
    settingsDirOf(home),
    mode === 'scoped'
      ? { specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: TEST_KEY, mintedAt: AT }
      : { specVersion: 1, endpoint: ENDPOINT, apiKey: TEST_KEY, mintedAt: AT },
  );
  return configWith({
    ...defaultWorkspaceSettings(),
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
    ...(scope === undefined ? {} : { attachmentScope: scope }),
  });
}

/** A scope record that enrolls the work repository, recorded for `endpoint`. */
const enrolled = (endpoint: string): unknown => ({
  endpoint,
  entries: [{ kind: 'repo', identity: WORK_REPO, enrolledAt: AT }],
});

/** The answer for an enrolled repository, a personal one, and no repository. */
const governedFor = (gateway: object): boolean[] =>
  [WORK_REPO, PERSONAL_REPO, undefined].map((key) => governanceApplies(gateway, key));

const runtimeSettings = (): WorkspaceSettings => ({
  ...defaultWorkspaceSettings(),
  policy: 'redact',
});

describe('governanceApplies — the question a model-guard site asks', () => {
  const stub = {
    getPolicyBundle: () => Promise.resolve(ORG_BUNDLE),
    recordAuditEvent: () => Promise.resolve(),
    close: () => Promise.resolve(),
  };

  it('governs every event through a gateway without the capability', () => {
    // The stubs the model-guard suites hand their sites look like this, and so,
    // to this question, do the local gateway and any gateway another program
    // builds over the same port.
    expect(offersGovernanceScope(stub)).toBe(false);
    expect(
      [WORK_REPO, PERSONAL_REPO, undefined, ''].map((key) => governanceApplies(stub, key)),
    ).toEqual([true, true, true, true]);
  });

  it('hands the event key to the capability and returns its answer', () => {
    const asked: (string | undefined)[] = [];
    const capable = {
      governanceAppliesTo: (key: string | undefined): boolean => {
        asked.push(key);
        return key === WORK_REPO;
      },
    };
    expect(offersGovernanceScope(capable)).toBe(true);
    expect(governedFor(capable)).toEqual([true, false, false]);
    expect(asked).toEqual([WORK_REPO, PERSONAL_REPO, undefined]);
  });

  it('does not govern when the capability throws', () => {
    const failing = {
      governanceAppliesTo: (): never => {
        throw new Error('a capability that fails');
      },
    };
    expect(offersGovernanceScope(failing)).toBe(true);
    expect(governedFor(failing)).toEqual([false, false, false]);
  });

  it('does not govern when the capability cannot even be read', () => {
    const unreadable = Object.defineProperty({}, 'governanceAppliesTo', {
      get(): never {
        throw new Error('a capability that cannot be read');
      },
    });
    expect(governedFor(unreadable)).toEqual([false, false, false]);
  });

  it('governs only on an answer of exactly true', () => {
    // The compiler holds a TypeScript implementation to a boolean; nothing holds
    // every implementation to it, and an answer that is not `true` is not
    // knowledge that the organization governs the event.
    for (const answer of ['true', 1, {}]) {
      const odd = { governanceAppliesTo: () => answer as unknown as boolean };
      expect(governanceApplies(odd, WORK_REPO)).toBe(false);
    }
  });

  it('keeps the narrowed gateway type a model-guard site holds', async () => {
    // Most sites hold a Pick of the gateway's members. This case stops
    // typechecking if the guard is typed on DataGateway, as the port's own
    // guards are: a Pick does not fit that parameter.
    const capable = {
      ...stub,
      governanceAppliesTo: (key: string | undefined): boolean => key === WORK_REPO,
    };
    const site: Pick<DataGateway, 'getPolicyBundle' | 'recordAuditEvent' | 'close'> = capable;
    expect(offersGovernanceScope(site)).toBe(true);
    if (offersGovernanceScope(site)) {
      expect((await site.getPolicyBundle()).version).toBe('org-1');
      expect(site.governanceAppliesTo(WORK_REPO)).toBe(true);
    }
  });
});

describe('AttachedDataGateway.governanceAppliesTo — the attachment it holds decides', () => {
  it.each<[string, string | undefined]>([
    ['an enrolled repository', WORK_REPO],
    ['a personal repository', PERSONAL_REPO],
    ['a directory in no repository', undefined],
    ['an empty key', ''],
  ])('a machine-wide attachment governs %s', async (_name, key) => {
    const { gateway } = attachedOver(new LocalStore(dataDirOf(home)), MACHINE);
    try {
      expect(gateway.governanceAppliesTo(key)).toBe(true);
    } finally {
      await gateway.close();
    }
  });

  // The expected answer sits second so the title's two `%s` read the row's name
  // and then that answer.
  it.each<[string, boolean, string | undefined]>([
    ['an enrolled repository', true, WORK_REPO],
    ['a personal repository', false, PERSONAL_REPO],
    ['a directory in no repository', false, undefined],
    ['an empty key', false, ''],
    ['the enrolled key in another case', false, WORK_REPO.toUpperCase()],
  ])('a scoped attachment answers %s with %s', async (_name, governed, key) => {
    const { gateway } = attachedOver(new LocalStore(dataDirOf(home)), SCOPED);
    try {
      expect(gateway.governanceAppliesTo(key)).toBe(governed);
    } finally {
      await gateway.close();
    }
  });

  it('does not govern when the enrolled set cannot be read', async () => {
    const keys = {
      has(): never {
        throw new Error('a set that cannot be read');
      },
    } as unknown as ReadonlySet<string>;
    const { gateway } = attachedOver(new LocalStore(dataDirOf(home)), { mode: 'scoped', keys });
    try {
      expect(gateway.governanceAppliesTo(WORK_REPO)).toBe(false);
    } finally {
      await gateway.close();
    }
  });

  it('does not govern when the attachment itself cannot be read', async () => {
    const attachment = Object.defineProperty({ keys: new Set([WORK_REPO]) }, 'mode', {
      get(): never {
        throw new Error('an attachment that cannot be read');
      },
    }) as unknown as ResolvedAttachmentScope;
    const { gateway } = attachedOver(new LocalStore(dataDirOf(home)), attachment);
    try {
      expect(gateway.governanceAppliesTo(WORK_REPO)).toBe(false);
      expect(gateway.governanceAppliesTo(undefined)).toBe(false);
    } finally {
      await gateway.close();
    }
  });

  it('decides by the event key alone, with no store, bundle or network read', async () => {
    // The question is asked on a decision path the user is waiting on, so it is
    // answered from the attachment in memory. It is the EVENT's key: no session
    // root is consulted, since a prohibition is about where the event happened
    // and the root rule exists for forwarding audit rows.
    const local = new LocalStore(dataDirOf(home));
    const { gateway, sent, readCachedBundle } = attachedOver(local, SCOPED);
    try {
      expect(
        [WORK_REPO, PERSONAL_REPO, undefined].map((key) => gateway.governanceAppliesTo(key)),
      ).toEqual([true, false, false]);
      expect(local.rootReads).toEqual([]);
      expect(local.bundleReads).toBe(0);
      expect(readCachedBundle).toHaveBeenCalledTimes(0);
      expect(sent).toEqual([]);
    } finally {
      await gateway.close();
    }
  });

  it('is offered by the attached gateway and not by the local one', async () => {
    const { gateway } = attachedOver(new LocalStore(dataDirOf(home)), MACHINE);
    const standalone = new StandaloneDataGateway(dataDirOf(home));
    try {
      expect(offersGovernanceScope(gateway)).toBe(true);
      // @ts-expect-error -- the local gateway holds no attachment to answer from
      const typed: GovernanceScope = standalone;
      expect(offersGovernanceScope(typed)).toBe(false);
    } finally {
      await standalone.close();
      await gateway.close();
    }
  });
});

describe('the gateway a hook opens, from the configuration on disk', () => {
  // Opened through resolveDataGateway, the call each plugin's openGateway makes,
  // so a wrapper added between the factory and resolveDataGateway's return could
  // not hide the capability and silently govern every repository again. Each
  // plugin's own openGateway is past this package's reach, so these cases do not
  // pin it.

  it('opens the local gateway on a machine with no attachment, and it governs every event', async () => {
    const gateway = resolveDataGateway(configWith(defaultWorkspaceSettings()));
    try {
      expect(gateway).toBeInstanceOf(StandaloneDataGateway);
      expect(offersGovernanceScope(gateway)).toBe(false);
      expect(governedFor(gateway)).toEqual([true, true, true]);
    } finally {
      await gateway.close();
    }
  });

  it('governs every event under a machine-wide credential, as before', async () => {
    // The enrolled scope on disk is ignored: a machine-wide attachment never reads it.
    const gateway = resolveDataGateway(attachedConfig('machine', enrolled(ENDPOINT)));
    try {
      expect(gateway).toBeInstanceOf(AttachedDataGateway);
      expect(offersGovernanceScope(gateway)).toBe(true);
      expect(governedFor(gateway)).toEqual([true, true, true]);
    } finally {
      await gateway.close();
    }
  });

  it('governs only events in an enrolled repository under a scoped credential', async () => {
    const gateway = resolveDataGateway(attachedConfig('scoped', enrolled(ENDPOINT)));
    try {
      expect(gateway).toBeInstanceOf(AttachedDataGateway);
      expect(governedFor(gateway)).toEqual([true, false, false]);
    } finally {
      await gateway.close();
    }
  });

  it.each<[string, unknown]>([
    ['no scope recorded', undefined],
    ['a record that is not a scope', 'not-a-scope-record'],
    ['a scope recorded for another deployment', enrolled(OTHER_ENDPOINT)],
    ['a scope with nothing enrolled', { endpoint: ENDPOINT, entries: [] }],
  ])('governs no event under a scoped credential with %s', async (_name, scope) => {
    const gateway = resolveDataGateway(attachedConfig('scoped', scope));
    try {
      expect(gateway).toBeInstanceOf(AttachedDataGateway);
      expect(governedFor(gateway)).toEqual([false, false, false]);
    } finally {
      await gateway.close();
    }
  });
});

describe('detection on a scoped attachment stays machine-wide', () => {
  it('composes the bundle a machine-wide attachment composes, prohibited models and keywords included', async () => {
    const local = new LocalStore(dataDirOf(home));
    const machine = attachedOver(local, MACHINE).gateway;
    const scoped = attachedOver(local, SCOPED).gateway;
    try {
      const fromScoped = await scoped.getPolicyBundle();
      expect(fromScoped).toEqual(await machine.getPolicyBundle());
      expect(fromScoped.prohibitedModels).toEqual(PROHIBITED);
      expect(fromScoped.customKeywords).toEqual(['local-word', ORG_KEYWORD]);
      expect(fromScoped.rules?.map((rule) => rule.id)).toEqual([
        MARKER_RULE_ID,
        ORG_KEYWORD_RULE_ID,
      ]);
    } finally {
      // One store under both gateways, so it is closed once.
      await local.close();
    }
  });

  it('an organization raise-only policy still applies in a personal repository', async () => {
    const { gateway, sent } = attachedOver(new LocalStore(dataDirOf(home)), SCOPED);
    const runtime = createPluginRuntime(gateway, runtimeSettings(), { dataDir: dataDirOf(home) });
    try {
      const personal = await runtime.capture({
        kind: 'prompt',
        sourceTool: SOURCE_TOOL.ClaudeCode,
        text: `${MARKER} in a personal project`,
        scopeKey: PERSONAL_REPO,
      });
      // Kept on this machine: the scope verdict reads the event as personal.
      expect(sent).toEqual([]);
      // And still detected, with the organization's action, which raises the
      // device's own warn for the category.
      expect(personal.action).toBe('block');

      // The control: the same detection in the enrolled repository, which is sent.
      const work = await runtime.capture({
        kind: 'prompt',
        sourceTool: SOURCE_TOOL.ClaudeCode,
        text: `${MARKER} in a work project`,
        scopeKey: WORK_REPO,
      });
      expect(work.action).toBe('block');
      expect(sent).toEqual(['ingestEvents']);
    } finally {
      await runtime.close();
    }
  });

  it('an organization keyword rule still fires in a personal repository', async () => {
    const { gateway, sent } = attachedOver(new LocalStore(dataDirOf(home)), SCOPED);
    const runtime = createPluginRuntime(gateway, runtimeSettings(), { dataDir: dataDirOf(home) });
    try {
      const result = await runtime.capture({
        kind: 'prompt',
        sourceTool: SOURCE_TOOL.ClaudeCode,
        text: `the ${ORG_KEYWORD} launch plan`,
        scopeKey: PERSONAL_REPO,
      });
      expect(result.findings.map((finding) => finding.ruleId)).toContain(ORG_KEYWORD_RULE_ID);
      expect(result.action).toBe('block');
      expect(sent).toEqual([]);
    } finally {
      await runtime.close();
    }
  });
});
