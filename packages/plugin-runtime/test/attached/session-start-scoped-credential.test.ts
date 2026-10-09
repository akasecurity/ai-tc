import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import type * as RemoteModule from '@akasecurity/remote';
import type {
  AuditEventInput,
  DetectedFinding,
  EgressIngestRequest,
  IngestBatch,
  IngestEvent,
  InventoryContext,
  ResolvedInventory,
  StorePostureSnapshot,
  WorkspaceSettings,
} from '@akasecurity/schema';
import { defaultWorkspaceSettings, SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { AttachedClient } from '../../src/attached/gateway.ts';
import { HISTORY_SYNC_MARKER_NAME } from '../../src/attached/history-sync-trigger.ts';
import { createPostureStore } from '../../src/attached/posture-store.ts';
import type * as SyncTriggerModule from '../../src/attached/sync-trigger.ts';
import { CONTENT_RETENTION_MARKER_NAME } from '../../src/content-retention-trigger.ts';
import { handleSessionStart } from '../../src/handle-session-start.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// A session start on a machine whose credential file really is a scoped (v2)
// one, read back by the real reader and built into a gateway by the real
// factory, beside a real local store and real checkouts. Only the network client
// and the detached policy refresh are replaced: the client by a recorder that
// answers every member the gateway can call, so no request leaves the machine,
// and the refresh by a recorder, so no child is spawned.
//
// A session start sends on three routes: the inventory, the audit-event route
// (the session root and the config scan) and the posture report. The gateway
// suite pins each verdict method by method on a hand-built attachment. This file
// is what fails when the pieces stop composing: a v2 file that no longer reaches
// the gateway as a scoped attachment, a mode that no longer reaches the posture
// report, or a posture count that starts following the scope. A machine
// credential beside the same settings is the control.

// Everything the gateway handed the client, per route, in order. The posture
// snapshot and the inventory context are serialized exactly as handed over, so
// their member order is the wire's; the audit routes re-validate a body before
// sending it.
const sent = vi.hoisted(() => ({
  inventory: [] as InventoryContext[],
  audit: [] as AuditEventInput[],
  auditBatches: [] as (readonly AuditEventInput[])[],
  posture: [] as StorePostureSnapshot[],
  captures: [] as IngestBatch[],
  egress: [] as EgressIngestRequest[],
}));

// Each policy refresh a session start asked for. Recorded instead of run: on an
// attached machine with a usable credential, which a scoped one is, the real
// trigger spawns a detached child. A session start asks for it after every send
// it makes, so counting the calls proves each pass got that far, and a case that
// expects nothing sent cannot pass because the pass gave up early.
const policySync = vi.hoisted(() => ({ configs: [] as PluginConfig[] }));

// The deployment's own ids for a session's inventory. A forwarded root is
// re-keyed with them, which is how a case sees that the inventory went first.
const DEPLOYMENT_INVENTORY = vi.hoisted((): ResolvedInventory => ({
  hostId: 'deployment-host',
  harnessId: 'deployment-harness',
  sourceProjectId: 'deployment-project',
}));

// The real module is spread first: the forward policy classifies a failed send
// with the transport's own helpers. The recorder is typed as the gateway's
// client, so a member the gateway gains later is a compile error here rather
// than a TypeError the breaker would count. Every member succeeds, so no failure
// can open the breaker and leave a "nothing sent" case passing by default.
vi.mock('@akasecurity/remote', async (importOriginal) => ({
  ...(await importOriginal<typeof RemoteModule>()),
  createRemoteClient: (): AttachedClient => ({
    ingestEvents: (batch) => {
      sent.captures.push(batch);
      return Promise.resolve({ accepted: batch.events.length, duplicates: 0 });
    },
    ingestInventory: (context) => {
      sent.inventory.push(context);
      return Promise.resolve(DEPLOYMENT_INVENTORY);
    },
    recordAuditEvent: (body) => {
      sent.audit.push(body);
      return Promise.resolve();
    },
    recordAuditEvents: (bodies) => {
      sent.auditBatches.push(bodies);
      return Promise.resolve({ accepted: bodies.length });
    },
    reportStorePosture: (snapshot) => {
      sent.posture.push(snapshot);
      return Promise.resolve({});
    },
    recordProjectEgress: (request) => {
      sent.egress.push(request);
      return Promise.resolve({});
    },
  }),
}));

vi.mock('../../src/attached/sync-trigger.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof SyncTriggerModule>()),
  triggerPolicySync: (config: PluginConfig) => {
    policySync.configs.push(config);
  },
}));

const ENDPOINT = 'https://aka.acme.test';
const AT = '2026-10-01T09:00:00.000Z';
const TEST_KEY = 'not-a-real-key';
const WORK_ORIGIN = 'https://github.com/acme/payments-api.git';
const WORK_KEY = 'github.com/acme/payments-api';
const PERSONAL_ORIGIN = 'https://github.com/someone/side-project.git';
const PERSONAL_KEY = 'github.com/someone/side-project';

// The line a scoped session shows when its own repository is not enrolled.
const LOCAL_ONLY_LINE =
  'AKA: local-only (not enrolled); work in an enrolled repository is still forwarded';

// A posture report's members, in the order the reporter writes them, with no
// plugin block: what a machine attachment reported before any mode existed.
const MACHINE_POSTURE_KEYS = [
  'deviceId',
  'hostname',
  'capturedAt',
  'storePresent',
  'schemaVersion',
  'findingsTotal',
  'findingsFirstAt',
  'findingsLastAt',
  'packs',
  'policyCounts',
];

// The three routes a session start never uses, silent in every case.
const NO_OTHER_ROUTE = { captures: 0, auditBatches: 0, egress: 0 };

// Neither of the other two detached children a session start can ask for was
// started: no history grant, and body retention off. Each trigger writes its
// marker just before it spawns, so a marker on disk means that trigger got past
// every gate it has.
const NO_CHILD = { historySync: false, contentRetention: false };

let tmp: string;
let home: string; // the ~/.aka base: settings, credential and store
let userHome: string; // a hermetic home, so the config scan never reads the real one
let work: string; // a checkout of the enrolled repository
let personal: string; // a checkout of a repository nobody enrolled
let scratch: string; // a directory inside no repository at all

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'aka-session-start-scoped-'));
  home = join(tmp, 'aka');
  userHome = join(tmp, 'user-home');
  work = join(tmp, 'work');
  personal = join(tmp, 'personal');
  scratch = join(tmp, 'scratch');
  mkdirSync(userHome, { recursive: true });
  mkdirSync(scratch, { recursive: true });
  gitRepo(work, WORK_ORIGIN);
  gitRepo(personal, PERSONAL_ORIGIN);
  // Schema by file copy rather than a migration per test.
  migratedStore.seed(dataDirOf(home));
  for (const route of Object.values(sent)) route.length = 0;
  policySync.configs.length = 0;
});

afterEach(() => {
  removeTree(tmp);
});

/** A checkout whose origin is `url`: the `.git/config` the resolvers read. No git runs. */
function gitRepo(dir: string, url: string): void {
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(
    join(dir, '.git', 'config'),
    `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${url}\n`,
  );
}

/**
 * The configuration a session start is handed, attached to ENDPOINT, with
 * `enrolled` as its scope. Built in memory: `loadConfig()` would read the real
 * ~/.aka. No history grant and no body retention, so neither of the other two
 * children a session start can ask for is started.
 */
function configFor(enrolled: readonly string[]): PluginConfig {
  const settings: WorkspaceSettings = {
    ...defaultWorkspaceSettings(),
    runMode: 'attached',
    controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
    attachmentScope: {
      endpoint: ENDPOINT,
      entries: enrolled.map((identity) => ({ kind: 'repo', identity, enrolledAt: AT })),
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

/**
 * An attachment: the credential file on disk, version 2 for a scoped one and
 * version 1 for a machine one, beside the SAME settings, which enroll the work
 * repository. What differs between the two modes is the credential alone.
 */
function attach(mode: 'scoped' | 'machine'): PluginConfig {
  writeControlPlaneCredential(
    settingsDirOf(home),
    mode === 'scoped'
      ? { specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: TEST_KEY, mintedAt: AT }
      : { specVersion: 1, endpoint: ENDPOINT, apiKey: TEST_KEY, mintedAt: AT },
  );
  return configFor([WORK_KEY]);
}

/** One session start in `cwd`, with the hermetic home and no build identity. */
async function start(sessionId: string, cwd: string, config: PluginConfig): Promise<void> {
  await handleSessionStart(
    { sessionId, cwd, tool: SOURCE_TOOL.ClaudeCode, homeDir: userHome },
    config,
  );
}

/**
 * What one session start wrote to the local store: its config scan, then its
 * root. `synced_at` is set only on a row a forward delivered.
 */
function storedRows(sessionId: string) {
  const db = new DatabaseSync(dbPathOf(home));
  try {
    return db
      .prepare(
        `SELECT event_type, scope_key, synced_at FROM audit_events
          WHERE id = :id OR root_session_id = :id
          ORDER BY event_type`,
      )
      .all({ id: sessionId });
  } finally {
    db.close();
  }
}

function otherRoutes(): typeof NO_OTHER_ROUTE {
  return {
    captures: sent.captures.length,
    auditBatches: sent.auditBatches.length,
    egress: sent.egress.length,
  };
}

function childMarkers(): typeof NO_CHILD {
  return {
    historySync: existsSync(join(dataDirOf(home), HISTORY_SYNC_MARKER_NAME)),
    contentRetention: existsSync(join(dataDirOf(home), CONTENT_RETENTION_MARKER_NAME)),
  };
}

// A capture and a finding on it, shaped as the live capture path records them.
function event(overrides: Partial<IngestEvent> = {}): IngestEvent {
  return {
    id: randomUUID(),
    sourceTool: 'claude-code',
    kind: 'prompt',
    occurredAt: new Date().toISOString(),
    contentHash: 'hash',
    content: 'redacted content',
    ...overrides,
  };
}

function finding(eventId: string, overrides: Partial<DetectedFinding> = {}): DetectedFinding {
  return {
    id: randomUUID(),
    eventId,
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    severity: 'critical',
    span: { start: 0, end: 4 },
    maskedMatch: 'AKIA…MPLE',
    actionTaken: 'block',
    confidence: 0.9,
    ...overrides,
  };
}

/** One finding in the work repository and one in the personal one, written locally. */
async function seedFindings(): Promise<void> {
  const local = new StandaloneDataGateway(dataDirOf(home));
  try {
    const inWork = event({ contentHash: 'hash-work' });
    await local.recordCapture({
      event: inWork,
      findings: [finding(inWork.id)],
      scopeKey: WORK_KEY,
    });
    const inPersonal = event({ contentHash: 'hash-personal' });
    await local.recordCapture({
      event: inPersonal,
      findings: [finding(inPersonal.id)],
      scopeKey: PERSONAL_KEY,
    });
  } finally {
    await local.close();
  }
}

describe('handleSessionStart on a scoped credential read from disk', () => {
  it('keeps a personal session local and still reports posture, marked scoped', async () => {
    const config = attach('scoped');
    await start('s-personal', personal, config);

    expect(sent.inventory).toEqual([]);
    // Neither the root (its repository is not enrolled) nor the config scan
    // (never keyed, so never sent on a scoped attachment) reached the client.
    expect(sent.audit).toEqual([]);
    // Posture is the device's liveness report and is never gated on scope. A
    // report at all also shows the factory built the attached gateway: the
    // local one reports nothing.
    expect(sent.posture.map((report) => report.attachmentMode)).toEqual(['scoped']);
    // Both rows are written locally, keyed as recorded, and neither is stamped delivered.
    expect(storedRows('s-personal')).toEqual([
      { event_type: 'config_scan', scope_key: null, synced_at: null },
      { event_type: 'session', scope_key: PERSONAL_KEY, synced_at: null },
    ]);
    expect(policySync.configs).toEqual([config]);
    expect(otherRoutes()).toEqual(NO_OTHER_ROUTE);
    expect(childMarkers()).toEqual(NO_CHILD);
  });

  it("sends an enrolled session's inventory and root, and keeps its config scan local", async () => {
    await start('s-work', work, attach('scoped'));

    expect(sent.inventory.map((context) => context.project?.url)).toEqual([WORK_ORIGIN]);
    expect(sent.audit.map((body) => body.eventType)).toEqual(['session']);
    // The root went out after the inventory, re-keyed to the deployment's ids.
    expect(sent.audit[0]).toMatchObject({ id: 's-work', ...DEPLOYMENT_INVENTORY });
    // The local scope key is in no body. Checked by the member's name, not its
    // value: the inventory's project url contains the key's text.
    expect(JSON.stringify([sent.inventory, sent.audit, sent.posture])).not.toContain('scope_key');
    expect(sent.posture.map((report) => report.attachmentMode)).toEqual(['scoped']);
    // The store keeps the key the wire does not carry. Only the root is stamped delivered.
    expect(storedRows('s-work')).toEqual([
      { event_type: 'config_scan', scope_key: null, synced_at: null },
      { event_type: 'session', scope_key: WORK_KEY, synced_at: expect.any(Number) as number },
    ]);
    expect(policySync.configs).toHaveLength(1);
    expect(otherRoutes()).toEqual(NO_OTHER_ROUTE);
    expect(childMarkers()).toEqual(NO_CHILD);
  });

  it('sends inventory for the work session only, and no config scan, when sessions start in both', async () => {
    // A scoped machine with one enrolled work repository. Sessions start in the
    // work repository and in a personal one.
    const config = attach('scoped');
    await start('s-both-work', work, config);
    await start('s-both-personal', personal, config);

    expect(sent.inventory.map((context) => context.project?.url)).toEqual([WORK_ORIGIN]);
    expect(sent.audit.map((body) => [body.eventType, body.id])).toEqual([
      ['session', 's-both-work'],
    ]);
    // One report for the two: the second session start falls inside the hour.
    expect(sent.posture.map((report) => report.attachmentMode)).toEqual(['scoped']);
    expect(storedRows('s-both-work')).toEqual([
      { event_type: 'config_scan', scope_key: null, synced_at: null },
      { event_type: 'session', scope_key: WORK_KEY, synced_at: expect.any(Number) as number },
    ]);
    expect(storedRows('s-both-personal')).toEqual([
      { event_type: 'config_scan', scope_key: null, synced_at: null },
      { event_type: 'session', scope_key: PERSONAL_KEY, synced_at: null },
    ]);
    expect(policySync.configs).toHaveLength(2);
    expect(otherRoutes()).toEqual(NO_OTHER_ROUTE);
    expect(childMarkers()).toEqual(NO_CHILD);
  });

  it('keeps a session outside any repository local and still reports posture, marked scoped', async () => {
    await start('s-scratch', scratch, attach('scoped'));

    expect(sent.inventory).toEqual([]);
    expect(sent.audit).toEqual([]);
    expect(sent.posture.map((report) => report.attachmentMode)).toEqual(['scoped']);
    // No repository, so no key: the root is stored without one and stays local.
    expect(storedRows('s-scratch')).toEqual([
      { event_type: 'config_scan', scope_key: null, synced_at: null },
      { event_type: 'session', scope_key: null, synced_at: null },
    ]);
    expect(policySync.configs).toHaveLength(1);
    expect(otherRoutes()).toEqual(NO_OTHER_ROUTE);
    expect(childMarkers()).toEqual(NO_CHILD);
  });
});

describe('handleSessionStart on a machine credential, with the same settings', () => {
  it('sends the inventory, root and config scan of a personal session, and posture with no mode', async () => {
    await start('s-machine', personal, attach('machine'));

    expect(sent.inventory.map((context) => context.project?.url)).toEqual([PERSONAL_ORIGIN]);
    expect(sent.audit.map((body) => body.eventType)).toEqual(['session', 'config_scan']);
    // Stripped on a machine attachment too: the root is stamped in every mode.
    expect(JSON.stringify(sent.audit)).not.toContain('scope_key');
    // What a machine attachment reported before the mode existed: no mode
    // member, not even an undefined one, and every other member where it was.
    expect(sent.posture).toHaveLength(1);
    expect(sent.posture[0]).not.toHaveProperty('attachmentMode');
    expect(Object.keys(sent.posture[0] ?? {})).toEqual(MACHINE_POSTURE_KEYS);
    expect(storedRows('s-machine')).toEqual([
      { event_type: 'config_scan', scope_key: null, synced_at: expect.any(Number) as number },
      { event_type: 'session', scope_key: PERSONAL_KEY, synced_at: expect.any(Number) as number },
    ]);
    expect(policySync.configs).toHaveLength(1);
    expect(otherRoutes()).toEqual(NO_OTHER_ROUTE);
    expect(childMarkers()).toEqual(NO_CHILD);
  });
});

describe('the posture report across an unenroll', () => {
  it('still counts every captured finding on the machine, under the same device, after the repository is unenrolled', async () => {
    await seedFindings();
    await start('s-before-unenroll', work, attach('scoped'));

    expect(sent.inventory).toHaveLength(1);
    expect(sent.posture).toHaveLength(1);
    const before = sent.posture[0];
    // The personal repository's finding counts too. The device report counts
    // the captured findings in the whole store, whatever the scope, so a store
    // that lost findings can be told apart from one that only changed what it
    // sends.
    expect(before?.findingsTotal).toBe(2);
    expect(typeof before?.findingsFirstAt).toBe('number');
    expect(typeof before?.findingsLastAt).toBe('number');

    // One report per device per hour. The stamp is moved back through the
    // store's own API, the state an hour passing would leave, rather than by
    // faking the clock, so every other time a session start records stays real.
    const postureStore = createPostureStore(settingsDirOf(home), dataDirOf(home));
    const state = await postureStore.read();
    if (state === null) throw new Error('the session start left no device identity');
    await postureStore.markAttempted(state.deviceId, 0);

    // The unenroll is a settings change: the same credential file, a scope that
    // lists nothing.
    await start('s-after-unenroll', work, configFor([]));

    // It took effect: the same repository's next session sends no inventory and no root.
    expect(sent.inventory).toHaveLength(1);
    expect(sent.audit.map((body) => body.id)).toEqual(['s-before-unenroll']);
    // And the device's report did not move.
    expect(sent.posture).toHaveLength(2);
    const after = sent.posture[1];
    expect(after?.findingsTotal).toBe(2);
    expect(after?.findingsFirstAt).toBe(before?.findingsFirstAt);
    expect(after?.findingsLastAt).toBe(before?.findingsLastAt);
    expect(sent.posture.map((report) => report.deviceId)).toEqual([state.deviceId, state.deviceId]);
    expect(sent.posture.map((report) => report.attachmentMode)).toEqual(['scoped', 'scoped']);
    expect(policySync.configs).toHaveLength(2);
    expect(otherRoutes()).toEqual(NO_OTHER_ROUTE);
    expect(childMarkers()).toEqual(NO_CHILD);
  });
});

describe('the forwarding line a session start returns', () => {
  /** One session start in `cwd`, returning what the adapter would show. */
  async function line(
    sessionId: string,
    cwd: string,
    config: PluginConfig,
  ): Promise<string | null> {
    const result = await handleSessionStart(
      { sessionId, cwd, tool: SOURCE_TOOL.ClaudeCode, homeDir: userHome },
      config,
    );
    return result.forwardingLine;
  }

  it('names the enrolled repository for a work session, and says local-only for the rest, as the root is sent', async () => {
    const config = attach('scoped');

    expect(await line('l-work', work, config)).toBe(`AKA: forwarding to ${ENDPOINT} (${WORK_KEY})`);
    expect(await line('l-personal', personal, config)).toBe(LOCAL_ONLY_LINE);
    expect(await line('l-scratch', scratch, config)).toBe(LOCAL_ONLY_LINE);
    // The line agrees with what the gateway did: only the root it named as
    // forwarding was sent.
    expect(
      sent.audit.filter((body) => body.eventType === 'session').map((body) => body.id),
    ).toEqual(['l-work']);
  });

  it('says everything forwards on a machine credential, in a repository nobody enrolled', async () => {
    expect(await line('l-machine', personal, attach('machine'))).toBe(
      `AKA: forwarding everything to ${ENDPOINT} (machine-wide)`,
    );
    expect(
      sent.audit.filter((body) => body.eventType === 'session').map((body) => body.id),
    ).toEqual(['l-machine']);
  });

  it('says local-only for the same repository once it is unenrolled', async () => {
    attach('scoped');

    expect(await line('l-unenrolled', work, configFor([]))).toBe(LOCAL_ONLY_LINE);
    expect(sent.audit).toEqual([]);
  });

  it('names the attachment by its label, with control characters removed', async () => {
    const config = attach('machine');
    const controlPlane = config.settings.controlPlane;
    if (controlPlane === undefined) throw new Error('the fixture is not attached');
    config.settings.controlPlane = { ...controlPlane, label: 'Acme\u001b[31m prod' };

    expect(await line('l-label', personal, config)).toBe(
      'AKA: forwarding everything to Acme[31m prod (machine-wide)',
    );
  });

  it('shows nothing when the credential is for another deployment, as the gateway forwards nothing', async () => {
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 1,
      endpoint: 'https://elsewhere.example.com',
      apiKey: TEST_KEY,
      mintedAt: AT,
    });

    expect(await line('l-mismatch', work, configFor([WORK_KEY]))).toBeNull();
    expect(sent.audit).toEqual([]);
    expect(sent.posture).toEqual([]);
  });

  it('shows nothing a second time for a session that already started', async () => {
    const config = attach('scoped');

    expect(await line('l-again', work, config)).toBe(
      `AKA: forwarding to ${ENDPOINT} (${WORK_KEY})`,
    );
    expect(await line('l-again', work, config)).toBeNull();
  });
});
