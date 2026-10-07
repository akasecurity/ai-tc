import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { DB_FILENAME, llmCallId, toolCallId } from '@akasecurity/persistence';
import type {
  CaptureRecord,
  CaptureStatusReader,
  DataGateway,
  LocalStoreMaintenance,
  ProjectEgressContext,
} from '@akasecurity/plugin-sdk';
import { bundledDetections, hasLocalStoreMaintenance } from '@akasecurity/plugin-sdk';
import type {
  AuditEventInput,
  ConfigScanRecord,
  DetectionCategory,
  IngestAck,
  IngestBatch,
  IngestEvent,
  InventoryContext,
  LlmCallInput,
  Policy,
  PolicyBundle,
  RecordProjectEgressInput,
  ResolvedAttachmentScope,
  ToolCallInput,
} from '@akasecurity/schema';
import { SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { readForwardDrops } from '../../src/attached/forward-drops.ts';
import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy.ts';
import { createForwardPolicy, FORWARD_STATE_FILENAME } from '../../src/attached/forward-policy.ts';
import type { AttachedClient, AttachedDataGatewayDeps } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';
import type { StoredRootKeyReader } from '../../src/session-root-key.ts';
import { StandaloneDataGateway } from '../../src/standalone-gateway.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// ── the port, as data ───────────────────────────────────────────────────────
// Every DataGateway method. The exhaustiveness check below turns a port that
// grows a 28th method into a COMPILE error here rather than a method the
// composite silently fails to delegate — which is the whole point of listing
// them: this file is the drift guard, so it must not be able to fall behind
// the port quietly.
const PORT_METHODS = [
  'recordCapture',
  'ensureInventory',
  'recordAuditEvent',
  'recordLlmCall',
  'recordLlmCalls',
  'recordToolCalls',
  'recordConfigScan',
  'configInventoryReport',
  'readSessionProvider',
  'facets',
  'getPolicyBundle',
  'consumeException',
  'recordBlockedDetection',
  'recentFindings',
  'healthSummary',
  'activityByDay',
  'tokenReports',
  'knownContentHashes',
  'scanLedger',
  'scanLedgerPaths',
  'scanLedgerPathKeys',
  'recordScanned',
  'getRuleProbeVerdict',
  'setRuleProbeVerdict',
  'openAtRestKeysForPath',
  'resolvedAtRestKeysForPath',
  'insertResolution',
  'recordProjectEgress',
  'close',
] as const;

// If the port gains a method that is not in PORT_METHODS, `Missing` stops being
// `never` and this line fails to compile.
type Missing = Exclude<keyof DataGateway, (typeof PORT_METHODS)[number]>;
// A call rather than a binding: the type argument is checked at compile time
// and nothing is left over to discard.
function pinNever<T extends never>(): T[] {
  return [];
}
pinNever<Missing>();

const MAINTENANCE_METHODS = [
  'sweepTerminalExceptions',
  'capWarnEraEnforcement',
  'recordProjectFiles',
  'reconcileWorktreeProjects',
  'staleBinaryNotice',
  'markCaptureDelivered',
  'markCaptureOwed',
  'markAuditEventsDelivered',
] as const;
type MissingMaintenance = Exclude<
  keyof LocalStoreMaintenance,
  (typeof MAINTENANCE_METHODS)[number]
>;
pinNever<MissingMaintenance>();

// ── fakes ───────────────────────────────────────────────────────────────────

interface Calls {
  order: string[];
  /** Ids handed to `markAuditEventsDelivered`, in the order they were stamped. */
  delivered: string[];
  /** Length of each array handed to `client.recordAuditEvents`, in order. */
  batchSizes: number[];
}

/**
 * A recording stand-in for the inner local gateway. Three of the maintenance
 * members are SYNCHRONOUS on the real port and are synchronous here too — a
 * fake that returned promises for them would hide exactly the bug the composite
 * has to avoid.
 */
function makeLocal(
  calls: Calls,
  overrides: Partial<
    DataGateway & LocalStoreMaintenance & CaptureStatusReader & StoredRootKeyReader
  > = {},
) {
  const base: Record<string, unknown> = {};
  for (const name of PORT_METHODS) {
    base[name] = vi.fn(() => {
      calls.order.push(`local.${name}`);
      // Shapes the composite passes straight through; the delegation test only
      // asserts the call happened and the value came back.
      if (name === 'ensureInventory') return Promise.resolve({});
      if (name === 'knownContentHashes') return Promise.resolve(new Set<string>());
      if (name === 'scanLedger') return Promise.resolve(new Map());
      if (name === 'scanLedgerPaths') return Promise.resolve([]);
      if (name === 'scanLedgerPathKeys') return Promise.resolve(new Map());
      if (name === 'getPolicyBundle')
        return Promise.resolve({
          version: 'local',
          policies: [],
          rules: [],
          customKeywords: [],
          fetchedAt: '2026-01-01T00:00:00.000Z',
        } satisfies PolicyBundle);
      if (name === 'consumeException') return Promise.resolve(true);
      if (name === 'recordProjectEgress')
        return Promise.resolve({
          destinations: 1,
          endpoints: 2,
          callSites: 3,
          truncated: false,
          droppedFiles: [],
        });
      if (name === 'recentFindings' || name === 'activityByDay' || name === 'tokenReports')
        return Promise.resolve([]);
      if (name === 'openAtRestKeysForPath' || name === 'resolvedAtRestKeysForPath')
        return Promise.resolve([]);
      if (name === 'facets')
        return Promise.resolve({ hosts: [], harnesses: [], osVersions: [], projects: [] });
      return Promise.resolve(undefined);
    });
  }
  base.sweepTerminalExceptions = vi.fn(() => {
    calls.order.push('local.sweepTerminalExceptions');
    return Promise.resolve(7);
  });
  base.capWarnEraEnforcement = vi.fn(() => {
    calls.order.push('local.capWarnEraEnforcement');
    return { capped: 3 };
  });
  base.recordProjectFiles = vi.fn(() => {
    calls.order.push('local.recordProjectFiles');
    return Promise.resolve();
  });
  base.reconcileWorktreeProjects = vi.fn(() => {
    calls.order.push('local.reconcileWorktreeProjects');
    return Promise.resolve();
  });
  base.staleBinaryNotice = vi.fn(() => {
    calls.order.push('local.staleBinaryNotice');
    return 'a notice';
  });
  base.markCaptureDelivered = vi.fn(() => {
    calls.order.push('local.markCaptureDelivered');
  });
  base.markCaptureOwed = vi.fn(() => {
    calls.order.push('local.markCaptureOwed');
  });
  base.markAuditEventsDelivered = vi.fn((events: readonly { id: string }[]) => {
    calls.order.push('local.markAuditEventsDelivered');
    for (const event of events) calls.delivered.push(event.id);
  });
  base.readCaptureStatuses = vi.fn(() => {
    calls.order.push('local.readCaptureStatuses');
    return Promise.resolve([]);
  });
  // The session roots this store holds, FIRST-WRITE-WINS as the real store keeps
  // them: the key a root was first recorded with is what the verdict reads back,
  // whatever a later root event for the same id carries.
  const storedRootKeys = new Map<string, string | undefined>();
  const recordAuditEvent = base.recordAuditEvent as (event: AuditEventInput) => Promise<undefined>;
  base.recordAuditEvent = vi.fn((event: AuditEventInput) => {
    if (event.eventType === 'session' && !storedRootKeys.has(event.id)) {
      const key = event.attributes?.scope_key;
      storedRootKeys.set(event.id, typeof key === 'string' ? key : undefined);
    }
    return recordAuditEvent(event);
  });
  base.readSessionScopeKey = vi.fn((sessionId: string) => storedRootKeys.get(sessionId));
  return Object.assign(base, overrides) as unknown as DataGateway &
    LocalStoreMaintenance &
    CaptureStatusReader &
    StoredRootKeyReader;
}

function makeClient(calls: Calls, overrides: Partial<AttachedClient> = {}): AttachedClient {
  return {
    ingestEvents: vi.fn(() => {
      calls.order.push('client.ingestEvents');
      // A COMPLETE ack. `IngestAck` carries both counts and the real client
      // zod-parses the response, so a fake missing `duplicates` is not a
      // lenient fixture — it is a shape the product cannot produce, and it
      // made `accepted + duplicates` NaN in every case that reads the ack.
      return Promise.resolve({ accepted: 1, duplicates: 0 } as never);
    }),
    ingestInventory: vi.fn(() => {
      calls.order.push('client.ingestInventory');
      return Promise.resolve({});
    }),
    recordAuditEvent: vi.fn(() => {
      calls.order.push('client.recordAuditEvent');
      return Promise.resolve();
    }),
    recordAuditEvents: vi.fn((events: readonly unknown[]) => {
      calls.order.push('client.recordAuditEvents');
      calls.batchSizes.push(events.length);
      return Promise.resolve({ accepted: events.length });
    }),
    reportStorePosture: vi.fn(() => {
      calls.order.push('client.reportStorePosture');
      return Promise.resolve({});
    }),
    recordProjectEgress: vi.fn(() => {
      calls.order.push('client.recordProjectEgress');
      return Promise.resolve({ ok: true });
    }),
    ...overrides,
  };
}

/** A forward policy that always runs its op — the "backend is healthy" case. */
function passthroughForward(calls: Calls): ForwardPolicy {
  return {
    run: async <T>(op: () => Promise<T>): Promise<ForwardResult<T>> => {
      calls.order.push('forward.run');
      try {
        return { ok: true, value: await op() };
      } catch {
        return { ok: false, reason: 'unreachable' };
      }
    },
  };
}

/** A forward policy that never calls the network — breaker open, or budget blown. */
function deadForward(calls: Calls): ForwardPolicy {
  return {
    run: vi.fn(() => {
      calls.order.push('forward.skipped');
      // `breaker-open` and not a backend verdict: this fake never asks.
      return Promise.resolve({ ok: false, reason: 'breaker-open' } as const);
    }),
  };
}

// Minimal but COMPLETE fixtures. These suites are about ordering and routing —
// which call happens first, which body reaches the client — so the content is
// incidental; what is not incidental is that they are real shapes, so a change
// to the wire contract shows up here rather than being absorbed by a cast.
const event = (id: string): IngestEvent => ({
  id,
  sourceTool: 'claude-code',
  kind: 'prompt',
  occurredAt: '2026-08-19T10:00:00.000Z',
  contentHash: `hash-${id}`,
  content: `content of ${id}`,
});

const auditEvent = (over: Partial<AuditEventInput> = {}): AuditEventInput => ({
  id: 'a1',
  eventType: 'session',
  startedAt: '2026-08-19T10:00:00.000Z',
  ...over,
});

const egressInput = (): RecordProjectEgressInput => ({
  projectKey: 'example/project',
  project: '/repo',
  projectId: null,
  reconcile: { mode: 'walk', walkedPrefix: '/repo' },
  hits: [],
});

// ── the scope verdict ───────────────────────────────────────────────────────
// Built directly rather than through the factory, so every case names the exact
// mode and key set it runs under. MACHINE is what build() passes by default.
const IN = 'github.com/org/api';
const OUT = 'github.com/me/personal';
const MACHINE: ResolvedAttachmentScope = { mode: 'machine', keys: new Set<string>() };
const SCOPED: ResolvedAttachmentScope = { mode: 'scoped', keys: new Set<string>([IN]) };
/** Freshly attached: scoped, a valid scope, and nothing enrolled in it yet. */
const SCOPED_EMPTY: ResolvedAttachmentScope = { mode: 'scoped', keys: new Set<string>() };

/** A bag carrying `key` as the local scope key, or no bag at all for no key. */
const keyed = (key: string | undefined): Pick<AuditEventInput, 'attributes'> =>
  key === undefined ? {} : { attributes: { scope_key: key } };

const rootRow = (id: string, key: string | undefined): AuditEventInput =>
  auditEvent({ id, ...keyed(key) });

const llmLeaf = (messageId: string, rootId: string, key: string | undefined): LlmCallInput => ({
  sessionId: rootId,
  messageId,
  parentId: rootId,
  rootSessionId: rootId,
  startedAt: '2026-08-19T10:00:01.000Z',
  attributes: { model: 'claude-opus-5', ...(key === undefined ? {} : { scope_key: key }) },
});

const toolLeaf = (toolUseId: string, rootId: string, key: string | undefined): ToolCallInput => ({
  sessionId: rootId,
  toolUseId,
  parentId: rootId,
  rootSessionId: rootId,
  startedAt: '2026-08-19T10:00:02.000Z',
  attributes: {
    tool_name: 'Bash',
    tool_use_id: toolUseId,
    ...(key === undefined ? {} : { scope_key: key }),
  },
  inspections: [],
});

/**
 * An inventory context as the resolver builds it: the harness the session runs
 * under, and its project when its directory sits in a repository. The harness
 * identity is the tool, which is what the verdict reads to tell a web chat
 * session from a coding one.
 */
const projectCtx = (
  url: string | undefined,
  tool: string = SOURCE_TOOL.ClaudeCode,
): InventoryContext => ({
  harness: { objectType: 'harness', identityKey: tool, title: tool, attributes: {} },
  ...(url === undefined ? {} : { project: { url, name: 'repo', attributes: {} } }),
});

const capture = (id: string, key: string | undefined): CaptureRecord => ({
  event: event(id),
  findings: [],
  ...(key === undefined ? {} : { scopeKey: key }),
});

/**
 * A real directory per test, because the gateway now WRITES here: the batch
 * budget records what it discarded, and a shared or absent dir would let one
 * test read another's tally.
 */
let dataDir: string;
beforeEach(() => {
  dataDir = mkdtempSync(join(tmpdir(), 'aka-gateway-'));
});
afterEach(() => {
  removeTree(dataDir);
});

function build(overrides: Partial<AttachedDataGatewayDeps> = {}) {
  const calls: Calls = { order: [], delivered: [], batchSizes: [] };
  const local = overrides.local ?? makeLocal(calls);
  const client = overrides.client ?? makeClient(calls);
  const gateway = new AttachedDataGateway({
    dataDir,
    local,
    client,
    readCachedBundle: overrides.readCachedBundle ?? (() => Promise.resolve(null)),
    forward: overrides.forward ?? passthroughForward(calls),
    attachment: overrides.attachment ?? MACHINE,
    ...(overrides.posture ? { posture: overrides.posture } : {}),
  });
  return { gateway, local, client, calls, dataDir };
}

const policy = (target: Policy['target'], action: Policy['action'], enabled = true): Policy => ({
  id: `${JSON.stringify(target)}-${action}`,
  scope: 'global',
  target,
  action,
  enabled,
});

const bundle = (policies: Policy[], extra: Partial<PolicyBundle> = {}): PolicyBundle => ({
  version: 'v',
  policies,
  rules: [],
  customKeywords: [],
  fetchedAt: '2026-01-01T00:00:00.000Z',
  ...extra,
});

/**
 * A rule as it arrives ON THE WIRE, inside the untrusted tenant bundle. Only
 * `id` and `category` matter to the clamp; the rest is shape.
 */
const wireRule = (id: string, category: DetectionCategory) =>
  ({
    specVersion: 1,
    id,
    name: id,
    category,
    severity: 'critical',
    matcher: { type: 'keyword', keywords: [id] },
  }) as NonNullable<PolicyBundle['rules']>[number];

// ── the drift guard ─────────────────────────────────────────────────────────

describe('the repository a ledgered file was in', () => {
  it('is the answer of the inner local gateway, unchanged', async () => {
    const keys = new Map<string, string | undefined>([['/repo/a.ts', IN]]);
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const { gateway } = build({
      local: makeLocal(calls, { scanLedgerPathKeys: () => Promise.resolve(keys) }),
    });

    expect(await gateway.scanLedgerPathKeys()).toBe(keys);
  });

  it('is an empty answer when the inner gateway cannot say, so no path has a key', async () => {
    // The method is optional on the port, for implementers outside this
    // repository. An inner gateway without it gives every deleted path no key,
    // which a scoped attachment reads as "do not send".
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls);
    Reflect.deleteProperty(local, 'scanLedgerPathKeys');
    const { gateway } = build({ local });

    expect(await gateway.scanLedgerPathKeys()).toEqual(new Map());
  });
});

describe('every DataGateway method delegates to the inner local gateway', () => {
  it.each(PORT_METHODS)('%s', async (name) => {
    const { gateway, local } = build();
    // Called with a single throwaway argument: every port method either ignores
    // extra args or takes one, and the assertion is only that the inner gateway
    // saw the call.
    const methods = gateway as unknown as Record<string, (a?: unknown) => Promise<unknown>>;
    // The two batch methods take an ARRAY and are now chunked, so the throwaway
    // has to be one: a string was tolerated by the old per-item loop only
    // because indexing a string yields characters.
    const arg =
      name === 'recordConfigScan'
        ? { items: [], scanEvent: { id: 'c1', eventType: 'config_scan' } }
        : name === 'recordLlmCalls' || name === 'recordToolCalls'
          ? []
          : 'arg';
    await Reflect.apply(methods[name] as (a?: unknown) => Promise<unknown>, gateway, [arg]);
    expect((local as unknown as Record<string, ReturnType<typeof vi.fn>>)[name]).toHaveBeenCalled();
  });
});

// readCaptureStatuses is on CaptureStatusReader, not DataGateway, so it is
// deliberately outside PORT_METHODS above — a separate, explicit case rather
// than folded into the generic loop.
describe('readCaptureStatuses', () => {
  it('delegates the capture-status read and forwards nothing', async () => {
    const { gateway, local } = build();
    await gateway.readCaptureStatuses();
    expect(
      (local as unknown as Record<string, ReturnType<typeof vi.fn>>).readCaptureStatuses,
    ).toHaveBeenCalled();
  });
});

describe('LocalStoreMaintenance (D3)', () => {
  it('satisfies the structural guard, so SessionStart maintenance actually runs', () => {
    const { gateway } = build();
    expect(hasLocalStoreMaintenance(gateway)).toBe(true);
  });

  it.each(MAINTENANCE_METHODS)('%s delegates', async (name) => {
    const { gateway, local } = build();
    const methods = gateway as unknown as Record<string, (...a: unknown[]) => unknown>;
    const result = Reflect.apply(methods[name] as (...a: unknown[]) => unknown, gateway, [
      'a',
      'b',
      'c',
    ]);
    if (result instanceof Promise) await result;
    expect((local as unknown as Record<string, ReturnType<typeof vi.fn>>)[name]).toHaveBeenCalled();
  });

  // The two synchronous members are the trap: handle-session-start calls
  // capWarnEraEnforcement WITHOUT await and uses staleBinaryNotice's return
  // value directly, so declaring either `async` here hands those call sites a
  // Promise and silently breaks both.
  it('capWarnEraEnforcement returns a value, not a Promise', () => {
    const { gateway } = build();
    const result = gateway.capWarnEraEnforcement('warn');
    expect(result).not.toBeInstanceOf(Promise);
    expect(result).toEqual({ capped: 3 });
  });

  it('staleBinaryNotice returns a value, not a Promise', () => {
    const { gateway } = build();
    const result = gateway.staleBinaryNotice('1.2.3');
    expect(result).not.toBeInstanceOf(Promise);
    expect(result).toBe('a notice');
  });
});

// ── local-first ordering and fail-open ──────────────────────────────────────

describe('writes are local-FIRST, then forwarded', () => {
  it('recordCapture writes locally before it forwards', async () => {
    const { gateway, calls } = build();
    await gateway.recordCapture({ event: event('e1'), findings: [] });
    expect(calls.order.indexOf('local.recordCapture')).toBeLessThan(
      calls.order.indexOf('client.ingestEvents'),
    );
  });

  it('a forward that never runs still returns the local result and does not throw', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const { gateway } = build({ forward: deadForward(calls) });
    await expect(
      gateway.recordCapture({ event: event('e'), findings: [] }),
    ).resolves.toBeUndefined();
  });

  it('stamps the capture delivered ONLY after the forward succeeds', async () => {
    // The queue is the local store: `synced_at` set means the organization's
    // copy was made, NULL means it is still owed. The stamp is what closes a
    // row, so it has to be ordered strictly after the forward reports success —
    // stamping before would mark a row delivered that a timeout was about to
    // lose.
    const { gateway, calls } = build();
    await gateway.recordCapture({ event: event('e1'), findings: [] });
    expect(calls.order.indexOf('forward.run')).toBeLessThan(
      calls.order.indexOf('local.markCaptureDelivered'),
    );
  });

  it('leaves an undelivered capture unstamped, which is what queues it', async () => {
    // The whole of the outbox, and the case that would silently lose events if
    // it regressed: a breaker-open forward never reached the backend, so the
    // row must stay outstanding for a later drain. A stamp here would mark it
    // delivered and it would never be sent again.
    // Two tapes, because the forward fake is built before `build()` makes its
    // own: `forwardCalls` is the fake's, `calls` is the LOCAL fake's, and the
    // stamp would show up on the second. Both are asserted for the reason the
    // {0,0} case below spells out — a stamp that is missing because nothing was
    // forwarded proves nothing, so the forward is pinned as having been reached.
    const forwardCalls: Calls = { order: [], delivered: [], batchSizes: [] };
    const { gateway, calls } = build({ forward: deadForward(forwardCalls) });
    await gateway.recordCapture({ event: event('e1'), findings: [] });
    expect(forwardCalls.order).toContain('forward.skipped');
    expect(calls.order).toContain('local.recordCapture');
    expect(calls.order).not.toContain('local.markCaptureDelivered');
    // THE POSITIVE HALF, and the one that makes the absence above mean
    // something. Not stamping is only half of queueing a row — the other half is
    // MARKING it owed, and that single line is the entire write side of the
    // outbox. Without this assertion it can be deleted with the whole suite
    // green: nothing would be marked, pendingCaptureRows would return [] for
    // ever, capturesPending would read false, and status would report a machine
    // that owes prompts as caught up.
    expect(calls.order).toContain('local.markCaptureOwed');
  });

  it('stamps a capture the plane already had, reported as a duplicate', async () => {
    // A duplicate is the receiver's id-dedup recognising a resend, which means
    // the plane HAS the row. Treating it as undelivered would leave the capture
    // outstanding for ever, resent on every pass and deduped every time.
    const { gateway, calls } = build({
      client: makeClient(
        { order: [], delivered: [], batchSizes: [] },
        {
          ingestEvents: vi.fn(() => Promise.resolve({ accepted: 0, duplicates: 1 })),
        },
      ),
    });
    await gateway.recordCapture({ event: event('e1'), findings: [] });
    expect(calls.order).toContain('local.markCaptureDelivered');
    // ...and NOT owed. The two are exclusive: a delivered row that also carried
    // the marker would be re-offered by every later drain, and the receiver's
    // id-dedup would absorb it silently for ever.
    expect(calls.order).not.toContain('local.markCaptureOwed');
  });

  it('does NOT stamp a 200 that accepted nothing', async () => {
    // `ok` says the call completed and parsed, not that the plane took the
    // event. An ack of {0,0} took nothing, and stamping on it is the one
    // failure mode on this path that loses a row instead of resending it —
    // the direction the whole "queued is what is owed" invariant rests on.
    const { gateway, calls } = build({
      client: makeClient(
        { order: [], delivered: [], batchSizes: [] },
        {
          ingestEvents: vi.fn(() => Promise.resolve({ accepted: 0, duplicates: 0 })),
        },
      ),
    });
    await gateway.recordCapture({ event: event('e1'), findings: [] });
    // A 200 that took nothing is a non-delivery like any other, so the row is
    // owed rather than merely unstamped.
    expect(calls.order).toContain('local.markCaptureOwed');
    // Both assertions below are satisfied by a run that never forwarded at all
    // — `recordCapture` comes first regardless, and the stamp is an ABSENCE. So
    // the forward is pinned as having happened, or this case cannot tell
    // "declined to stamp a {0,0}" from "nothing was sent", which is exactly the
    // reading that would keep it green with the guard gone.
    expect(calls.order).toContain('forward.run');
    expect(calls.order).toContain('local.recordCapture');
    expect(calls.order).not.toContain('local.markCaptureDelivered');
  });

  it('a forward that REJECTS is contained — the local write still stands', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const client = makeClient(calls, {
      ingestEvents: vi.fn(() => Promise.reject(new Error('backend down'))),
    });
    const { gateway, local } = build({ client, forward: passthroughForward(calls) });
    await expect(
      gateway.recordCapture({ event: event('e'), findings: [] }),
    ).resolves.toBeUndefined();
    expect(
      (local as unknown as Record<string, ReturnType<typeof vi.fn>>).recordCapture,
    ).toHaveBeenCalled();
  });

  it('recordProjectEgress writes locally, then attempts a forward', async () => {
    const { gateway, calls } = build();
    const summary = await gateway.recordProjectEgress(egressInput());
    expect(calls.order.indexOf('local.recordProjectEgress')).toBeLessThan(
      calls.order.indexOf('client.recordProjectEgress'),
    );
    // The inner gateway's real summary is returned, not a zeroed stand-in: the
    // scanner reads a throw as a failed write and skips its ledger commit.
    expect(summary).toEqual({
      destinations: 1,
      endpoints: 2,
      callSites: 3,
      truncated: false,
      droppedFiles: [],
    });
  });

  it('recordProjectEgress forward failure still returns the LOCAL summary and does not throw', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const client = makeClient(calls, {
      recordProjectEgress: vi.fn(() => Promise.reject(new Error('backend down'))),
    });
    const { gateway } = build({ client, forward: passthroughForward(calls) });
    await expect(gateway.recordProjectEgress(egressInput())).resolves.toEqual({
      destinations: 1,
      endpoints: 2,
      callSites: 3,
      truncated: false,
      droppedFiles: [],
    });
    expect(calls.order).toContain('forward.run');
  });
});

// ── the scope key stays on this machine ─────────────────────────────────────

describe('the scope key is a local-only carrier', () => {
  const KEY = 'github.com/acme/widgets';
  const ack = (): Promise<IngestAck> => Promise.resolve({ accepted: 1, duplicates: 0 });

  it('reaches the local write with the record, and is absent from the ingestEvents body', async () => {
    // A GUARD rather than a red test: the gateway already hands `record` to the
    // local write whole and sends only `record.event`. What it pins is that both
    // stay true now that the record carries something the event must not.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const recordCapture = vi.fn<(record: CaptureRecord) => Promise<void>>(() => Promise.resolve());
    const ingestEvents = vi.fn<(batch: IngestBatch) => Promise<IngestAck>>(ack);
    const { gateway } = build({
      local: makeLocal(calls, { recordCapture }),
      client: makeClient(calls, { ingestEvents }),
    });

    await gateway.recordCapture({ event: event('e1'), findings: [], scopeKey: KEY });

    expect(recordCapture.mock.calls[0]?.[0].scopeKey).toBe(KEY);
    // The absence first, so a body that gained the key fails on the line that
    // names it; the whole-body comparison then pins that nothing else changed.
    expect(JSON.stringify(ingestEvents.mock.calls[0]?.[0])).not.toContain(KEY);
    expect(ingestEvents.mock.calls[0]?.[0]).toEqual({ events: [event('e1')] });
  });

  it('lands on the real row while the forwarded body is byte-identical to a keyless capture', async () => {
    migratedStore.seed(dataDir);
    const local = new StandaloneDataGateway(dataDir);
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const ingestEvents = vi.fn<(batch: IngestBatch) => Promise<IngestAck>>(ack);
    const { gateway } = build({ local, client: makeClient(calls, { ingestEvents }) });

    await gateway.recordCapture({ event: event('keyed'), findings: [], scopeKey: KEY });
    await gateway.recordCapture({ event: event('keyless'), findings: [] });
    await local.close();

    const raw = new DatabaseSync(join(dataDir, DB_FILENAME));
    const rows = raw
      .prepare(
        "SELECT content_hash, scope_key FROM audit_events WHERE event_type = 'prompt' ORDER BY content_hash",
      )
      .all() as { content_hash: string; scope_key: string | null }[];
    raw.close();
    expect(rows).toEqual([
      { content_hash: 'hash-keyed', scope_key: KEY },
      { content_hash: 'hash-keyless', scope_key: null },
    ]);

    // The keyed capture's body is exactly the body of the same event captured
    // with no key at all: the key changed what this machine stored and nothing
    // about what it sent.
    const keyedBody = JSON.stringify(ingestEvents.mock.calls[0]?.[0]);
    expect(keyedBody).toBe(JSON.stringify({ events: [event('keyed')] }));
    expect(keyedBody).not.toContain(KEY);
  });
});

describe('consumeException is a fail-secure boundary', () => {
  it('delegates the answer unmodified', async () => {
    const { gateway } = build();
    await expect(gateway.consumeException('x')).resolves.toBe(true);
  });

  it('does NOT convert a local rejection into a granted bypass', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      consumeException: vi.fn(() => Promise.reject(new Error('store unreadable'))),
    });
    const { gateway } = build({ local });
    // It must reject rather than resolve true. Swallowing this into `true`
    // would turn a store error into a silent enforcement bypass.
    await expect(gateway.consumeException('x')).rejects.toThrow('store unreadable');
  });
});

// ── the id spaces ───────────────────────────────────────────────────────────

describe('ensureInventory and the two id spaces', () => {
  it('returns the LOCAL resolution, not the backend one', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      ensureInventory: vi.fn(() => Promise.resolve({ hostId: 'local-host' })),
    });
    const client = makeClient(calls, {
      ingestInventory: vi.fn(() => Promise.resolve({ hostId: 'tenant-host' })),
    });
    const { gateway } = build({ local, client });
    await expect(gateway.ensureInventory({})).resolves.toEqual({ hostId: 'local-host' });
  });

  it('re-keys a forwarded audit event into the BACKEND id space', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      ensureInventory: vi.fn(() => Promise.resolve({ hostId: 'local-host' })),
    });
    const recordAuditEvent = vi.fn<(event: AuditEventInput) => Promise<void>>(() =>
      Promise.resolve(),
    );
    const client = makeClient(calls, {
      ingestInventory: vi.fn(() => Promise.resolve({ hostId: 'tenant-host' })),
      recordAuditEvent,
    });
    const { gateway } = build({ local, client });
    await gateway.ensureInventory({});
    await gateway.recordAuditEvent(auditEvent({ id: 'root', hostId: 'local-host' }));

    // The forwarded copy must reference the tenant's inventory row, or it is
    // orphaned against an inventory the backend never minted.
    expect(recordAuditEvent.mock.calls[0]?.[0]).toMatchObject({ hostId: 'tenant-host' });
  });

  it('forwards nothing at all when the breaker is open', async () => {
    // deadForward skips the network entirely, so there is nothing on the wire to
    // assert about — the point is only that the local write still ran and
    // nothing threw. The id-space cases below use a LIVE forward with a failing
    // inventory call, which is the state that actually reaches the wire.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const recordAuditEvent = vi.fn<(event: AuditEventInput) => Promise<void>>(() =>
      Promise.resolve(),
    );
    const client = makeClient(calls, { recordAuditEvent });
    const { gateway } = build({ client, forward: deadForward(calls) });
    await gateway.ensureInventory({});
    await gateway.recordAuditEvent(auditEvent({ id: 'r', hostId: 'local-host' }));
    expect(recordAuditEvent).not.toHaveBeenCalled();
  });

  it('DROPS local inventory ids when the backend resolved none', async () => {
    // The two sides content-address differently — the device hashes
    // ['inventory', …], the backend hashes [tenantId, 'inventory', …] — so a
    // local id in a tenant FK column references a row that cannot exist. The
    // insert is rejected, forward.run swallows it, and the session root plus
    // every descendant silently never reaches the tenant copy. Omitting the
    // field costs one degraded join instead.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const recordAuditEvent = vi.fn<(event: AuditEventInput) => Promise<void>>(() =>
      Promise.resolve(),
    );
    const client = makeClient(calls, {
      ingestInventory: vi.fn(() => Promise.reject(new Error('backend down'))),
      recordAuditEvent,
    });
    const { gateway } = build({ client });
    await gateway.ensureInventory({});
    await gateway.recordAuditEvent(
      auditEvent({
        id: 'r',
        hostId: 'local-host',
        harnessId: 'local-harness',
        sourceProjectId: 'local-project',
      }),
    );

    const forwarded = recordAuditEvent.mock.calls[0]?.[0];
    expect(forwarded).toBeDefined();
    expect(forwarded).not.toHaveProperty('hostId');
    expect(forwarded).not.toHaveProperty('harnessId');
    expect(forwarded).not.toHaveProperty('sourceProjectId');
    // Everything that is not an inventory id still goes.
    expect(forwarded).toMatchObject({ id: 'r', eventType: 'session' });
  });

  it("a failed inventory forward CLEARS the previous session's resolution", async () => {
    // One gateway instance serves many sessions (reconcileHistory walks them in
    // a loop). Keeping session A's resolution when session B's forward fails
    // would stamp B's events with A's host/harness/project — an insert that
    // SUCCEEDS while attributing a whole session to the wrong repository, which
    // is worse than not forwarding it.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const recordAuditEvent = vi.fn<(event: AuditEventInput) => Promise<void>>(() =>
      Promise.resolve(),
    );
    let call = 0;
    const client = makeClient(calls, {
      ingestInventory: vi.fn(() => {
        call += 1;
        return call === 1
          ? Promise.resolve({ hostId: 'tenant-host-A', sourceProjectId: 'tenant-project-A' })
          : Promise.reject(new Error('backend down'));
      }),
      recordAuditEvent,
    });
    const { gateway } = build({ client });

    await gateway.ensureInventory({}); // session A — resolves
    await gateway.ensureInventory({}); // session B — fails
    await gateway.recordAuditEvent(auditEvent({ id: 'b-root', hostId: 'local-host-B' }));

    const forwarded = recordAuditEvent.mock.calls[0]?.[0];
    expect(forwarded).toBeDefined();
    // Session A's ids must not appear on session B's event.
    expect(forwarded).not.toHaveProperty('hostId');
    expect(forwarded).not.toHaveProperty('sourceProjectId');
    expect(JSON.stringify(forwarded)).not.toContain('tenant-host-A');
    expect(JSON.stringify(forwarded)).not.toContain('tenant-project-A');
  });
});

// ── the policy merge ────────────────────────────────────────────────────────

/** A minimal ToolCallInput; only its identity has to vary per item. */
const toolCallInput = (id: string): ToolCallInput => ({
  sessionId: 's',
  toolUseId: id,
  parentId: 'p',
  rootSessionId: 'r',
  startedAt: '2026-01-01T00:00:00.000Z',
  attributes: { tool_name: 'Bash', tool_use_id: id },
  inspections: [],
});

/** A minimal LlmCallInput; only its identity has to vary per item. */
const llmCallInput = (id: string): LlmCallInput => ({
  sessionId: 's',
  messageId: id,
  parentId: 'p',
  rootSessionId: 'r',
  startedAt: '2026-01-01T00:00:00.000Z',
  attributes: { model: 'claude-opus-5', provider: 'anthropic' },
});

describe('the batch budget records what it discards', () => {
  /**
   * There was no coverage of the batch deadline at all, and the shape it guards
   * is the one that hides best: a plane that answers every request SUCCESSFULLY
   * but slowly produces no failures, so the breaker never opens and every other
   * line of `aka status` reads healthy while the tail of each batch is thrown
   * away. Without the tally this asserts, that machine is indistinguishable from
   * a working one.
   */
  it('drops the tail of a slow batch and writes down how many', async () => {
    let clock = 1_000;
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        // Every call SUCCEEDS, and each one costs 600ms of the budget. That is
        // the case the breaker cannot see: it only counts failures.
        clock += 600;
        return { ok: true, value: await op() } as ForwardResult<unknown>;
      },
    } as unknown as ForwardPolicy;

    const seen: unknown[] = [];
    const client = {
      ...makeClient({ order: [], delivered: [], batchSizes: [] }),
      recordAuditEvents: vi.fn((events: readonly unknown[]) => {
        seen.push(...events);
        return Promise.resolve({ accepted: events.length });
      }),
    } as unknown as AttachedClient;

    const nowSpy = vi.spyOn(Date, 'now').mockImplementation(() => clock);
    try {
      const { gateway } = build({ client, forward });
      // 600 tool calls is 12 chunks at 600ms each — 7.2s against a 3s budget.
      // It took 40 to blow the same budget before chunking, which is the whole
      // point of the change and the reason this number moved.
      await gateway.recordToolCalls(
        Array.from({ length: 600 }, (_, i) => toolCallInput(`call-${String(i)}`)),
      );
    } finally {
      nowSpy.mockRestore();
    }

    // Some were forwarded and some were not — the positive control on both
    // sides. An assertion on the tally alone passes if NOTHING was forwarded,
    // which is a different bug wearing the same number.
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.length).toBeLessThan(600);

    const drops = readForwardDrops(dataDir);
    expect(drops?.droppedForwards).toBe(600 - seen.length);
  });

  it('clears in ONE request what used to take forty, so the budget is not reached', async () => {
    // The regression guard for the fix itself. At 600ms a request, forty events
    // cost 24s per-item and blew a 3s budget; as one chunk they cost 600ms and
    // do not. If this ever drops anything again, the chunking has come undone.
    let clock = 1_000;
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        clock += 600;
        return { ok: true, value: await op() } as ForwardResult<unknown>;
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const nowSpy = vi.spyOn(Date, 'now').mockImplementation(() => clock);
    try {
      const { gateway, dataDir: dir } = build({ forward, local: makeLocal(calls) });
      await gateway.recordToolCalls(
        Array.from({ length: 40 }, (_, i) => toolCallInput(`call-${String(i)}`)),
      );
      expect(readForwardDrops(dir)).toBeNull();
    } finally {
      nowSpy.mockRestore();
    }
    expect(calls.delivered).toHaveLength(40);
  });

  it('never hands the client more than the wire cap', async () => {
    // AUDIT_EVENT_BATCH_MAX is not a convention here: the client REFUSES a
    // longer array client-side, so a chunk that grew past it would fail every
    // send with `invalid-request` rather than overflow anything.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const { gateway } = build({ client: makeClient(calls), local: makeLocal(calls) });
    await gateway.recordToolCalls(
      Array.from({ length: 125 }, (_, i) => toolCallInput(`call-${String(i)}`)),
    );
    expect(calls.batchSizes).toEqual([50, 50, 25]);
    expect(calls.delivered).toHaveLength(125);
  });

  it('writes nothing when the whole batch fits', async () => {
    // The other half: a tally that appears on a healthy run would make the
    // status row permanent noise and the assertion above meaningless.
    const { gateway, dataDir: dir } = build();
    await gateway.recordToolCalls([toolCallInput('only-one')]);
    expect(readForwardDrops(dir)).toBeNull();
  });
});

describe('the live forward stamps what it delivered', () => {
  it('stamps only the CHUNKS that succeeded within a mixed batch', async () => {
    // The per-chunk half of the rule. Settlement is batch-atomic — the receiver
    // wraps a chunk in one transaction — so the unit that succeeds or fails is
    // the chunk, and this alternates them. Delete the `if (forwarded.ok)` and
    // push unconditionally and this fails; that guard is what it pins.
    let call = 0;
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        call += 1;
        if (call % 2 === 1) {
          return { ok: true, value: await op() } as ForwardResult<unknown>;
        }
        return { ok: false, reason: 'unreachable' } as ForwardResult<unknown>;
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const { gateway } = build({ forward, client: makeClient(calls), local: makeLocal(calls) });
    // Three chunks: 50 land, 50 do not, 20 land.
    await gateway.recordToolCalls(
      Array.from({ length: 120 }, (_, i) => toolCallInput(`call-${String(i)}`)),
    );

    expect(calls.delivered).toEqual([
      ...Array.from({ length: 50 }, (_, i) => toolCallId('s', `call-${String(i)}`)),
      ...Array.from({ length: 20 }, (_, i) => toolCallId('s', `call-${String(i + 100)}`)),
    ]);
  });

  it('re-sends a chunk the CLIENT refused one at a time, so one bad event costs only itself', async () => {
    // The regression this fix could have introduced. `invalid-request` means the
    // client refused the body before any request went out, so batching would
    // otherwise charge 49 good events for one malformed neighbour — a new way to
    // lose data, added by the change meant to stop losing it.
    const bad = toolCallId('s', 'call-7');
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        try {
          const value = await op();
          return { ok: true, value } as ForwardResult<unknown>;
        } catch {
          return { ok: false, reason: 'invalid-request' } as ForwardResult<unknown>;
        }
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const client = {
      ...makeClient(calls),
      // Refuses any array containing the bad event — the client-side validation
      // shape, which rejects the whole body rather than one member.
      recordAuditEvents: vi.fn((events: readonly { id: string }[]) =>
        events.some((e) => e.id === bad)
          ? Promise.reject(new Error('invalid'))
          : Promise.resolve({ accepted: events.length }),
      ),
      recordAuditEvent: vi.fn((e: { id: string }) =>
        e.id === bad ? Promise.reject(new Error('invalid')) : Promise.resolve(),
      ),
    } as unknown as AttachedClient;

    const { gateway } = build({ forward, client, local: makeLocal(calls) });
    await gateway.recordToolCalls(
      Array.from({ length: 10 }, (_, i) => toolCallInput(`call-${String(i)}`)),
    );

    // Nine delivered, and exactly the bad one lost — not the whole chunk.
    expect(calls.delivered).toHaveLength(9);
    expect(calls.delivered).not.toContain(bad);
  });

  it('re-sends singly against a deployment that PREDATES the batch route', async () => {
    // The compatibility path, and the reason it lives in this loop rather than
    // inside the client. The client's own fallback would spend 50 sequential
    // round trips inside the ONE FORWARD_BUDGET_MS wrapping this call, so an
    // older deployment answering every single-event request would time out,
    // trip the breaker after three chunks, and deliver NOTHING — strictly worse
    // than the per-item code this PR replaced. Through this loop each single
    // gets its own budget, which is what that code already had.
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        try {
          return { ok: true, value: await op() } as ForwardResult<unknown>;
        } catch (err) {
          // Classified by NAME and before any breaker write, exactly as the
          // real policy classifies it.
          const reason =
            (err as { name?: string }).name === 'RemoteRouteAbsent'
              ? 'route-absent'
              : 'unreachable';
          return { ok: false, reason } as ForwardResult<unknown>;
        }
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const singles: string[] = [];
    const client = {
      ...makeClient(calls),
      // The older deployment: it does not have the route at all.
      recordAuditEvents: vi.fn(() =>
        Promise.reject(Object.assign(new Error('absent'), { name: 'RemoteRouteAbsent' })),
      ),
      recordAuditEvent: vi.fn((e: { id: string }) => {
        singles.push(e.id);
        return Promise.resolve();
      }),
    } as unknown as AttachedClient;

    const { gateway } = build({ forward, client, local: makeLocal(calls) });
    await gateway.recordToolCalls(
      Array.from({ length: 10 }, (_, i) => toolCallInput(`call-${String(i)}`)),
    );

    // Every row landed, over the route the deployment does serve, and every one
    // of them is stamped — not left reading as owed.
    expect(singles).toHaveLength(10);
    expect(calls.delivered).toHaveLength(10);
  });

  it('recovers a chunk the deployment ACCEPTED FEWER of than it was sent', async () => {
    // The batch ack is an aggregate count, not delivery: `ok: true` with
    // `accepted` short of `chunk.length` is a well-formed answer the wire
    // contract permits. Trusting `ok` alone would stamp all ten as delivered
    // and never re-offer the ones the plane silently dropped.
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) =>
        ({ ok: true, value: await op() }) as ForwardResult<unknown>,
    } as unknown as ForwardPolicy;

    const singles: string[] = [];
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const client = {
      ...makeClient(calls),
      // Claims only 7 of the 10 sent — which seven is not knowable from the
      // ack, so recovery has to re-send all ten.
      recordAuditEvents: vi.fn((events: readonly unknown[]) =>
        Promise.resolve({ accepted: 7 }).then((ack) => {
          calls.batchSizes.push(events.length);
          return ack;
        }),
      ),
      recordAuditEvent: vi.fn((e: { id: string }) => {
        singles.push(e.id);
        return Promise.resolve();
      }),
    } as unknown as AttachedClient;

    const { gateway } = build({ forward, client, local: makeLocal(calls) });
    await gateway.recordToolCalls(
      Array.from({ length: 10 }, (_, i) => toolCallInput(`call-${String(i)}`)),
    );

    // The batch attempt happened once, then every row was recovered singly —
    // safe because a re-send of a row that DID land is a no-op on the receiver.
    expect(calls.batchSizes).toEqual([10]);
    expect(singles).toHaveLength(10);
    expect(calls.delivered).toHaveLength(10);
  });

  it('re-sends singly against a deployment that REJECTS the batch body', async () => {
    // The server-side twin of the CLIENT-refused case above: the deployment
    // answered with a 4xx it considers a body-shape problem, not an outage.
    // Isolating it the same way costs one event instead of the whole chunk.
    const bad = toolCallId('s', 'call-3');
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        try {
          return { ok: true, value: await op() } as ForwardResult<unknown>;
        } catch {
          return { ok: false, reason: 'rejected' } as ForwardResult<unknown>;
        }
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const client = {
      ...makeClient(calls),
      recordAuditEvents: vi.fn((events: readonly { id: string }[]) =>
        events.some((e) => e.id === bad)
          ? Promise.reject(Object.assign(new Error('unprocessable'), { status: 422 }))
          : Promise.resolve({ accepted: events.length }),
      ),
      recordAuditEvent: vi.fn((e: { id: string }) =>
        e.id === bad
          ? Promise.reject(Object.assign(new Error('unprocessable'), { status: 422 }))
          : Promise.resolve(),
      ),
    } as unknown as AttachedClient;

    const { gateway } = build({ forward, client, local: makeLocal(calls) });
    await gateway.recordToolCalls(
      Array.from({ length: 10 }, (_, i) => toolCallInput(`call-${String(i)}`)),
    );

    expect(calls.delivered).toHaveLength(9);
    expect(calls.delivered).not.toContain(bad);
  });

  it('does NOT retry a 429 singly — a rate limit is not a body rejection', async () => {
    // The regression this fix could have introduced in the other direction.
    // 429 does not classify as `rejected` (forward-policy.ts's own boundary),
    // so this fake mirrors that: a chunk refused with a 429 status comes back
    // `unreachable`, which is NOT one of the three reasons this loop retries
    // per item. Retrying it here would fire up to 50 more requests at the
    // same already-rate-limited endpoint with no pacing between them — the
    // exact burst `forwardBatch`'s own docblock says staying serial exists to
    // avoid.
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        try {
          return { ok: true, value: await op() } as ForwardResult<unknown>;
        } catch {
          // What the real policy now returns for a 429 — never `rejected`.
          return { ok: false, reason: 'unreachable' } as ForwardResult<unknown>;
        }
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const recordAuditEvent = vi.fn<(event: AuditEventInput) => Promise<void>>(() =>
      Promise.resolve(),
    );
    const client = {
      ...makeClient(calls),
      recordAuditEvents: vi.fn(() =>
        Promise.reject(Object.assign(new Error('too many requests'), { status: 429 })),
      ),
      recordAuditEvent,
    } as unknown as AttachedClient;

    const { gateway } = build({ forward, client, local: makeLocal(calls) });
    await gateway.recordToolCalls(
      Array.from({ length: 50 }, (_, i) => toolCallInput(`call-${String(i)}`)),
    );

    // The whole chunk stays pending — no per-item burst, nothing delivered.
    expect(recordAuditEvent).not.toHaveBeenCalled();
    expect(calls.delivered).toHaveLength(0);
  });

  it('counts a single that fails INSIDE the retry, not just the ones never attempted', async () => {
    // The gap beside the deadline tally: a single that fails within the
    // per-item pass is neither in `delivered` nor caught by the deadline
    // check, so without its own accounting it is simply invisible — the same
    // failure mode the deadline tally exists to prevent, with a different
    // cause. This one is NOT breaker-open, so the loop must keep going: the
    // rest of the chunk still deserves its own attempt.
    const bad = toolCallId('s', 'call-4');
    // The batch attempt's rejection must classify as `invalid-request` (to
    // enter the retry) while the one failed SINGLE classifies as `unreachable`
    // (to prove it does NOT stop the loop) — distinguished by the error's name,
    // exactly as the real policy distinguishes them.
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        try {
          return { ok: true, value: await op() } as ForwardResult<unknown>;
        } catch (err) {
          const reason =
            (err as { name?: string }).name === 'RemoteRequestInvalid'
              ? 'invalid-request'
              : 'unreachable';
          return { ok: false, reason } as ForwardResult<unknown>;
        }
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const client = {
      ...makeClient(calls),
      recordAuditEvents: vi.fn(() =>
        Promise.reject(Object.assign(new Error('invalid'), { name: 'RemoteRequestInvalid' })),
      ),
      recordAuditEvent: vi.fn((e: { id: string }) =>
        e.id === bad ? Promise.reject(new Error('down')) : Promise.resolve(),
      ),
    } as unknown as AttachedClient;

    const { gateway, dataDir: dir } = build({ forward, client, local: makeLocal(calls) });
    await gateway.recordToolCalls(
      Array.from({ length: 10 }, (_, i) => toolCallInput(`call-${String(i)}`)),
    );

    // Nine delivered — the loop did not stop at the failed one.
    expect(calls.delivered).toHaveLength(9);
    expect(calls.delivered).not.toContain(bad);
    const drops = readForwardDrops(dir);
    expect(drops?.droppedForwards).toBe(1);
  });

  it('stops the WHOLE PASS — not just this chunk — and counts every chunk still owed, the moment the breaker opens mid-retry', async () => {
    // TWO chunks, deliberately: with only one, `break` and `return` behave
    // identically, because there is no next chunk for the bug to hide in.
    // Once a single comes back breaker-open here, every remaining `run()`
    // call — this chunk's own remainder AND every later chunk's batch
    // attempt — would answer breaker-open identically at zero network cost.
    // `breaker-open` is not one of the three reasons the outer gate retries
    // per item, so a chunk that reaches it via `continue` records NOTHING —
    // which is what a `break` here used to leave the SECOND chunk to. The
    // fix counts the full remainder, across every chunk still owed, and
    // returns from the whole pass rather than merely breaking this loop.
    let callCount = 0;
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        callCount += 1;
        if (callCount === 1) {
          // Chunk 1's own batch attempt: refused, triggering the retry.
          return { ok: false, reason: 'invalid-request' } as ForwardResult<unknown>;
        }
        if (callCount <= 4) {
          // Three singles succeed, THEN the breaker opens on the fourth.
          return { ok: true, value: await op() } as ForwardResult<unknown>;
        }
        // Everything from here on, including chunk 2's own batch attempt if
        // it were ever reached, answers breaker-open at zero network cost.
        return { ok: false, reason: 'breaker-open' } as ForwardResult<unknown>;
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const singles: string[] = [];
    const client = {
      ...makeClient(calls),
      recordAuditEvents: vi.fn(() =>
        Promise.reject(Object.assign(new Error('invalid'), { name: 'RemoteRequestInvalid' })),
      ),
      recordAuditEvent: vi.fn((e: { id: string }) => {
        singles.push(e.id);
        return Promise.resolve();
      }),
    } as unknown as AttachedClient;

    const { gateway, dataDir: dir } = build({ forward, client, local: makeLocal(calls) });
    // 100 events is two chunks of 50. Chunk 1's batch is refused; three
    // singles land, the fourth opens the breaker. Chunk 2 must never even be
    // ATTEMPTED — the whole pass stops here.
    await gateway.recordToolCalls(
      Array.from({ length: 100 }, (_, i) => toolCallInput(`call-${String(i)}`)),
    );

    // Exactly three singles reached the client and succeeded — the fourth
    // call answers breaker-open without calling `op()` at all, so this is
    // the value, not merely a bound on it.
    expect(singles).toHaveLength(3);
    expect(calls.delivered).toHaveLength(3);
    // The client was never asked for chunk 2's batch: only the five calls
    // chunk 1 itself made (one batch + four singles) ever happened.
    expect(callCount).toBe(5);
    const drops = readForwardDrops(dir);
    // 97, not 47: the remainder covers BOTH chunk 1's own un-retried tail
    // and the whole of chunk 2, which a `break` would have abandoned to the
    // outer loop's silent `continue`.
    expect(drops?.droppedForwards).toBe(97);
    expect(calls.delivered.length + (drops?.droppedForwards ?? 0)).toBe(100);
  });

  it('counts the events a chunk never reached when the deadline lands mid-retry', async () => {
    // The tally is keyed to the OUTER loop's index. A `break` out of the retry
    // returns to that loop, advances past this whole chunk, and counts the
    // remainder from the NEXT boundary — so everything this chunk still had goes
    // uncounted, on exactly the machine the tally exists for. The invariant is
    // arithmetic and the docblock puts it in capitals: what is dropped is
    // counted, so delivered + dropped is the batch.
    let clock = 1_000;
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        try {
          const value = await op();
          // Only a SINGLE costs budget: the batch attempt rejects before this.
          clock += 600;
          return { ok: true, value } as ForwardResult<unknown>;
        } catch (err) {
          const reason =
            (err as { name?: string }).name === 'RemoteRouteAbsent'
              ? 'route-absent'
              : 'unreachable';
          return { ok: false, reason } as ForwardResult<unknown>;
        }
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const client = {
      ...makeClient(calls),
      recordAuditEvents: vi.fn(() =>
        Promise.reject(Object.assign(new Error('absent'), { name: 'RemoteRouteAbsent' })),
      ),
      recordAuditEvent: vi.fn(() => Promise.resolve()),
    } as unknown as AttachedClient;

    const nowSpy = vi.spyOn(Date, 'now').mockImplementation(() => clock);
    let dir: string;
    try {
      const built = build({ forward, client, local: makeLocal(calls) });
      dir = built.dataDir;
      // 100 events is two chunks. The first 404s, then five singles at 600ms
      // each exhaust the 3s budget 45 events into a chunk of 50.
      await built.gateway.recordToolCalls(
        Array.from({ length: 100 }, (_, i) => toolCallInput(`call-${String(i)}`)),
      );
    } finally {
      nowSpy.mockRestore();
    }

    expect(calls.delivered).toHaveLength(5);
    const drops = readForwardDrops(dir);
    // 95, not 50: counted from where the retry stopped, not from the next chunk
    // boundary. Counting from the boundary loses the 45 this chunk had left.
    expect(drops?.droppedForwards).toBe(95);
    expect(calls.delivered.length + (drops?.droppedForwards ?? 0)).toBe(100);
  });

  it('counts from the CHUNK it stopped in, not from the start of the batch', async () => {
    // The other half of the tally arithmetic. The case above stops inside the
    // FIRST chunk, where `i` is 0 — so it cannot tell `inputs.length - i - j`
    // from `inputs.length - j`. This one stops inside the SECOND chunk, where
    // both terms are non-zero and dropping either one breaks the invariant.
    let clock = 1_000;
    let batches = 0;
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        try {
          const value = await op();
          clock += 600;
          return { ok: true, value } as ForwardResult<unknown>;
        } catch (err) {
          const reason =
            (err as { name?: string }).name === 'RemoteRouteAbsent'
              ? 'route-absent'
              : 'unreachable';
          return { ok: false, reason } as ForwardResult<unknown>;
        }
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const client = {
      ...makeClient(calls),
      // The first chunk lands whole; the second finds no batch route and falls
      // to the per-item pass, which is where the deadline catches it.
      recordAuditEvents: vi.fn((events: readonly unknown[]) => {
        batches += 1;
        return batches === 1
          ? Promise.resolve({ accepted: events.length })
          : Promise.reject(Object.assign(new Error('absent'), { name: 'RemoteRouteAbsent' }));
      }),
      recordAuditEvent: vi.fn(() => Promise.resolve()),
    } as unknown as AttachedClient;

    const nowSpy = vi.spyOn(Date, 'now').mockImplementation(() => clock);
    let dir: string;
    try {
      const built = build({ forward, client, local: makeLocal(calls) });
      dir = built.dataDir;
      await built.gateway.recordToolCalls(
        Array.from({ length: 100 }, (_, i) => toolCallInput(`call-${String(i)}`)),
      );
    } finally {
      nowSpy.mockRestore();
    }

    // Fifty from the first chunk, then four singles before the budget ran out.
    expect(calls.delivered).toHaveLength(54);
    const drops = readForwardDrops(dir);
    // 46 = 100 - 50 settled - 4 attempted. Dropping `- i` gives 96 and dropping
    // `- j` gives 50; both are caught here and by the invariant below.
    expect(drops?.droppedForwards).toBe(46);
    expect(calls.delivered.length + (drops?.droppedForwards ?? 0)).toBe(100);
  });

  /**
   * The gap `HistorySyncPartition`'s docblock named: a structural row the live
   * path forwarded SUCCESSFULLY was never stamped by anything, so it stayed NULL
   * and read as owed — indistinguishable from one the batch budget threw away.
   * `queued` therefore measured "recorded since attach" rather than "not
   * delivered", and every surface built on it would have inherited that.
   */
  it('stamps a single audit event once the forward settles', async () => {
    const { gateway, calls } = build();
    await gateway.recordAuditEvent({
      id: 'evt-1',
      eventType: 'session',
      startedAt: '2026-01-01T00:00:00.000Z',
    });
    expect(calls.delivered).toEqual(['evt-1']);
  });

  it('stamps AFTER the forward, never before', async () => {
    // Same ordering rule recordCapture follows: the local write is authoritative
    // and commits whatever the network does, so there is nothing true to record
    // until the forward has settled. A stamp written first would claim delivery
    // the deployment never acknowledged.
    const { gateway, calls } = build();
    await gateway.recordLlmCall(llmCallInput('m1'));
    expect(calls.order.indexOf('forward.run')).toBeLessThan(
      calls.order.indexOf('local.markAuditEventsDelivered'),
    );
  });

  it('stamps NOTHING when the forward fails', async () => {
    // The bucket has to stay honest in the direction that matters: a row the
    // deployment never received must keep reading as owed, or the outbox forgets
    // it. This is the assertion that stops the stamp becoming unconditional.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const { gateway } = build({ forward: deadForward(calls), local: makeLocal(calls) });
    await gateway.recordLlmCall(llmCallInput('m1'));
    expect(calls.delivered).toEqual([]);
  });

  it('stamps the DELIVERED HEAD of a batch whose tail the budget dropped', async () => {
    // The case the accumulate-then-stamp shape exists for. `forwardBatch`
    // returns early when the deadline passes, and a stamp written only after the
    // loop would be skipped by that return — leaving the rows that DID arrive
    // reading as owed, on exactly the slow-plane machine this is all for.
    // Chunked now, so it takes 600 events rather than 40 to reach the deadline.
    let clock = 1_000;
    const forward: ForwardPolicy = {
      run: async (op: () => Promise<unknown>) => {
        clock += 600;
        return { ok: true, value: await op() } as ForwardResult<unknown>;
      },
    } as unknown as ForwardPolicy;

    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const seen: unknown[] = [];
    const client = {
      ...makeClient(calls),
      recordAuditEvents: vi.fn((events: readonly unknown[]) => {
        seen.push(...events);
        return Promise.resolve({ accepted: events.length });
      }),
    } as unknown as AttachedClient;

    const nowSpy = vi.spyOn(Date, 'now').mockImplementation(() => clock);
    try {
      const { gateway } = build({ client, forward, local: makeLocal(calls) });
      await gateway.recordToolCalls(
        Array.from({ length: 600 }, (_, i) => toolCallInput(`call-${String(i)}`)),
      );
    } finally {
      nowSpy.mockRestore();
    }

    // Partial on BOTH sides — the positive control. An assertion that only
    // checked "some were stamped" would pass if all 600 were, which is the
    // opposite bug.
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.length).toBeLessThan(600);
    // IDENTITY, not count. `toHaveLength(seen.length)` would pass if the
    // accumulator had stamped the wrong ids — the first N inputs rather than
    // the N that came back `ok`. Those coincide here, which is exactly why a
    // length assertion cannot tell them apart; this pins the join the whole PR
    // rests on. `reKeyForForward` rewrites inventory ids, not `event.id`, so
    // `seen`'s own ids are still comparable to what got stamped.
    expect(calls.delivered).toEqual(seen.map((e) => (e as AuditEventInput).id));
  });
});

// ── the local scope key ─────────────────────────────────────────────────────

describe('the local scope key never reaches the client', () => {
  /**
   * `scope_key` is this machine's own routing fact, and every audit-event
   * request's attributes member is an open record that the outbound parse
   * passes straight through. So the strip is the only thing between a stamped
   * row and the receiving side's storage. It has to hold on every route, and on
   * both of reKeyForForward's branches: before the inventory resolved (ids
   * dropped) and after it (ids substituted).
   */
  it('is absent from every body, on every route and both re-key branches', async () => {
    const KEY = 'github.com/org/api';
    const sent: string[] = [];
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const client = makeClient(calls, {
      ingestEvents: (batch) => {
        sent.push(JSON.stringify(batch));
        return Promise.resolve({ accepted: 1, duplicates: 0 });
      },
      ingestInventory: (context) => {
        sent.push(JSON.stringify(context));
        return Promise.resolve({ hostId: 'tenant-host' });
      },
      recordAuditEvent: (body) => {
        sent.push(JSON.stringify(body));
        return Promise.resolve();
      },
      recordAuditEvents: (bodies) => {
        sent.push(JSON.stringify(bodies));
        return Promise.resolve({ accepted: bodies.length });
      },
    });
    const { gateway } = build({ client, local: makeLocal(calls) });

    // Before any inventory resolved: reKeyForForward's null branch.
    await gateway.recordAuditEvent(
      auditEvent({ id: 'root-a', attributes: { cwd: '/w', scope_key: KEY } }),
    );
    await gateway.recordLlmCall({
      ...llmCallInput('m-a'),
      attributes: { model: 'claude-opus-5', scope_key: KEY },
    });
    await gateway.recordConfigScan({
      items: [],
      scanEvent: {
        id: 'scan-a',
        eventType: 'config_scan',
        startedAt: '2026-08-19T10:00:00.000Z',
        attributes: { skills: 1, scope_key: KEY },
      },
    });
    // After it resolved: the substitution branch.
    await gateway.ensureInventory({});
    await gateway.recordAuditEvent(auditEvent({ id: 'root-b', attributes: { scope_key: KEY } }));
    await gateway.recordLlmCalls([
      { ...llmCallInput('m-b'), attributes: { model: 'claude-opus-5', scope_key: KEY } },
    ]);
    await gateway.recordToolCalls([
      { ...toolCallInput('t-b'), attributes: { tool_name: 'Bash', scope_key: KEY } },
    ]);
    // A capture carries its key BESIDE the event, so its body never had one.
    await gateway.recordCapture({ event: event('e1'), findings: [], scopeKey: KEY });

    // Positive control: all eight forwards reached the client, so the absence
    // below is the strip's doing and not a forward that never ran.
    expect(sent).toHaveLength(8);
    for (const body of sent) {
      expect(body).not.toContain('scope_key');
      expect(body).not.toContain(KEY);
    }
  });
});

// ── the scope verdict, method by method ─────────────────────────────────────

const REFUSED_KEYS = [OUT, undefined, ''] as const;

describe("a finding's location never reaches the client", () => {
  it('forwards each inspection without its line, column or excerpt, and stores them locally', async () => {
    const seen: unknown[] = [];
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls);
    const localCalls: ToolCallInput[][] = [];
    const recordLocally = local.recordToolCalls.bind(local);
    local.recordToolCalls = (inputs) => {
      localCalls.push([...inputs]);
      return recordLocally(inputs);
    };
    const client = {
      ...makeClient(calls),
      recordAuditEvents: vi.fn((events: readonly unknown[]) => {
        seen.push(...events);
        return Promise.resolve({ accepted: events.length });
      }),
    } as unknown as AttachedClient;
    const { gateway } = build({ client, local });

    const inspection = {
      ruleId: 'code-flaws/xss-inner-html',
      ruleName: 'innerHTML assignment',
      ruleVersion: '1',
      category: 'code_flaw' as const,
      severity: 'high' as const,
      span: { start: 4, end: 15 },
      maskedMatch: 'i*********=',
      actionTaken: 'log' as const,
      confidence: 0.8,
    };
    await gateway.recordToolCalls([
      {
        ...toolCallInput('located'),
        inspections: [
          {
            ...inspection,
            line: 2,
            col: 5,
            context: {
              basis: 'excerpt',
              firstLine: 2,
              lines: ['x = innerHTML = y'],
              match: { line: 2, start: 4, end: 15 },
            },
          },
        ],
      },
    ]);

    // Positive control: the local write kept the location.
    expect(localCalls[0]?.[0]?.inspections[0]?.line).toBe(2);
    expect(localCalls[0]?.[0]?.inspections[0]?.context).not.toBeNull();
    // The wire carries the inspection as the wire shape names it, and nothing more.
    expect(seen).toHaveLength(1);
    const sent = (seen[0] as { inspections?: unknown[] }).inspections ?? [];
    expect(sent).toEqual([inspection]);
  });
});

describe('the scope verdict, method by method', () => {
  // Every `… forwards …` case here is a GUARD rather than a red test: a gateway
  // with no verdict forwards everything, so they pass before one exists. They
  // pin the verdict's other half, that an in-scope row still forwards, so a
  // verdict that refused everything on a scoped attachment fails here.
  it('recordCapture forwards a capture whose key is in scope', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordCapture(capture('e1', IN));
    expect(calls.order).toContain('client.ingestEvents');
    expect(calls.order).toContain('local.markCaptureDelivered');
  });

  // The owed branch marks every NON-DELIVERY owed, and an owed capture is sent
  // later, text included, by the drain. A refusal is not a non-delivery, so it
  // must return before that branch, and before the forward.
  it.each(REFUSED_KEYS)(
    'recordCapture keeps a capture keyed %s local and never owed',
    async (key) => {
      const { gateway, calls } = build({ attachment: SCOPED });
      await gateway.recordCapture(capture('e1', key));
      expect(calls.order).toContain('local.recordCapture');
      expect(calls.order).not.toContain('forward.run');
      expect(calls.order).not.toContain('local.markCaptureOwed');
      expect(calls.order).not.toContain('local.markCaptureDelivered');
    },
  );

  it('recordAuditEvent forwards a root whose key is in scope', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordAuditEvent(rootRow('s1', IN));
    expect(calls.order).toContain('client.recordAuditEvent');
    expect(calls.delivered).toEqual(['s1']);
  });

  it.each(REFUSED_KEYS)(
    'recordAuditEvent keeps a root keyed %s local and unstamped',
    async (key) => {
      const { gateway, calls } = build({ attachment: SCOPED });
      await gateway.recordAuditEvent(rootRow('s1', key));
      expect(calls.order).toContain('local.recordAuditEvent');
      expect(calls.order).not.toContain('forward.run');
      expect(calls.delivered).toEqual([]);
    },
  );

  it('recordLlmCall forwards an in-scope leaf under an in-scope root', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordLlmCall(llmLeaf('m1', 's1', IN));
    expect(calls.delivered).toEqual(['s1', llmCallId('s1', 'm1')]);
  });

  it.each(REFUSED_KEYS)(
    'recordLlmCall keeps a leaf keyed %s local under an in-scope root',
    async (key) => {
      const { gateway, calls } = build({ attachment: SCOPED });
      await gateway.recordAuditEvent(rootRow('s1', IN));
      await gateway.recordLlmCall(llmLeaf('m1', 's1', key));
      expect(calls.order).toContain('local.recordLlmCall');
      // One forward, the root's; the leaf is never offered and never stamped.
      expect(calls.order.filter((step) => step === 'forward.run')).toHaveLength(1);
      expect(calls.delivered).toEqual(['s1']);
    },
  );

  it('recordLlmCalls and recordToolCalls forward in-scope leaves under an in-scope root', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordLlmCalls([llmLeaf('m1', 's1', IN)]);
    await gateway.recordToolCalls([toolLeaf('t1', 's1', IN)]);
    expect(calls.batchSizes).toEqual([1, 1]);
    expect(calls.delivered).toEqual(['s1', llmCallId('s1', 'm1'), toolCallId('s1', 't1')]);
  });

  it.each(REFUSED_KEYS)(
    'recordLlmCalls and recordToolCalls keep leaves keyed %s out of the batch',
    async (key) => {
      const { gateway, calls, dataDir: dir } = build({ attachment: SCOPED });
      await gateway.recordAuditEvent(rootRow('s1', IN));
      await gateway.recordLlmCalls([llmLeaf('m1', 's1', key)]);
      await gateway.recordToolCalls([toolLeaf('t1', 's1', key)]);
      expect(calls.order).toContain('local.recordLlmCalls');
      expect(calls.order).toContain('local.recordToolCalls');
      expect(calls.batchSizes).toEqual([]);
      expect(calls.delivered).toEqual(['s1']);
      // Filtered BEFORE the batch, so not one refusal is tallied as a lost forward.
      expect(readForwardDrops(dir)).toBeNull();
    },
  );

  it('recordConfigScan stays local on a scoped attachment, even when stamped in scope', async () => {
    const scan: ConfigScanRecord = {
      items: [],
      scanEvent: {
        id: 'scan-1',
        eventType: 'config_scan',
        startedAt: '2026-08-19T10:00:00.000Z',
        attributes: { scope_key: IN },
      },
    };
    const scoped = build({ attachment: SCOPED });
    await scoped.gateway.recordConfigScan(scan);
    expect(scoped.calls.order).toContain('local.recordConfigScan');
    expect(scoped.calls.order).not.toContain('forward.run');
    expect(scoped.calls.delivered).toEqual([]);
    // The contrast: a machine attachment forwards the same scan.
    const machine = build();
    await machine.gateway.recordConfigScan(scan);
    expect(machine.calls.delivered).toEqual(['scan-1']);
  });

  it('recordProjectEgress forwards a scan of an enrolled remote, keyed before hashing', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    const summary = await gateway.recordProjectEgress(
      { ...egressInput(), projectKey: 'git:https://github.com/org/api.git' },
      // The scan walked no nested repository, and says so.
      { nestedScopeKeys: [] },
    );
    expect(calls.order).toContain('client.recordProjectEgress');
    expect(summary.destinations).toBe(1);
  });

  it.each(['git:https://github.com/me/personal.git', 'path:/home/me/scratch'])(
    'recordProjectEgress keeps %s local and still returns the local summary',
    async (projectKey) => {
      const { gateway, calls } = build({ attachment: SCOPED });
      // The scan walked no nested repository, and says so: what refuses the
      // register here is the project's own key, not a list nobody supplied.
      const summary = await gateway.recordProjectEgress(
        { ...egressInput(), projectKey },
        { nestedScopeKeys: [] },
      );
      expect(calls.order).toContain('local.recordProjectEgress');
      expect(calls.order).not.toContain('forward.run');
      expect(summary).toEqual({
        destinations: 1,
        endpoints: 2,
        callSites: 3,
        truncated: false,
        droppedFiles: [],
      });
    },
  );

  it('ensureInventory sends the inventory for an enrolled repository', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.ensureInventory(projectCtx('https://github.com/org/api.git'));
    expect(calls.order).toContain('client.ingestInventory');
  });

  // The session root's key is withheld for a web chat session, and the
  // inventory is held to the same rule: the browser host gives such a session
  // its home directory as a stand-in working directory, and a home directory
  // kept under version control resolves a project. Here that project IS enrolled.
  it.each([SOURCE_TOOL.ChatGpt, SOURCE_TOOL.ClaudeAi])(
    'ensureInventory sends no inventory for a %s session, though its project is enrolled',
    async (tool) => {
      const calls: Calls = { order: [], delivered: [], batchSizes: [] };
      const posture = {
        prepare: vi.fn(() => {
          calls.order.push('posture.prepare');
          return Promise.resolve({ deviceId: 'd' } as never);
        }),
        send: vi.fn(() => {
          calls.order.push('posture.send');
          return Promise.resolve();
        }),
      };
      const { gateway } = build({
        attachment: SCOPED,
        posture,
        local: makeLocal(calls),
        client: makeClient(calls),
      });
      await gateway.ensureInventory(projectCtx('https://github.com/org/api.git', tool));
      expect(calls.order).toContain('local.ensureInventory');
      expect(calls.order).not.toContain('client.ingestInventory');
      // Posture stays unconditional.
      expect(calls.order).toContain('posture.prepare');
      expect(calls.order).toContain('posture.send');

      // The control: the same project under a coding harness is sent, so the
      // refusal above is the harness's doing and not the project's.
      await gateway.ensureInventory(projectCtx('https://github.com/org/api.git'));
      expect(calls.order).toContain('client.ingestInventory');
    },
  );

  // A context that names no harness cannot be shown not to be a web chat
  // session, so it is held back with the rest of what the verdict cannot place.
  it('ensureInventory sends no inventory for a context that names no harness', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.ensureInventory({
      project: { url: 'https://github.com/org/api.git', name: 'repo', attributes: {} },
    });
    expect(calls.order).toContain('local.ensureInventory');
    expect(calls.order).not.toContain('client.ingestInventory');
  });

  // Posture is the liveness channel: a scoped machine whose sessions are all
  // personal must still report, or it grades silent.
  it.each(['https://github.com/me/personal.git', '/home/me/scratch', undefined])(
    'ensureInventory sends no inventory for project %s, and still reports posture',
    async (url) => {
      const calls: Calls = { order: [], delivered: [], batchSizes: [] };
      const posture = {
        prepare: vi.fn(() => {
          calls.order.push('posture.prepare');
          return Promise.resolve({ deviceId: 'd' } as never);
        }),
        send: vi.fn(() => {
          calls.order.push('posture.send');
          return Promise.resolve();
        }),
      };
      const { gateway } = build({
        attachment: SCOPED,
        posture,
        local: makeLocal(calls),
        client: makeClient(calls),
      });
      await expect(gateway.ensureInventory(projectCtx(url))).resolves.toEqual({});
      expect(calls.order).toContain('local.ensureInventory');
      expect(calls.order).not.toContain('client.ingestInventory');
      expect(calls.order).toContain('posture.prepare');
      expect(calls.order).toContain('posture.send');
    },
  );

  it("a refused inventory CLEARS the previous session's resolution, as a failed one does", async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const recordAuditEvent = vi.fn<(event: AuditEventInput) => Promise<void>>(() =>
      Promise.resolve(),
    );
    const client = makeClient(calls, {
      ingestInventory: vi.fn(() =>
        Promise.resolve({ hostId: 'tenant-host-A', sourceProjectId: 'tenant-project-A' }),
      ),
      recordAuditEvent,
    });
    const { gateway } = build({ attachment: SCOPED, client });
    await gateway.ensureInventory(projectCtx('https://github.com/org/api.git')); // A: enrolled, resolves
    await gateway.ensureInventory(projectCtx('https://github.com/me/personal.git')); // B: refused
    await gateway.recordAuditEvent(rootRow('c-root', IN));

    const forwarded = recordAuditEvent.mock.calls[0]?.[0];
    expect(forwarded).toBeDefined();
    expect(JSON.stringify(forwarded)).not.toContain('tenant-host-A');
    expect(JSON.stringify(forwarded)).not.toContain('tenant-project-A');
  });
});

// ── freshly attached, nothing enrolled ──────────────────────────────────────

describe('a scoped attachment with nothing enrolled', () => {
  // The state every scoped machine starts in: attached, and no repository
  // enrolled yet. Every row is written exactly as standalone writes it and none
  // is sent, while the posture report, the device's liveness channel, still
  // goes out.
  it('writes every row locally, sends none of them, and still reports posture', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const posture = {
      prepare: vi.fn(() => {
        calls.order.push('posture.prepare');
        return Promise.resolve({ deviceId: 'd' } as never);
      }),
      send: vi.fn(() => {
        calls.order.push('posture.send');
        return Promise.resolve();
      }),
    };
    const { gateway } = build({
      attachment: SCOPED_EMPTY,
      posture,
      local: makeLocal(calls),
      client: makeClient(calls),
      // One `calls` for every fake, so the forward policy's steps land beside
      // the local and client steps this case reads.
      forward: passthroughForward(calls),
    });
    // Every input carries the key an enrolled repository's would, so nothing
    // here is refused for a missing or a foreign key: only for the empty scope.
    await gateway.recordCapture(capture('e1', IN));
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordLlmCall(llmLeaf('m1', 's1', IN));
    await gateway.recordLlmCalls([llmLeaf('m2', 's1', IN)]);
    await gateway.recordToolCalls([toolLeaf('t1', 's1', IN)]);
    await gateway.recordConfigScan({
      items: [],
      scanEvent: { id: 'scan-1', eventType: 'config_scan', startedAt: '2026-08-19T10:00:00.000Z' },
    });
    await gateway.recordProjectEgress(
      { ...egressInput(), projectKey: 'git:https://github.com/org/api.git' },
      // Nothing nested, so only the empty scope can keep the register local.
      { nestedScopeKeys: [] },
    );
    await gateway.ensureInventory(projectCtx('https://github.com/org/api.git'));

    for (const step of [
      'local.recordCapture',
      'local.recordAuditEvent',
      'local.recordLlmCall',
      'local.recordLlmCalls',
      'local.recordToolCalls',
      'local.recordConfigScan',
      'local.recordProjectEgress',
      'local.ensureInventory',
    ]) {
      expect(calls.order).toContain(step);
    }
    expect(calls.order).not.toContain('forward.run');
    expect(calls.order.filter((step) => step.startsWith('client.'))).toEqual([]);
    expect(calls.order).not.toContain('local.markCaptureOwed');
    expect(calls.order).not.toContain('local.markCaptureDelivered');
    expect(calls.delivered).toEqual([]);
    expect(calls.order).toContain('posture.prepare');
    expect(calls.order).toContain('posture.send');
  });
});

// ── a child row needs its session root in scope ─────────────────────────────

describe('a child row forwards only beside an in-scope root', () => {
  it('a keyless root with keyed leaves sends nothing', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordAuditEvent(rootRow('s1', undefined));
    await gateway.recordLlmCalls([llmLeaf('m1', 's1', IN)]);
    await gateway.recordToolCalls([toolLeaf('t1', 's1', IN)]);
    await gateway.recordLlmCall(llmLeaf('m2', 's1', IN));
    expect(calls.order).not.toContain('forward.run');
    expect(calls.delivered).toEqual([]);
  });

  it('a keyed root with a keyless leaf sends the root only', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordLlmCalls([llmLeaf('m1', 's1', undefined)]);
    await gateway.recordToolCalls([toolLeaf('t1', 's1', undefined)]);
    expect(calls.batchSizes).toEqual([]);
    expect(calls.delivered).toEqual(['s1']);
  });

  // A leaf and its session root can be keyed differently: the root from where
  // the session began, a leaf from the path or directory it names. A leaf
  // forwards only when its own key AND its root's are enrolled, so a personal
  // leaf never forwards beside an enrolled root, and neither does an enrolled
  // leaf beside a personal one. Which root a leaf is held to is the one the
  // store keeps, which the real-store cases further down pin.
  it('a personal leaf never forwards under an enrolled root', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordLlmCalls([llmLeaf('m1', 's1', OUT)]);
    expect(calls.delivered).toEqual(['s1']);
  });

  it('an enrolled leaf never forwards under a personal root', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordAuditEvent(rootRow('s1', OUT));
    await gateway.recordLlmCalls([llmLeaf('m1', 's1', IN)]);
    await gateway.recordToolCalls([toolLeaf('t1', 's1', IN)]);
    expect(calls.order).not.toContain('forward.run');
    expect(calls.delivered).toEqual([]);
  });

  it('a leaf whose root this instance never saw stays local', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordLlmCall(llmLeaf('m1', 'unseen', IN));
    await gateway.recordAuditEvent(
      auditEvent({
        id: 'refusal-1',
        eventType: 'model_refusal',
        rootSessionId: 'unseen',
        ...keyed(IN),
      }),
    );
    expect(calls.order).not.toContain('forward.run');
  });

  // The root's verdict comes from the row the store keeps for it, read back once
  // after the local write, and never from the key on the event just written.
  it('judges a root by the key the store holds, not by the key on the event', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, { readSessionScopeKey: () => OUT });
    const { gateway } = build({ attachment: SCOPED, local, forward: passthroughForward(calls) });
    // The event says enrolled; the store says personal.
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordLlmCalls([llmLeaf('m1', 's1', IN)]);
    await gateway.recordToolCalls([toolLeaf('t1', 's1', IN)]);
    await gateway.recordLlmCall(llmLeaf('m2', 's1', IN));
    expect(calls.order).not.toContain('forward.run');
    expect(calls.delivered).toEqual([]);
  });

  // A root event is sent only when its OWN key is in scope as well. Its
  // attributes (cwd, project, repo) describe where it was recorded from, so a
  // root event keyed to a personal directory must not leave under an enrolled
  // stored root. The leaves are held to the stored root alone, so the enrolled
  // ones still forward: the instance that wrote the stored root forwarded it.
  it.each([OUT, undefined])(
    'does not send a root event keyed %s under an enrolled stored root, and still forwards its enrolled leaves',
    async (eventKey) => {
      const calls: Calls = { order: [], delivered: [], batchSizes: [] };
      const local = makeLocal(calls, { readSessionScopeKey: () => IN });
      const { gateway } = build({
        attachment: SCOPED,
        local,
        client: makeClient(calls),
        forward: passthroughForward(calls),
      });
      await gateway.recordAuditEvent(rootRow('s1', eventKey));
      await gateway.recordLlmCalls([llmLeaf('m1', 's1', IN)]);
      expect(calls.order).not.toContain('client.recordAuditEvent');
      expect(calls.delivered).not.toContain('s1');
      // The leaf did forward, so the root event's absence is the root event's
      // own key and not a gateway that refused the session.
      expect(calls.batchSizes).toEqual([1]);
      expect(calls.delivered).toContain(llmCallId('s1', 'm1'));
    },
  );

  it('keeps a root and its leaves local when the store holds no key for it', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, { readSessionScopeKey: () => undefined });
    const { gateway } = build({ attachment: SCOPED, local, forward: passthroughForward(calls) });
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordLlmCalls([llmLeaf('m1', 's1', IN)]);
    expect(calls.order).not.toContain('forward.run');
    expect(calls.delivered).toEqual([]);
  });

  it('reads the stored root once per root per instance', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const read = vi.fn<(sessionId: string) => string | undefined>(() => IN);
    const local = makeLocal(calls, { readSessionScopeKey: read });
    const { gateway } = build({
      attachment: SCOPED,
      local,
      client: makeClient(calls),
      forward: passthroughForward(calls),
    });
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordLlmCalls([llmLeaf('m1', 's1', IN)]);
    await gateway.recordToolCalls([toolLeaf('t1', 's1', IN)]);
    await gateway.recordLlmCall(llmLeaf('m2', 's1', IN));
    expect(read).toHaveBeenCalledTimes(1);
    await gateway.recordAuditEvent(rootRow('s2', IN));
    expect(read).toHaveBeenCalledTimes(2);
    // Positive control: the root and its leaves did forward, so the single read
    // above is not a count taken of a gateway that refused everything.
    expect(calls.delivered).toContain('s1');
    expect(calls.batchSizes).toEqual([1, 1]);
  });

  // The read costs a store hit, and machine mode owes none: it answers before
  // any root is looked at.
  it('never reads the store in machine mode', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const read = vi.fn<(sessionId: string) => string | undefined>(() => IN);
    const local = makeLocal(calls, { readSessionScopeKey: read });
    const { gateway } = build({ attachment: MACHINE, local, forward: passthroughForward(calls) });
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordLlmCalls([llmLeaf('m1', 's1', IN)]);
    expect(read).not.toHaveBeenCalled();
    expect(calls.delivered).toContain('s1');
  });

  // The verdict is total: a store that cannot answer is an answer of local.
  it('keeps a root and its leaves local, and rejects nothing, when the read throws', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      readSessionScopeKey: () => {
        throw new Error('store unreadable');
      },
    });
    const { gateway } = build({ attachment: SCOPED, local, forward: passthroughForward(calls) });
    await expect(gateway.recordAuditEvent(rootRow('s1', IN))).resolves.toBeUndefined();
    await expect(gateway.recordLlmCalls([llmLeaf('m1', 's1', IN)])).resolves.toBeUndefined();
    expect(calls.order).not.toContain('forward.run');
    expect(calls.delivered).toEqual([]);
  });

  // A GUARD: a gateway with no verdict forwards this row too. It pins that the
  // root rule never reaches a row with no root to be held to.
  it('a row with no root reference is decided by its own key alone', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordAuditEvent(
      auditEvent({ id: 'refusal-1', eventType: 'model_refusal', ...keyed(IN) }),
    );
    expect(calls.delivered).toEqual(['refusal-1']);
  });

  it('a mixed batch forwards only its in-scope leaves, and tallies no drops', async () => {
    const { gateway, calls, dataDir: dir } = build({ attachment: SCOPED });
    await gateway.recordAuditEvent(rootRow('s1', IN));
    await gateway.recordToolCalls([
      toolLeaf('t-in-1', 's1', IN),
      toolLeaf('t-out', 's1', OUT),
      toolLeaf('t-none', 's1', undefined),
      toolLeaf('t-in-2', 's1', IN),
    ]);
    expect(calls.batchSizes).toEqual([2]);
    expect(calls.delivered).toEqual(['s1', toolCallId('s1', 't-in-1'), toolCallId('s1', 't-in-2')]);
    expect(readForwardDrops(dir)).toBeNull();
  });

  // A batch leaf is held to its root by the reference a single row is held by:
  // its `rootSessionId`, else its `parentId`. Both input shapes require both
  // today, so the leaves here are cast past the type to carry only a parent.
  describe('a batch leaf that names only a parent', () => {
    const parentOnly = <T extends { rootSessionId: string }>(leaf: T): T => {
      const copy = { ...leaf };
      Reflect.deleteProperty(copy, 'rootSessionId');
      return copy;
    };

    it('is held back under a personal root, though its own key is enrolled', async () => {
      const { gateway, calls } = build({ attachment: SCOPED });
      await gateway.recordAuditEvent(rootRow('s1', OUT));
      await gateway.recordLlmCalls([parentOnly(llmLeaf('m1', 's1', IN))]);
      await gateway.recordToolCalls([parentOnly(toolLeaf('t1', 's1', IN))]);
      expect(calls.batchSizes).toEqual([]);
      expect(calls.delivered).toEqual([]);
    });

    it('is held back when its parent was never recorded by this instance', async () => {
      const { gateway, calls } = build({ attachment: SCOPED });
      await gateway.recordLlmCalls([parentOnly(llmLeaf('m1', 'unseen', IN))]);
      await gateway.recordToolCalls([parentOnly(toolLeaf('t1', 'unseen', IN))]);
      expect(calls.batchSizes).toEqual([]);
    });

    // The control: under an enrolled root the same leaves forward, so the two
    // refusals above are the root rule's and not the cast's.
    it('forwards under an enrolled root', async () => {
      const { gateway, calls } = build({ attachment: SCOPED });
      await gateway.recordAuditEvent(rootRow('s1', IN));
      await gateway.recordLlmCalls([parentOnly(llmLeaf('m1', 's1', IN))]);
      await gateway.recordToolCalls([parentOnly(toolLeaf('t1', 's1', IN))]);
      expect(calls.batchSizes).toEqual([1, 1]);
    });
  });

  // A GUARD: a gateway with no verdict forwards these rows too. It pins that
  // machine mode answers before the root rule, on the single-row path and the
  // batch path alike, so a machine attachment never loses a leaf to it.
  it('machine mode keeps no root rule: a leaf whose root it never saw still forwards', async () => {
    const { gateway, calls } = build({ attachment: MACHINE });
    await gateway.recordLlmCall(llmLeaf('m1', 'unseen', undefined));
    await gateway.recordLlmCalls([llmLeaf('m2', 'unseen', undefined)]);
    await gateway.recordToolCalls([toolLeaf('t1', 'unseen', undefined)]);
    expect(calls.batchSizes).toEqual([1, 1]);
    expect(calls.delivered).toEqual([
      llmCallId('unseen', 'm1'),
      llmCallId('unseen', 'm2'),
      toolCallId('unseen', 't1'),
    ]);
  });
});

// ── totality ────────────────────────────────────────────────────────────────

describe('the verdict is total: a throw means local, never a rejection', () => {
  const unreadableMode = (): ResolvedAttachmentScope => {
    // Built well-typed, then its `mode` redefined as a throwing getter: a cast
    // from a literal without `mode` is a compile error, not a fixture.
    const attachment: ResolvedAttachmentScope = { mode: 'scoped', keys: new Set<string>([IN]) };
    Object.defineProperty(attachment, 'mode', {
      get: () => {
        throw new Error('mode unreadable');
      },
    });
    return attachment;
  };
  const throwingLookup: ResolvedAttachmentScope = {
    mode: 'scoped',
    keys: {
      has: () => {
        throw new Error('key set unreadable');
      },
    } as unknown as ReadonlySet<string>,
  };
  const CASES: readonly (readonly [string, ResolvedAttachmentScope])[] = [
    ['an attachment whose mode cannot be read', unreadableMode()],
    ['a key set that throws on lookup', throwingLookup],
  ];

  it.each(CASES)(
    'with %s, every method writes locally and forwards nothing',
    async (_label, attachment) => {
      const { gateway, calls } = build({ attachment });
      await gateway.recordCapture(capture('e1', IN));
      await gateway.recordAuditEvent(rootRow('s1', IN));
      await gateway.recordLlmCall(llmLeaf('m1', 's1', IN));
      await gateway.recordLlmCalls([llmLeaf('m2', 's1', IN)]);
      await gateway.recordToolCalls([toolLeaf('t1', 's1', IN)]);
      await gateway.recordProjectEgress(
        { ...egressInput(), projectKey: 'git:https://github.com/org/api.git' },
        { nestedScopeKeys: [] },
      );
      await gateway.ensureInventory(projectCtx('https://github.com/org/api.git'));
      for (const step of [
        'local.recordCapture',
        'local.recordAuditEvent',
        'local.recordLlmCall',
        'local.recordLlmCalls',
        'local.recordToolCalls',
        'local.recordProjectEgress',
        'local.ensureInventory',
      ]) {
        expect(calls.order).toContain(step);
      }
      expect(calls.order).not.toContain('forward.run');
      expect(calls.order).not.toContain('local.markCaptureOwed');
      expect(calls.delivered).toEqual([]);
    },
  );

  it('a capture whose key cannot be read is kept local', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    const record = capture('e1', IN);
    Object.defineProperty(record, 'scopeKey', {
      get: () => {
        throw new Error('key unreadable');
      },
    });
    await expect(gateway.recordCapture(record)).resolves.toBeUndefined();
    expect(calls.order).toContain('local.recordCapture');
    expect(calls.order).not.toContain('forward.run');
    expect(calls.order).not.toContain('local.markCaptureOwed');
  });
});

// ── what a refusal never touches ────────────────────────────────────────────

describe('a refusal never reaches the forward policy', () => {
  it('leaves no breaker state after repeated refusals, against a plane that is down', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const down = (): Promise<never> => Promise.reject(new Error('backend down'));
    const client = makeClient(calls, {
      ingestEvents: down,
      recordAuditEvent: down,
      recordProjectEgress: down,
    });
    const { gateway, dataDir: dir } = build({
      attachment: SCOPED,
      client,
      local: makeLocal(calls),
      forward: createForwardPolicy({ dir: dataDir }),
    });
    for (let i = 0; i < 5; i += 1) {
      await gateway.recordCapture(capture(`out-${String(i)}`, OUT));
      await gateway.recordAuditEvent(rootRow(`personal-${String(i)}`, OUT));
      await gateway.recordProjectEgress(
        { ...egressInput(), projectKey: 'path:/home/me/scratch' },
        { nestedScopeKeys: [] },
      );
    }
    expect(existsSync(join(dir, FORWARD_STATE_FILENAME))).toBe(false);
    expect(readForwardDrops(dir)).toBeNull();

    // Positive control: one in-scope forward against the same dead plane DOES
    // write the breaker's file, so the absence above is the verdict's doing.
    await gateway.recordCapture(capture('in-1', IN));
    expect(existsSync(join(dir, FORWARD_STATE_FILENAME))).toBe(true);
  });
});

describe('a refused capture is never marked owed, on a real store', () => {
  it('leaves outbox_owed NULL on the refused row, and sets it on the undelivered in-scope one', async () => {
    migratedStore.seed(dataDir);
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const gateway = new AttachedDataGateway({
      dataDir,
      local: new StandaloneDataGateway(dataDir, bundledDetections()),
      client: makeClient(calls, {
        ingestEvents: () => Promise.reject(new Error('backend down')),
      }),
      readCachedBundle: () => Promise.resolve(null),
      forward: passthroughForward(calls),
      attachment: SCOPED,
    });
    try {
      await gateway.recordCapture({
        event: { ...event('personal'), id: randomUUID() },
        findings: [],
        scopeKey: OUT,
      });
      await gateway.recordCapture({
        event: { ...event('enrolled'), id: randomUUID() },
        findings: [],
        scopeKey: IN,
      });
    } finally {
      await gateway.close();
    }

    const raw = new DatabaseSync(join(dataDir, DB_FILENAME));
    try {
      const rows = raw
        .prepare(
          `SELECT content_hash, scope_key, outbox_owed, synced_at FROM audit_events
            WHERE event_type = 'prompt' ORDER BY content_hash`,
        )
        .all();
      expect(rows).toEqual([
        { content_hash: 'hash-enrolled', scope_key: IN, outbox_owed: 1, synced_at: null },
        { content_hash: 'hash-personal', scope_key: OUT, outbox_owed: null, synced_at: null },
      ]);
    } finally {
      raw.close();
    }
  });
});

// ── a leaf is held to the stored session root ───────────────────────────────

describe('a leaf is held to the stored session root, on a real store', () => {
  /**
   * Two gateway instances over ONE store, the way the producers meet: the hook
   * that opened the session records its root, and a later reconcile pass, in a
   * process of its own, records a root event for the same session before its
   * leaves. Roots are first-write-wins in the store, so the second root event
   * leaves the stored row as it was, and the history drain decides that row by
   * the key it holds.
   */
  function twoInstances(): {
    first: { gateway: AttachedDataGateway; calls: Calls };
    later: { gateway: AttachedDataGateway; calls: Calls };
  } {
    migratedStore.seed(dataDir);
    const instance = () => {
      const calls: Calls = { order: [], delivered: [], batchSizes: [] };
      const gateway = new AttachedDataGateway({
        dataDir,
        local: new StandaloneDataGateway(dataDir, bundledDetections()),
        client: makeClient(calls),
        readCachedBundle: () => Promise.resolve(null),
        forward: passthroughForward(calls),
        attachment: SCOPED,
      });
      return { gateway, calls };
    };
    return { first: instance(), later: instance() };
  }

  const sent = (calls: Calls): string[] => calls.order.filter((step) => step.startsWith('client.'));

  /** `synced_at` of each named row, read raw: the real store stamps delivery itself. */
  function syncedAt(ids: readonly string[]): Record<string, number | null> {
    const raw = new DatabaseSync(join(dataDir, DB_FILENAME));
    try {
      const stmt = raw.prepare('SELECT synced_at FROM audit_events WHERE id = :id');
      return Object.fromEntries(
        ids.map((id) => [id, (stmt.get({ id }) as { synced_at: number | null }).synced_at]),
      );
    } finally {
      raw.close();
    }
  }

  it('forwards nothing when the stored root is personal and a later root event is enrolled', async () => {
    const { first, later } = twoInstances();
    try {
      await first.gateway.recordAuditEvent(rootRow('s-split', OUT));
      await later.gateway.recordAuditEvent(rootRow('s-split', IN));
      await later.gateway.recordLlmCalls([llmLeaf('m1', 's-split', IN)]);
      await later.gateway.recordToolCalls([toolLeaf('t1', 's-split', IN)]);
      await later.gateway.recordLlmCall(llmLeaf('m2', 's-split', IN));
    } finally {
      await first.gateway.close();
      await later.gateway.close();
    }

    // Neither instance sent a thing, and nothing was stamped delivered.
    expect(sent(first.calls)).toEqual([]);
    expect(sent(later.calls)).toEqual([]);
    expect(syncedAt(['s-split', llmCallId('s-split', 'm1'), toolCallId('s-split', 't1')])).toEqual({
      's-split': null,
      [llmCallId('s-split', 'm1')]: null,
      [toolCallId('s-split', 't1')]: null,
    });
    // The stored root is still the personal one, which is the row the drain reads.
    const raw = new DatabaseSync(join(dataDir, DB_FILENAME));
    try {
      const root = raw.prepare(`SELECT scope_key FROM audit_events WHERE id = 's-split'`).get();
      expect(root).toEqual({ scope_key: OUT });
    } finally {
      raw.close();
    }
  });

  it('forwards the enrolled leaves, but not the personal root event, when the stored root is enrolled', async () => {
    const { first, later } = twoInstances();
    try {
      await first.gateway.recordAuditEvent(rootRow('s-mirror', IN));
      await later.gateway.recordAuditEvent(rootRow('s-mirror', OUT));
      await later.gateway.recordLlmCalls([llmLeaf('m1', 's-mirror', IN)]);
      await later.gateway.recordToolCalls([toolLeaf('t1', 's-mirror', IN)]);
      // A personal leaf beside the same root still never forwards.
      await later.gateway.recordToolCalls([toolLeaf('t2', 's-mirror', OUT)]);
    } finally {
      await first.gateway.close();
      await later.gateway.close();
    }

    // The first instance forwarded the stored root, so the leaves have a root to
    // hang off on the plane.
    expect(sent(first.calls)).toEqual(['client.recordAuditEvent']);
    // The later instance did NOT send its personal-keyed root event: its
    // attributes describe a personal checkout. It forwarded one enrolled
    // llm_call and one enrolled tool_call, in a batch each, and stamped exactly
    // those two. The personal tool_call went nowhere.
    expect(sent(later.calls)).toEqual(['client.recordAuditEvents', 'client.recordAuditEvents']);
    expect(later.calls.batchSizes).toEqual([1, 1]);
    const stamps = syncedAt([
      llmCallId('s-mirror', 'm1'),
      toolCallId('s-mirror', 't1'),
      toolCallId('s-mirror', 't2'),
    ]);
    expect(stamps[llmCallId('s-mirror', 'm1')]).not.toBeNull();
    expect(stamps[toolCallId('s-mirror', 't1')]).not.toBeNull();
    expect(stamps[toolCallId('s-mirror', 't2')]).toBeNull();
  });
});

describe('the verdict decides whether a row is sent, never what is sent', () => {
  // A GUARD: a gateway with no verdict sends the same bodies in both modes. It
  // pins that the verdict, and the scoped slug rewrite, change nothing in what
  // an in-scope row sends.
  it('an in-scope row reaches the client byte-identical to machine mode, with no scope key', async () => {
    const sentBy = async (attachment: ResolvedAttachmentScope): Promise<string[]> => {
      const sent: string[] = [];
      const calls: Calls = { order: [], delivered: [], batchSizes: [] };
      const client = makeClient(calls, {
        ingestEvents: (batch) => {
          sent.push(JSON.stringify(batch));
          return Promise.resolve({ accepted: 1, duplicates: 0 });
        },
        recordAuditEvent: (body) => {
          sent.push(JSON.stringify(body));
          return Promise.resolve();
        },
        recordAuditEvents: (bodies) => {
          sent.push(JSON.stringify(bodies));
          return Promise.resolve({ accepted: bodies.length });
        },
        recordProjectEgress: (request) => {
          sent.push(JSON.stringify(request));
          return Promise.resolve({});
        },
      });
      const { gateway } = build({ attachment, client, local: makeLocal(calls) });
      // The common case the scoped slug rewrite must leave byte for byte alone:
      // the session's checkout IS the keyed repository, so the producer's slug
      // already equals the key's last segment ('api'). The slug is listed FIRST,
      // so a rewrite that moved it to the end of the metadata would show here.
      await gateway.recordCapture({
        event: { ...event('e1'), metadata: { repo: 'api', sessionId: 's1' } },
        findings: [],
        scopeKey: IN,
      });
      await gateway.recordAuditEvent(
        auditEvent({ id: 's1', attributes: { cwd: '/work/api', scope_key: IN } }),
      );
      await gateway.recordLlmCalls([llmLeaf('m1', 's1', IN)]);
      await gateway.recordToolCalls([toolLeaf('t1', 's1', IN)]);
      await gateway.recordProjectEgress(
        { ...egressInput(), projectKey: 'git:https://github.com/org/api.git' },
        { nestedScopeKeys: [] },
      );
      return sent;
    };
    const scoped = await sentBy(SCOPED);
    expect(scoped).toHaveLength(5);
    expect(scoped).toEqual(await sentBy(MACHINE));
    for (const body of scoped) expect(body).not.toContain('scope_key');
  });
});

// ── a scoped capture carries its own key's repository name ──────────────────

describe("a scoped capture forwards its key's repository name", () => {
  const WORK = 'github.com/org/work-repo';
  const SCOPED_WORK: ResolvedAttachmentScope = { mode: 'scoped', keys: new Set<string>([WORK]) };

  /**
   * A file in the enrolled checkout, captured from a session whose working
   * directory is a personal checkout. The producer's slug names the session's
   * directory; the key names the file's repository.
   */
  const crossRepo = (): CaptureRecord => ({
    event: {
      ...event('e1'),
      metadata: { sessionId: 's1', repo: 'personal-repo', filePath: '/work/work-repo/src/app.ts' },
    },
    findings: [],
    scopeKey: WORK,
  });

  /**
   * A gateway whose client records every event `ingestEvents` is handed, and
   * whose local store records the event each delivery stamp is handed.
   * `ingest` settles the forward: a delivery by default, a dead plane to reach
   * the owed stamp.
   */
  const recordingGateway = (
    attachment: ResolvedAttachmentScope,
    ingest: () => ReturnType<AttachedClient['ingestEvents']> = () =>
      Promise.resolve({ accepted: 1, duplicates: 0 }),
  ) => {
    const sent: IngestEvent[] = [];
    const stamped: IngestEvent[] = [];
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const client = makeClient(calls, {
      ingestEvents: (batch) => {
        sent.push(...batch.events);
        return ingest();
      },
    });
    const local = makeLocal(calls, {
      markCaptureDelivered: (stampedEvent) => {
        stamped.push(stampedEvent);
      },
      markCaptureOwed: (stampedEvent) => {
        stamped.push(stampedEvent);
      },
    });
    const { gateway } = build({ attachment, client, local });
    return { gateway, sent, stamped };
  };

  it("scoped: a capture keyed to an enrolled repository forwards that repository's name", async () => {
    const { gateway, sent } = recordingGateway(SCOPED_WORK);
    const record = crossRepo();
    await gateway.recordCapture(record);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.metadata?.repo).toBe('work-repo');
    // Only the slug changes: the id, the content and every other metadata field
    // are the producer's.
    expect(sent[0]).toEqual({
      ...record.event,
      metadata: { ...record.event.metadata, repo: 'work-repo' },
    });
  });

  // A GUARD: a gateway with no rewrite sends the producer's slug already. It
  // pins that the rewrite never reaches a machine attachment.
  it("machine: the same capture forwards the producer's slug, byte-identical", async () => {
    const { gateway, sent } = recordingGateway(MACHINE);
    const record = crossRepo();
    await gateway.recordCapture(record);
    expect(sent[0]?.metadata?.repo).toBe('personal-repo');
    expect(JSON.stringify(sent)).toBe(JSON.stringify([record.event]));
  });

  it("scoped: a capture with no slug (a scanned file's shape) gains its key's; machine adds none", async () => {
    const scoped = recordingGateway(SCOPED_WORK);
    await scoped.gateway.recordCapture({ event: event('scan-1'), findings: [], scopeKey: WORK });
    expect(scoped.sent[0]?.metadata).toEqual({ repo: 'work-repo' });

    const machine = recordingGateway(MACHINE);
    await machine.gateway.recordCapture({ event: event('scan-1'), findings: [], scopeKey: WORK });
    expect(machine.sent[0]).not.toHaveProperty('metadata');
  });

  // The stamps find the row by an id derived from the session id, content hash
  // and file path, never the slug. They are handed the producer's own event all
  // the same, so nothing that reads `record.event` ever sees the copy.
  it("never rewrites the record: the delivery stamp is handed the producer's event", async () => {
    const { gateway, sent, stamped } = recordingGateway(SCOPED_WORK);
    const record = crossRepo();
    await gateway.recordCapture(record);
    expect(sent[0]?.metadata?.repo).toBe('work-repo');
    expect(stamped).toHaveLength(1);
    expect(stamped[0]).toBe(record.event);
    expect(record.event.metadata?.repo).toBe('personal-repo');
  });

  // A GUARD, like the machine case: with no rewrite the owed stamp is handed
  // the producer's event already.
  it("never rewrites the record: the owed stamp is handed the producer's event", async () => {
    const { gateway, stamped } = recordingGateway(SCOPED_WORK, () =>
      Promise.reject(new Error('backend down')),
    );
    const record = crossRepo();
    await gateway.recordCapture(record);
    expect(stamped).toHaveLength(1);
    expect(stamped[0]).toBe(record.event);
    expect(record.event.metadata?.repo).toBe('personal-repo');
  });
});

// ── repositories nested in a scanned project ────────────────────────────────

describe('recordProjectEgress holds a register to every repository nested in it', () => {
  // The scanner folds a nested clone's or submodule's files into the scanned
  // project's register, and hands the key of each nested repository beside it.
  const SHARED = 'github.com/org/shared-lib';
  const SCOPED_WITH_SHARED: ResolvedAttachmentScope = {
    mode: 'scoped',
    keys: new Set<string>([IN, SHARED]),
  };
  const enrolledScan = (): RecordProjectEgressInput => ({
    ...egressInput(),
    projectKey: 'git:https://github.com/org/api.git',
  });
  const LOCAL_SUMMARY = {
    destinations: 1,
    endpoints: 2,
    callSites: 3,
    truncated: false,
    droppedFiles: [],
  };

  it('forwards when the project and every repository nested in it are in scope', async () => {
    const { gateway, calls } = build({ attachment: SCOPED_WITH_SHARED });
    await gateway.recordProjectEgress(enrolledScan(), { nestedScopeKeys: [SHARED] });
    expect(calls.order).toContain('client.recordProjectEgress');
  });

  it('forwards a scan that walked no nested repository', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordProjectEgress(enrolledScan(), { nestedScopeKeys: [] });
    expect(calls.order).toContain('client.recordProjectEgress');
  });

  it.each([
    ['a remote that is not enrolled', [OUT]],
    ['no remote at all', [undefined]],
    ['an empty key', ['']],
    ['one repository out of scope among in-scope ones', [SHARED, OUT]],
  ] as const)(
    'keeps the register local when a nested repository has %s',
    async (_label, nestedScopeKeys) => {
      const { gateway, calls } = build({ attachment: SCOPED_WITH_SHARED });
      const summary = await gateway.recordProjectEgress(enrolledScan(), { nestedScopeKeys });
      expect(calls.order).toContain('local.recordProjectEgress');
      expect(calls.order).not.toContain('forward.run');
      // The scanner reads a throw as a failed write: the local summary comes
      // back whatever the verdict.
      expect(summary).toEqual(LOCAL_SUMMARY);
    },
  );

  it('keeps the register local when the caller does not say what its scan walked', async () => {
    // Only the code that walked the tree can say what is nested in it. A
    // register nobody vouched for is not one a scoped attachment may send.
    const { gateway, calls } = build({ attachment: SCOPED });
    await gateway.recordProjectEgress(enrolledScan());
    expect(calls.order).toContain('local.recordProjectEgress');
    expect(calls.order).not.toContain('forward.run');
  });

  it('keeps the register local when the nested keys cannot be read', async () => {
    const { gateway, calls } = build({ attachment: SCOPED });
    const unreadable: ProjectEgressContext = {
      get nestedScopeKeys(): readonly string[] {
        throw new Error('nested keys unreadable');
      },
    };
    await expect(gateway.recordProjectEgress(enrolledScan(), unreadable)).resolves.toEqual(
      LOCAL_SUMMARY,
    );
    expect(calls.order).not.toContain('forward.run');
  });

  it('keeps an out-of-scope project local, and never reads what is nested in it', async () => {
    const { gateway, calls } = build({ attachment: SCOPED_WITH_SHARED });
    let reads = 0;
    const counted: ProjectEgressContext = {
      get nestedScopeKeys(): readonly string[] {
        reads += 1;
        return [SHARED];
      },
    };
    await gateway.recordProjectEgress(
      { ...egressInput(), projectKey: 'git:https://github.com/me/personal.git' },
      counted,
    );
    expect(calls.order).not.toContain('forward.run');
    // The project's own key is decided first, so the list is never read.
    expect(reads).toBe(0);
  });

  it('never reads the nested keys on a machine attachment: the same request either way', async () => {
    const requestSent = async (context?: ProjectEgressContext): Promise<string> => {
      // The fake held in a local, as elsewhere in this file: an unbound method
      // read off `client` would trip the unbound-method lint rule.
      const recordProjectEgress = vi.fn<AttachedClient['recordProjectEgress']>(() =>
        Promise.resolve({}),
      );
      const calls: Calls = { order: [], delivered: [], batchSizes: [] };
      const { gateway } = build({ client: makeClient(calls, { recordProjectEgress }) });
      await gateway.recordProjectEgress(enrolledScan(), context);
      const request = recordProjectEgress.mock.calls[0]?.[0];
      expect(request).toBeDefined();
      return JSON.stringify(request);
    };
    const unreadable: ProjectEgressContext = {
      get nestedScopeKeys(): readonly string[] {
        throw new Error('a machine attachment must not read this');
      },
    };

    const plain = await requestSent();
    expect(await requestSent({ nestedScopeKeys: [OUT, undefined] })).toBe(plain);
    expect(await requestSent(unreadable)).toBe(plain);
  });

  it.each([
    ['a machine attachment', MACHINE],
    ['a scoped attachment', SCOPED_WITH_SHARED],
  ] as const)(
    'writes the register to the local store alone, with %s: the context never reaches it',
    async (_label, attachment) => {
      // The local store's write takes the register and nothing else. Its
      // argument list is recorded as the fake received it, so a context handed
      // down along with the register shows up here as a second argument.
      // Held in a local, as elsewhere in this file, for the unbound-method rule.
      const recordProjectEgress = vi.fn<DataGateway['recordProjectEgress']>(() =>
        Promise.resolve(LOCAL_SUMMARY),
      );
      const calls: Calls = { order: [], delivered: [], batchSizes: [] };
      const { gateway } = build({ attachment, local: makeLocal(calls, { recordProjectEgress }) });

      await gateway.recordProjectEgress(enrolledScan(), { nestedScopeKeys: [SHARED] });

      expect(recordProjectEgress.mock.calls).toHaveLength(1);
      const args: readonly unknown[] = recordProjectEgress.mock.calls[0] ?? [];
      expect(args).toEqual([enrolledScan()]);
    },
  );
});

// ── deleted paths of a register ─────────────────────────────────────────────

describe('recordProjectEgress sends a deleted path only when its repository is in scope', () => {
  // The scan's deletion sweep lists every ledgered path under its root that is
  // gone, whichever repository it was in, and the register carries them under
  // the scanned project's key. The scan says which repository each was in
  // (`deletedFileKeys`); a scoped attachment sends the ones in scope.
  const SHARED = 'github.com/org/shared-lib';
  const SCOPED_WITH_SHARED: ResolvedAttachmentScope = {
    mode: 'scoped',
    keys: new Set<string>([IN, SHARED]),
  };
  const ENROLLED = 'git:https://github.com/org/api.git';
  const DELETED = ['src/old.ts', 'personal-clone/a.ts', 'personal-clone/src/b.ts', 'lib/gone.ts'];
  const ledgerRegister = (deletedFiles: readonly string[] = DELETED): RecordProjectEgressInput => ({
    ...egressInput(),
    projectKey: ENROLLED,
    reconcile: { mode: 'ledger', scannedFiles: ['src/new.ts'], deletedFiles: [...deletedFiles] },
  });
  const LOCAL_SUMMARY = {
    destinations: 1,
    endpoints: 2,
    callSites: 3,
    truncated: false,
    droppedFiles: [],
  };

  // The request the client was handed, if any, and what every fake saw.
  const run = async (
    attachment: ResolvedAttachmentScope,
    input: RecordProjectEgressInput,
    context?: ProjectEgressContext,
  ) => {
    const recordProjectEgress = vi.fn<AttachedClient['recordProjectEgress']>(() =>
      Promise.resolve({}),
    );
    const localWrite = vi.fn<DataGateway['recordProjectEgress']>(() =>
      Promise.resolve(LOCAL_SUMMARY),
    );
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const { gateway } = build({
      attachment,
      client: makeClient(calls, { recordProjectEgress }),
      local: makeLocal(calls, { recordProjectEgress: localWrite }),
    });
    const summary = await gateway.recordProjectEgress(input, context);
    const request = recordProjectEgress.mock.calls[0]?.[0];
    return { summary, request, forwards: recordProjectEgress.mock.calls.length, localWrite };
  };
  type Request = Parameters<AttachedClient['recordProjectEgress']>[0];
  const deletedOf = (request: Request | undefined): readonly string[] => {
    const reconcile = request?.reconcile;
    if (reconcile?.mode !== 'ledger') throw new Error('expected a ledger-mode request');
    return reconcile.deletedFiles;
  };

  it('forwards only the deleted paths whose key is in scope, in the register order', async () => {
    const keys = [IN, OUT, undefined, SHARED];
    const { request, summary } = await run(SCOPED_WITH_SHARED, ledgerRegister(), {
      nestedScopeKeys: [],
      deletedFileKeys: () => Promise.resolve(keys),
    });
    expect(deletedOf(request)).toEqual(['src/old.ts', 'lib/gone.ts']);
    expect(summary).toEqual(LOCAL_SUMMARY);
  });

  it('keeps everything else of the register as it was: the scanned files, the hits, the key', async () => {
    const withKeys = await run(SCOPED, ledgerRegister(), {
      nestedScopeKeys: [],
      deletedFileKeys: () => Promise.resolve([IN, IN, IN, IN]),
    });
    // Every path in scope: the request is the one a register with no filtering
    // would send, so only the deleted list can differ when some are held back.
    const held = await run(SCOPED, ledgerRegister(), {
      nestedScopeKeys: [],
      deletedFileKeys: () => Promise.resolve([IN, OUT, OUT, IN]),
    });
    expect(deletedOf(withKeys.request)).toEqual(DELETED);
    expect(deletedOf(held.request)).toEqual(['src/old.ts', 'lib/gone.ts']);
    expect({ ...held.request, reconcile: undefined }).toEqual({
      ...withKeys.request,
      reconcile: undefined,
    });
    expect(held.request).toMatchObject({
      reconcile: { mode: 'ledger', scannedFiles: ['src/new.ts'] },
    });
  });

  it.each([
    ['a remote that is not enrolled', OUT],
    ['no remote at all', undefined],
    ['an empty key', ''],
  ] as const)('holds back a deleted path with %s', async (_label, key) => {
    const { request } = await run(SCOPED, ledgerRegister(['gone.ts']), {
      nestedScopeKeys: [],
      deletedFileKeys: () => Promise.resolve([key]),
    });
    expect(deletedOf(request)).toEqual([]);
  });

  it('forwards the register itself when every deleted path is held back', async () => {
    const { forwards, request } = await run(SCOPED, ledgerRegister(), {
      nestedScopeKeys: [],
      deletedFileKeys: () => Promise.resolve([OUT, OUT, undefined, OUT]),
    });
    expect(forwards).toBe(1);
    expect(deletedOf(request)).toEqual([]);
  });

  it.each([
    ['no list of keys', undefined],
    [
      'a list that cannot be read',
      () => {
        throw new Error('deleted keys unreadable');
      },
    ],
    ['a list whose read is rejected', () => Promise.reject(new Error('deleted keys unreadable'))],
    ['a list shorter than the deleted paths', () => Promise.resolve([IN, IN, IN])],
    ['a list longer than the deleted paths', () => Promise.resolve([IN, IN, IN, IN, IN])],
  ] as const)('forwards no deleted path, but the register, with %s', async (_label, getter) => {
    const { forwards, request, summary } = await run(SCOPED, ledgerRegister(), {
      nestedScopeKeys: [],
      deletedFileKeys: getter,
    });
    expect(forwards).toBe(1);
    expect(deletedOf(request)).toEqual([]);
    expect(request).toMatchObject({ reconcile: { scannedFiles: ['src/new.ts'] } });
    expect(summary).toEqual(LOCAL_SUMMARY);
  });

  it('never reads the deleted keys when no path was deleted, or for a register that lists none', async () => {
    let reads = 0;
    const counted: ProjectEgressContext = {
      nestedScopeKeys: [],
      deletedFileKeys: () => {
        reads += 1;
        return Promise.resolve([]);
      },
    };
    const none = await run(SCOPED, ledgerRegister([]), counted);
    expect(none.forwards).toBe(1);
    expect(deletedOf(none.request)).toEqual([]);
    const walk = await run(SCOPED, { ...egressInput(), projectKey: ENROLLED }, counted);
    expect(walk.forwards).toBe(1);
    expect(walk.request).toMatchObject({ reconcile: { mode: 'walk', walkedPrefix: '/repo' } });
    expect(reads).toBe(0);
  });

  it('never reads the deleted keys of a register it keeps local', async () => {
    let reads = 0;
    const counted = (nestedScopeKeys: readonly (string | undefined)[]): ProjectEgressContext => ({
      nestedScopeKeys,
      deletedFileKeys: () => {
        reads += 1;
        return Promise.resolve([IN, IN, IN, IN]);
      },
    });
    // The project's own key is out of scope.
    const personal = await run(
      SCOPED,
      { ...ledgerRegister(), projectKey: 'git:https://github.com/me/personal.git' },
      counted([]),
    );
    // A repository nested in the project is out of scope.
    const nested = await run(SCOPED, ledgerRegister(), counted([OUT]));
    expect(personal.forwards).toBe(0);
    expect(nested.forwards).toBe(0);
    expect(reads).toBe(0);
  });

  it('writes every deleted path to the local store, and leaves the scan its own register untouched', async () => {
    const input = ledgerRegister();
    const before = structuredClone(input);
    const { localWrite } = await run(SCOPED, input, {
      nestedScopeKeys: [],
      deletedFileKeys: () => Promise.resolve([IN, OUT, undefined, IN]),
    });
    expect(localWrite.mock.calls).toHaveLength(1);
    const args: readonly unknown[] = localWrite.mock.calls[0] ?? [];
    expect(args).toEqual([before]);
    // The scanner goes on to read the register it handed over.
    expect(input).toEqual(before);
  });

  it('forwards a machine attachment its register unchanged, and never reads the deleted keys', async () => {
    let reads = 0;
    const counted: ProjectEgressContext = {
      nestedScopeKeys: [OUT, undefined],
      deletedFileKeys: () => {
        reads += 1;
        return Promise.resolve([OUT, OUT, OUT, OUT]);
      },
    };
    const unreadable: ProjectEgressContext = {
      get deletedFileKeys(): () => Promise<readonly string[]> {
        throw new Error('a machine attachment must not read this');
      },
    };
    const plain = await run(MACHINE, ledgerRegister());
    const withCounted = await run(MACHINE, ledgerRegister(), counted);
    const withUnreadable = await run(MACHINE, ledgerRegister(), unreadable);

    expect(deletedOf(plain.request)).toEqual(DELETED);
    expect(JSON.stringify(withCounted.request)).toBe(JSON.stringify(plain.request));
    expect(JSON.stringify(withUnreadable.request)).toBe(JSON.stringify(plain.request));
    expect(reads).toBe(0);
  });
});

describe('getPolicyBundle merges the tenant bundle raise-only', () => {
  it('returns the local bundle untouched when the tenant cache is cold', async () => {
    const { gateway } = build({ readCachedBundle: () => Promise.resolve(null) });
    await expect(gateway.getPolicyBundle()).resolves.toMatchObject({ version: 'local' });
  });

  it('degrades to the local bundle when the cache read throws', async () => {
    const { gateway } = build({
      readCachedBundle: () => Promise.reject(new Error('unreadable cache')),
    });
    await expect(gateway.getPolicyBundle()).resolves.toMatchObject({ version: 'local' });
  });

  it('lets the tenant RAISE enforcement above the local policy', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(bundle([policy({ category: 'secret' }, 'warn')], { version: 'local' })),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([policy({ category: 'secret' }, 'block')])),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies.filter((p) => 'category' in p.target)).toHaveLength(1);
    expect(merged.policies[0]?.action).toBe('block');
  });

  /**
   * ONE RULE PER ID, and the LOCAL copy is the one that survives.
   *
   * A bundle re-shipping a rule the machine already installed is ordinary. What
   * two copies cost is not a duplicate finding — `recordCapture` refuses a
   * second finding with the same rule, span and masked value — it is a VAULTED
   * value's recoverability: two identical spans read as an overlap group, the
   * finding is dropped from it, and the region is destroyed one-way instead of
   * being tokenized into a pointer the user can reveal.
   *
   * The ORDER assertion is the half that matters more. With the cache winning,
   * a bundle naming a known rule id with a matcher that never matches would
   * REPLACE the detection instead of sitting beside it — a remote kill switch
   * for any rule an organization can name. So the surviving object is asserted
   * to be the local one, not merely that one survived.
   */
  it('keeps one rule per id, and the local copy is the one that survives', async () => {
    const CONTESTED = 'marketplace/installed-secret';
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const localRule = wireRule(CONTESTED, 'secret');
    const remoteRule = { ...wireRule(CONTESTED, 'secret'), name: 'from-the-plane' };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(bundle([], { version: 'local', rules: [localRule] })),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([], { rules: [remoteRule] })),
    });

    const merged = await gateway.getPolicyBundle();
    const contested = (merged.rules ?? []).filter((r) => r.id === CONTESTED);
    expect(contested).toHaveLength(1);
    // Reds if anyone flips the concat order or lets the cache win.
    expect(contested[0]?.name).toBe(CONTESTED);
  });

  it('still carries a rule only one side declares', async () => {
    // The positive control: dedup must not become "drop whatever the plane
    // adds", which would pass the case above while disabling the whole feature.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(
          bundle([], { version: 'local', rules: [wireRule('local/only', 'secret')] }),
        ),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(bundle([], { rules: [wireRule('plane/only', 'secret')] })),
    });

    const ids = ((await gateway.getPolicyBundle()).rules ?? []).map((r) => r.id);
    expect(ids).toContain('local/only');
    expect(ids).toContain('plane/only');
  });

  // ⚠ THE FIRST-WRITE-WINS TEST. The runtime indexes policies first-write-wins,
  // so a naive [...tenant, ...local] concatenation hands the tenant precedence
  // for every contended target. A tenant policy that is WEAKER than the user's
  // local policy but still at/above the compiled-in default floor then passes a
  // floor-only clamp while silently downgrading real enforcement. This is the
  // one merge bug that looks correct and disables protection.
  it('a WEAKER tenant policy can never win under first-write-wins', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(bundle([policy({ category: 'secret' }, 'block')], { version: 'local' })),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([policy({ category: 'secret' }, 'warn')])),
    });
    const merged = await gateway.getPolicyBundle();
    const secret = merged.policies.filter(
      (p) => 'category' in p.target && p.target.category === 'secret',
    );
    // Exactly ONE policy for the target, so the result is correct whatever
    // order it is read in — and it is the stronger, local one.
    expect(secret).toHaveLength(1);
    expect(secret[0]?.action).toBe('block');
  });

  it('DOES carry prohibitedModels from the cache — a restriction, not a relaxation', async () => {
    // The merge below returns an EXPLICIT field list over `...local`, so a field
    // the organization's bundle carries and this list omits is dropped in
    // silence. That is what happened: the prohibition reached the cache on
    // every attached device and never reached the hook that enforces it, so the
    // whole control was inert while every test around it stayed green.
    //
    // Taking it is safe for the reason the two fields below are not: a
    // prohibition can only ADD a refusal, so there is no relaxation to hand a
    // cache-writer. What it could do is block the user's own sessions, which
    // anyone able to write into that directory can already do far more cheaply
    // by deleting the plugin.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([], { prohibitedModels: ['claude-opus-5'] })),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.prohibitedModels).toEqual(['claude-opus-5']);
  });

  it('leaves prohibitedModels absent when the organization prohibits nothing', async () => {
    // The control: a standalone bundle carries no prohibitions, so the merge
    // must not invent an empty list that reads as an enforced decision.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({ local, readCachedBundle: () => Promise.resolve(bundle([])) });
    const merged = await gateway.getPolicyBundle();
    expect(merged.prohibitedModels).toBeUndefined();
  });

  it('DOES carry redactFallback from the cache — the merge that applies it is elsewhere', async () => {
    // Same defect class as prohibitedModels above: the explicit field list over
    // `...local` drops anything it does not name, so a field the organization
    // ships would reach the cache and never reach the runtime.
    //
    // Carrying it here is not the same as honouring it. The value is merged
    // RAISE-ONLY against the device's own `WorkspaceSettings.redactFallback` by
    // the runtime, where both are in hand — this seam has the bundle and not
    // the setting, so a merge here could only ever be half of one.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([], { redactFallback: 'block' })),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.redactFallback).toBe('block');
  });

  it('leaves redactFallback absent when the organization ships none', async () => {
    // The control: absent must stay absent, so the device's own setting is what
    // the runtime merges against. An invented value here would read as an
    // organizational decision nobody made.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({ local, readCachedBundle: () => Promise.resolve(bundle([])) });
    const merged = await gateway.getPolicyBundle();
    expect(merged.redactFallback).toBeUndefined();
  });

  it('never takes rulesComplete from the cache — that would be a detection kill-switch', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([], { rulesComplete: true, rules: [] })),
    });
    const merged = await gateway.getPolicyBundle();
    // `{ rulesComplete: true, rules: [] }` from the wire would replace the
    // compiled-in bundled packs with nothing, zeroing local detection.
    expect(merged.rulesComplete).toBeUndefined();
  });

  // ── the authored-policy marker ────────────────────────────────────────────
  // `provenance: 'authored'` marks a policy as authored against the deployment
  // rather than expanded from a built-in archetype, and it is read in exactly
  // one direction: the rules such a policy targets are not locally
  // re-assignable. That is a refusal it can only ADD, which is what puts it on
  // the `prohibitedModels` side of the honour/drop line rather than the
  // `reversibleRuleIds` side.
  //
  // The merge emits policies by SPREAD, so the marker survives by construction
  // — including at the two sites that rebuild a policy around a stronger
  // action. Asserted rather than left to the spread, because losing it is the
  // silent failure: the action goes on being enforced while the local override
  // the organization authored away quietly comes back.

  it('keeps the authored marker on a tenant-only policy that passes through', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        // Already at the compiled-in floor for `secret`, so nothing rebuilds it.
        Promise.resolve(
          bundle([{ ...policy({ category: 'secret' }, 'block'), provenance: 'authored' }]),
        ),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies).toHaveLength(1);
    expect(merged.policies[0]?.action).toBe('block');
    expect(merged.policies[0]?.provenance).toBe('authored');
  });

  it('keeps it when the FLOOR CLAMP rebuilds the tenant policy', async () => {
    // The first rebuild site: a tenant-only policy below the compiled-in floor
    // is re-emitted as `{ ...policy, action: floor }`. DEFAULT_ACTIONS.secret is
    // 'warn', so 'log' is rebuilt and the marker has to ride the spread.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(
          bundle([{ ...policy({ category: 'secret' }, 'log'), provenance: 'authored' }]),
        ),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies[0]?.action).toBe('warn');
    expect(merged.policies[0]?.provenance).toBe('authored');
  });

  it('keeps it when a tenant category policy RAISES a local ruleId policy', async () => {
    // The second rebuild site, and the one on the LOCAL side: a local ruleId
    // policy weaker than what the tenant enforces for that rule's category is
    // re-emitted as `{ ...policy, action: remoteFloor }`. The marker asserted
    // here is the LOCAL policy's own — the rebuild must not launder it away
    // either, since a device that forgets which of its policies were authored
    // has lost the lock for all of them.
    const RULE = 'marketplace/authored-secret';
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(
          bundle([{ ...policy({ ruleId: RULE }, 'log'), provenance: 'authored' }], {
            version: 'local',
            rules: [wireRule(RULE, 'secret')],
          }),
        ),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([policy({ category: 'secret' }, 'block')])),
    });
    const merged = await gateway.getPolicyBundle();
    const rulePolicy = merged.policies.find(
      (p) => 'ruleId' in p.target && p.target.ruleId === RULE,
    );
    expect(rulePolicy?.action).toBe('block');
    expect(rulePolicy?.provenance).toBe('authored');
  });

  it('keeps it on the STRONGER side when both sides contend for one target', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(bundle([policy({ category: 'pii' }, 'warn')], { version: 'local' })),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(
          bundle([{ ...policy({ category: 'pii' }, 'block'), provenance: 'authored' }]),
        ),
    });
    const merged = await gateway.getPolicyBundle();
    const pii = merged.policies.filter(
      (p) => 'category' in p.target && p.target.category === 'pii',
    );
    expect(pii).toHaveLength(1);
    expect(pii[0]?.action).toBe('block');
    expect(pii[0]?.provenance).toBe('authored');
  });

  it('invents no marker for a policy neither side authored', async () => {
    // The control. Every assertion above would also pass if the merge stamped
    // `provenance: 'authored'` onto everything it touched — which would lock a device
    // out of re-assigning packs no one ever authored a policy for.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(bundle([policy({ category: 'secret' }, 'warn')], { version: 'local' })),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([policy({ category: 'secret' }, 'block')])),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies).toHaveLength(1);
    expect(merged.policies[0]?.provenance).toBeUndefined();
  });

  it('carries disabled policies through rather than dropping them', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(bundle([policy({ category: 'pii' }, 'warn', false)], { version: 'local' })),
      ),
    });
    const { gateway } = build({ local, readCachedBundle: () => Promise.resolve(bundle([])) });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies.some((p) => !p.enabled)).toBe(true);
  });

  // ── the floor clamp ───────────────────────────────────────────────────────
  // The raise-only test above covers a CONTENDED target. These cover the other
  // half: a target only the tenant declares, where there is no local policy to
  // be stronger than and the compiled-in DEFAULT_ACTIONS floor is the only
  // thing standing between an unsigned bundle and reduced enforcement.

  it('clamps a tenant-only policy UP to the compiled-in floor for its category', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({
      local,
      // The local bundle declares nothing for `secret`, so a floor-only clamp
      // is all that applies. DEFAULT_ACTIONS.secret is 'warn'.
      readCachedBundle: () => Promise.resolve(bundle([policy({ category: 'secret' }, 'log')])),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies).toHaveLength(1);
    expect(merged.policies[0]?.action).toBe('warn');
  });

  it('leaves a tenant policy already AT or ABOVE the floor exactly as sent', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([policy({ category: 'secret' }, 'redact')])),
    });
    const merged = await gateway.getPolicyBundle();
    // Clamping is a floor, not a rewrite: 'redact' is above 'warn' and survives.
    expect(merged.policies[0]?.action).toBe('redact');
  });

  // ⚠ THE TRUST-ORDERING TEST. The wire rules used to resolve a ruleId's
  // category come from the SAME unsigned bundle the clamp defends against. If a
  // tampered bundle could redeclare a compiled-in rule's category, it would pick
  // its own floor: moving `secrets/aws-access-key` from `secret` (floor warn) to
  // `code_context` (floor log) and pairing that with a ruleId-targeted 'log'
  // policy slips a real AWS key past at log-only. The bundled packs are seeded
  // LAST for exactly this reason, so they win every id collision.
  it("a tampered wire category cannot weaken a COMPILED-IN rule's clamp floor", async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(
          bundle([policy({ ruleId: 'secrets/aws-access-key' }, 'log')], {
            // The lie: a real `secret` rule reclassified to a weaker category.
            rules: [wireRule('secrets/aws-access-key', 'code_context')],
          }),
        ),
    });
    const merged = await gateway.getPolicyBundle();
    // Resolved as 'secret' from the compiled-in pack → floor 'warn', not 'log'.
    expect(merged.policies[0]?.action).toBe('warn');
  });

  it('a wire rule DOES supply a floor for a ruleId the plugin does not compile in', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(
          bundle([policy({ ruleId: 'marketplace/brand-new-secret' }, 'allow')], {
            rules: [wireRule('marketplace/brand-new-secret', 'secret')],
          }),
        ),
    });
    const merged = await gateway.getPolicyBundle();
    // The other half of the trust ordering: wire categories are still USEFUL for
    // ids the plugin has never heard of — they just cannot override a known one.
    expect(merged.policies[0]?.action).toBe('warn');
  });

  it('leaves a policy for an UNRESOLVABLE ruleId unclamped rather than guessing', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
    });
    const { gateway } = build({
      local,
      // Not compiled in, and the bundle ships no rule declaring it.
      readCachedBundle: () =>
        Promise.resolve(bundle([policy({ ruleId: 'nobody/knows' }, 'allow')])),
    });
    const merged = await gateway.getPolicyBundle();
    // Deliberate: with no resolvable category there is no floor to apply, and
    // inventing one would clamp against a category the rule may not be in. The
    // policy is inert anyway — it targets a rule nothing can match.
    expect(merged.policies[0]?.action).toBe('allow');
  });

  it('keeps ruleId- and category-targeted policies in SEPARATE namespaces', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      // The user's own category-wide rule for secrets.
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(bundle([policy({ category: 'secret' }, 'block')], { version: 'local' })),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        // A rule id chosen to COLLIDE with that category name once the two
        // namespaces are flattened. Rule ids ride in on the same unsigned
        // bundle as the policies, so an attacker picks this id freely — which
        // is what makes the `rule:`/`category:` prefixing load-bearing rather
        // than cosmetic.
        Promise.resolve(bundle([policy({ ruleId: 'secret' }, 'redact')])),
    });
    const merged = await gateway.getPolicyBundle();
    // Two distinct slots, matching the runtime's two separate indexes. Flatten
    // them and the tenant's ruleId policy contends with the user's category
    // policy for one key, silently dropping one of the two.
    expect(merged.policies).toHaveLength(2);
    const byTarget = Object.fromEntries(
      merged.policies.map((p) => [
        'ruleId' in p.target ? `rule:${p.target.ruleId}` : `category:${p.target.category}`,
        p.action,
      ]),
    );
    expect(byTarget).toEqual({ 'category:secret': 'block', 'rule:secret': 'redact' });
  });

  // ── the local bundle's OWN rules are a category source ─────────────────────

  it('a LOCALLY INSTALLED rule supplies a floor the plugin does not compile in', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      // A marketplace pack the user installed on this device: present in the
      // LOCAL bundle's rules, absent from the tenant's, absent from
      // bundledDetections(). Before it was seeded into the category map, this
      // was the one rule-id shape with no floor at all.
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(
          bundle([], {
            version: 'local',
            rules: [wireRule('marketplace/installed-secret', 'secret')],
          }),
        ),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(bundle([policy({ ruleId: 'marketplace/installed-secret' }, 'allow')])),
    });
    const merged = await gateway.getPolicyBundle();
    const rulePolicy = merged.policies.find((p) => 'ruleId' in p.target);
    // Resolved as 'secret' from the device's own installed pack → floor 'warn'.
    expect(rulePolicy?.action).toBe('warn');
  });

  it("the WIRE cannot redeclare a locally installed rule's category either", async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(
          bundle([], {
            version: 'local',
            rules: [wireRule('marketplace/installed-secret', 'secret')],
          }),
        ),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(
          bundle([policy({ ruleId: 'marketplace/installed-secret' }, 'log')], {
            // The same lie as the compiled-in case, aimed one tier lower.
            rules: [wireRule('marketplace/installed-secret', 'code_context')],
          }),
        ),
    });
    const merged = await gateway.getPolicyBundle();
    // The local pack outranks the wire, so the floor stays 'secret' → 'warn'.
    // Seeding the two sides in the other order would answer 'log' here.
    expect(merged.policies.find((p) => 'ruleId' in p.target)?.action).toBe('warn');
  });

  // ── the two namespaces are separate KEYS but not separate ENFORCEMENT ──────

  // ⚠ THE CROSS-NAMESPACE TEST. `policyKey` (@akasecurity/schema) keeps rule:
  // and category: distinct, so these two policies never contend and both
  // survive the merge — the array looks entirely reasonable. It is the
  // RESOLVER that makes it wrong: plugin-sdk's `createPolicyResolver` consults
  // its `byRule` map first and returns unconditionally when it has an entry,
  // so the tenant's ruleId policy overrides the user's category policy. The
  // compiled-in floor cannot catch it — DEFAULT_ACTIONS tops out at 'warn'.
  it('a tenant ruleId policy cannot undercut the local CATEGORY policy', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(bundle([policy({ category: 'secret' }, 'block')], { version: 'local' })),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(bundle([policy({ ruleId: 'secrets/aws-access-key' }, 'allow')])),
    });
    const merged = await gateway.getPolicyBundle();
    // Clamped to the local category's 'block', not to the 'warn' floor.
    expect(merged.policies.find((p) => 'ruleId' in p.target)?.action).toBe('block');
  });

  it('…including for a rule only the LOCAL bundle declares', async () => {
    // Needs both halves: the category map must resolve the installed rule at
    // all before the local category policy can floor a policy targeting it.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(
          bundle([policy({ category: 'secret' }, 'block')], {
            version: 'local',
            rules: [wireRule('marketplace/installed-secret', 'secret')],
          }),
        ),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(bundle([policy({ ruleId: 'marketplace/installed-secret' }, 'allow')])),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies.find((p) => 'ruleId' in p.target)?.action).toBe('block');
  });

  // The MIRROR of the two cases above, and the one they do not cover. Every
  // enabled installed pack contributes a ruleId-targeted policy per rule via
  // StandaloneDataGateway.getPolicyBundle, with the action taken from
  // `installed_packs.policy_id` — NULL for any pack the user never assigned,
  // which policyIdToAction coalesces to Monitor, i.e. 'log'. Those land on
  // `rule:*` keys the tenant's category policy never contends for, and
  // resolveAction's resolver consults its `byRule` map FIRST. So without a
  // floor on this side, a device's own untouched packs silently reduce the
  // tenant's `secret -> block` to log-only — the fleet-wide failure this merge
  // exists to prevent, reached from the local side instead of the wire.
  it('a LOCAL ruleId policy cannot undercut the TENANT category policy', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(
          bundle([policy({ ruleId: 'secrets/aws-access-key' }, 'log')], { version: 'local' }),
        ),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([policy({ category: 'secret' }, 'block')])),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies.find((p) => 'ruleId' in p.target)?.action).toBe('block');
  });

  it('…including for a rule only the LOCAL bundle declares', async () => {
    // Same two halves as the tenant-side case: the category map has to resolve
    // a locally installed rule before any category policy can floor it.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(
          bundle([policy({ ruleId: 'marketplace/installed-secret' }, 'log')], {
            version: 'local',
            rules: [wireRule('marketplace/installed-secret', 'secret')],
          }),
        ),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([policy({ category: 'secret' }, 'block')])),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies.find((p) => 'ruleId' in p.target)?.action).toBe('block');
  });

  it('a LOCAL ruleId policy STRICTER than the tenant category survives', async () => {
    // The floor must not equalise. A user hardening one rule beyond the
    // tenant's category-wide setting is raising enforcement, which is always
    // allowed — clamping it down to the tenant's action would be the same bug
    // in the opposite direction.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(
          bundle([policy({ ruleId: 'secrets/aws-access-key' }, 'block')], { version: 'local' }),
        ),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () => Promise.resolve(bundle([policy({ category: 'secret' }, 'warn')])),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies.find((p) => 'ruleId' in p.target)?.action).toBe('block');
  });

  it('a tenant ruleId policy that RAISES above the local category still stands', async () => {
    // The clamp is a floor, not an equalisation — the tenant tightening one
    // rule beyond the user's category-wide setting is the whole point of
    // attached mode and must survive.
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(bundle([policy({ category: 'secret' }, 'warn')], { version: 'local' })),
      ),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(bundle([policy({ ruleId: 'secrets/aws-access-key' }, 'block')])),
    });
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies.find((p) => 'ruleId' in p.target)?.action).toBe('block');
  });

  it.each([
    ['category first', true],
    ['ruleId first', false],
  ])(
    'a TENANT category policy never becomes the floor for a tenant ruleId policy (%s)',
    async (_label, categoryFirst) => {
      // Raise-only is defined against the LOCAL bundle. Letting a tenant
      // category policy floor a tenant ruleId policy would both overstate the
      // guarantee and make the result depend on array order — the exact
      // property this merge exists to remove. With no local policy for
      // 'secret', the only floor is the compiled-in 'warn'.
      const calls: Calls = { order: [], delivered: [], batchSizes: [] };
      const local = makeLocal(calls, {
        getPolicyBundle: vi.fn(() => Promise.resolve(bundle([], { version: 'local' }))),
      });
      const tenant = [
        policy({ category: 'secret' }, 'block'),
        policy({ ruleId: 'secrets/aws-access-key' }, 'allow'),
      ];
      const { gateway } = build({
        local,
        readCachedBundle: () =>
          Promise.resolve(bundle(categoryFirst ? tenant : [...tenant].reverse())),
      });
      const merged = await gateway.getPolicyBundle();
      expect(merged.policies.find((p) => 'ruleId' in p.target)?.action).toBe('warn');
    },
  );

  it('resolves duplicate LOCAL targets first-write-wins, matching the runtime', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() =>
        Promise.resolve(
          bundle([policy({ category: 'pii' }, 'block'), policy({ category: 'pii' }, 'log')], {
            version: 'local',
          }),
        ),
      ),
    });
    const { gateway } = build({ local, readCachedBundle: () => Promise.resolve(bundle([])) });
    const merged = await gateway.getPolicyBundle();
    // One slot, and the FIRST local policy holds it — the same precedence the
    // runtime would have applied to the unmerged local bundle.
    expect(merged.policies).toHaveLength(1);
    expect(merged.policies[0]?.action).toBe('block');
  });

  // ── the local store is the trusted side ───────────────────────────────────

  it("a CORRUPT local bundle read propagates — it never degrades to the tenant's", async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const local = makeLocal(calls, {
      getPolicyBundle: vi.fn(() => Promise.reject(new Error('local store corrupt'))),
    });
    const { gateway } = build({
      local,
      readCachedBundle: () =>
        Promise.resolve(bundle([policy({ category: 'secret' }, 'allow')], { version: 'tenant' })),
    });
    // The cache fallback is deliberately one-directional. Degrading a broken
    // LOCAL read to the cached tenant bundle would let anything able to write
    // policy-cache.json become the whole policy the moment it corrupts the
    // store — the backend dictating enforcement, which local-first exists to
    // prevent. A rejection reaches SessionStart, which fails open per its own
    // contract, rather than being silently answered with tenant policy here.
    await expect(gateway.getPolicyBundle()).rejects.toThrow('local store corrupt');
  });
});

// ── posture ordering ────────────────────────────────────────────────────────

describe('posture reporting stays strictly after inventory settles', () => {
  it('runs prepare and send after the inventory call, never before', async () => {
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const posture = {
      prepare: vi.fn(() => {
        calls.order.push('posture.prepare');
        return Promise.resolve({ deviceId: 'd' } as never);
      }),
      send: vi.fn(() => {
        calls.order.push('posture.send');
        return Promise.resolve();
      }),
    };
    const { gateway } = build({ posture });
    await gateway.ensureInventory({});
    expect(calls.order.indexOf('local.ensureInventory')).toBeLessThan(
      calls.order.indexOf('posture.prepare'),
    );
    expect(calls.order.indexOf('posture.prepare')).toBeLessThan(
      calls.order.indexOf('posture.send'),
    );
  });

  it('a throwing posture phase never reaches the session', async () => {
    const posture = {
      prepare: vi.fn(() => {
        throw new Error('sync boom');
      }),
      send: vi.fn(() => Promise.resolve()),
    };
    const { gateway } = build({ posture: posture });
    await expect(gateway.ensureInventory({})).resolves.toEqual({});
  });
});
