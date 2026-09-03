import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { toolCallId } from '@akasecurity/persistence';
import type { DataGateway, LocalStoreMaintenance } from '@akasecurity/plugin-sdk';
import { hasLocalStoreMaintenance } from '@akasecurity/plugin-sdk';
import type {
  AuditEventInput,
  DetectionCategory,
  IngestEvent,
  LlmCallInput,
  Policy,
  PolicyBundle,
  RecordProjectEgressInput,
  ToolCallInput,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { readForwardDrops } from '../../src/attached/forward-drops.ts';
import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy.ts';
import type { AttachedClient, AttachedDataGatewayDeps } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';

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
const _portIsFullyListed: Missing extends never ? true : Missing = true;
void _portIsFullyListed;

const MAINTENANCE_METHODS = [
  'sweepTerminalExceptions',
  'capWarnEraEnforcement',
  'recordProjectFiles',
  'reconcileWorktreeProjects',
  'staleBinaryNotice',
  'markCaptureDelivered',
  'markAuditEventsDelivered',
] as const;
type MissingMaintenance = Exclude<
  keyof LocalStoreMaintenance,
  (typeof MAINTENANCE_METHODS)[number]
>;
const _maintenanceIsFullyListed: MissingMaintenance extends never ? true : MissingMaintenance =
  true;
void _maintenanceIsFullyListed;

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
function makeLocal(calls: Calls, overrides: Partial<DataGateway & LocalStoreMaintenance> = {}) {
  const base: Record<string, unknown> = {};
  for (const name of PORT_METHODS) {
    base[name] = vi.fn((...args: unknown[]) => {
      calls.order.push(`local.${name}`);
      void args;
      // Shapes the composite passes straight through; the delegation test only
      // asserts the call happened and the value came back.
      if (name === 'ensureInventory') return Promise.resolve({});
      if (name === 'knownContentHashes') return Promise.resolve(new Set<string>());
      if (name === 'scanLedger') return Promise.resolve(new Map());
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
  base.markAuditEventsDelivered = vi.fn((events: readonly { id: string }[]) => {
    calls.order.push('local.markAuditEventsDelivered');
    for (const event of events) calls.delivered.push(event.id);
  });
  return Object.assign(base, overrides) as unknown as DataGateway & LocalStoreMaintenance;
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
  rmSync(dataDir, { recursive: true, force: true });
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
    const recordAuditEvent = vi.fn((event: AuditEventInput) => {
      void event;
      return Promise.resolve();
    });
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
    const recordAuditEvent = vi.fn((event: AuditEventInput) => {
      void event;
      return Promise.resolve();
    });
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
    const recordAuditEvent = vi.fn((event: AuditEventInput) => {
      void event;
      return Promise.resolve();
    });
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
    const recordAuditEvent = vi.fn((event: AuditEventInput) => {
      void event;
      return Promise.resolve();
    });
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
        await op();
        return { ok: true } as ForwardResult<unknown>;
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
        await op();
        return { ok: true } as ForwardResult<unknown>;
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
          await op();
          return { ok: true } as ForwardResult<unknown>;
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
        await op();
        return { ok: true } as ForwardResult<unknown>;
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
    // Exactly what landed, and nothing the deadline discarded.
    expect(calls.delivered).toHaveLength(seen.length);
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

  // ⚠ THE CROSS-NAMESPACE TEST. `policyKey` keeps rule: and category: distinct,
  // so these two policies never contend and both survive the merge — the array
  // looks entirely reasonable. It is the RUNTIME that makes it wrong:
  // resolveAction consults the rule index first and returns unconditionally, so
  // the tenant's ruleId policy overrides the user's category policy. The
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
  // resolveAction consults the rule index FIRST. So without a floor on this
  // side, a device's own untouched packs silently reduce the tenant's
  // `secret -> block` to log-only — the fleet-wide failure this merge exists
  // to prevent, reached from the local side instead of the wire.
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
    const calls: Calls = { order: [], delivered: [], batchSizes: [] };
    const posture = {
      prepare: vi.fn(() => {
        throw new Error('sync boom');
      }),
      send: vi.fn(() => Promise.resolve()),
    };
    const { gateway } = build({ posture: posture });
    await expect(gateway.ensureInventory({})).resolves.toEqual({});
    void calls;
  });
});
