import type { DataGateway, LocalStoreMaintenance } from '@akasecurity/plugin-sdk';
import { hasLocalStoreMaintenance } from '@akasecurity/plugin-sdk';
import type {
  AuditEventInput,
  DetectionCategory,
  IngestEvent,
  Policy,
  PolicyBundle,
  RecordProjectEgressInput,
} from '@akasecurity/schema';
import { describe, expect, it, vi } from 'vitest';

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
}

/**
 * A recording stand-in for the inner local gateway. Two of the five maintenance
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
  return Object.assign(base, overrides) as unknown as DataGateway & LocalStoreMaintenance;
}

function makeClient(calls: Calls, overrides: Partial<AttachedClient> = {}): AttachedClient {
  return {
    ingestEvents: vi.fn(() => {
      calls.order.push('client.ingestEvents');
      return Promise.resolve({ accepted: 1 } as never);
    }),
    ingestInventory: vi.fn(() => {
      calls.order.push('client.ingestInventory');
      return Promise.resolve({});
    }),
    recordAuditEvent: vi.fn(() => {
      calls.order.push('client.recordAuditEvent');
      return Promise.resolve();
    }),
    reportStorePosture: vi.fn(() => {
      calls.order.push('client.reportStorePosture');
      return Promise.resolve({});
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

function build(overrides: Partial<AttachedDataGatewayDeps> = {}) {
  const calls: Calls = { order: [] };
  const local = overrides.local ?? makeLocal(calls);
  const client = overrides.client ?? makeClient(calls);
  const gateway = new AttachedDataGateway({
    local,
    client,
    readCachedBundle: overrides.readCachedBundle ?? (() => Promise.resolve(null)),
    forward: overrides.forward ?? passthroughForward(calls),
    ...(overrides.posture ? { posture: overrides.posture } : {}),
  });
  return { gateway, local, client, calls };
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
    await Reflect.apply(methods[name] as (a?: unknown) => Promise<unknown>, gateway, [
      name === 'recordConfigScan'
        ? { items: [], scanEvent: { id: 'c1', eventType: 'config_scan' } }
        : 'arg',
    ]);
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
    const calls: Calls = { order: [] };
    const { gateway } = build({ forward: deadForward(calls) });
    await expect(
      gateway.recordCapture({ event: event('e'), findings: [] }),
    ).resolves.toBeUndefined();
  });

  it('a forward that REJECTS is contained — the local write still stands', async () => {
    const calls: Calls = { order: [] };
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

  it('recordProjectEgress is LOCAL-ONLY — there is no egress ingest endpoint to forward to', async () => {
    const { gateway, calls } = build();
    const summary = await gateway.recordProjectEgress(egressInput());
    expect(calls.order).toContain('local.recordProjectEgress');
    expect(calls.order).not.toContain('forward.run');
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
});

describe('consumeException is a fail-secure boundary', () => {
  it('delegates the answer unmodified', async () => {
    const { gateway } = build();
    await expect(gateway.consumeException('x')).resolves.toBe(true);
  });

  it('does NOT convert a local rejection into a granted bypass', async () => {
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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

  // ⚠ THE FIRST-WRITE-WINS TEST. The runtime indexes policies first-write-wins,
  // so a naive [...tenant, ...local] concatenation hands the tenant precedence
  // for every contended target. A tenant policy that is WEAKER than the user's
  // local policy but still at/above the compiled-in default floor then passes a
  // floor-only clamp while silently downgrading real enforcement. This is the
  // one merge bug that looks correct and disables protection.
  it('a WEAKER tenant policy can never win under first-write-wins', async () => {
    const calls: Calls = { order: [] };
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

  it('never takes rulesComplete from the cache — that would be a detection kill-switch', async () => {
    const calls: Calls = { order: [] };
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

  it('carries disabled policies through rather than dropping them', async () => {
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
      const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
    const calls: Calls = { order: [] };
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
