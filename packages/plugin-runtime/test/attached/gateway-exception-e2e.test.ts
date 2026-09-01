import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DataGateway, LocalStoreMaintenance } from '@akasecurity/plugin-sdk';
import {
  createPluginRuntime,
  fingerprintValue,
  loadOrCreateFingerprintKey,
  registerRulePack,
} from '@akasecurity/plugin-sdk';
import type { ExceptionBundleEntry, PolicyBundle, WorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy';
import type { AttachedClient } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';

/**
 * `consumeException` end-to-end, through the REAL runtime.
 *
 * `AttachedDataGateway.consumeException` delegates unmodified — including a
 * rejection — and its doc comment justifies that by pointing here: the claim is
 * not just "the composite propagates" (the unit test next door covers that) but
 * that propagating is SAFE, because the runtime treats a throwing consume as
 * "the exception does not apply" and keeps enforcing.
 *
 * That claim spans two packages, so only a composed test can hold it. The
 * plugin-sdk suite already proves the runtime is fail-secure against a *generic*
 * throwing gateway; what is unproven — and what regresses if someone "fixes"
 * the composite by wrapping this method in `catch { return true }` — is that the
 * attached gateway is that kind of gateway when its local store is failing.
 */
registerRulePack('attached-e2e-pack', [
  {
    specVersion: 1,
    id: 'attached-e2e/secret-marker',
    name: 'Attached e2e secret marker',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'keyword', keywords: ['E2E_SECRET_MARKER'] },
    examples: ['E2E_SECRET_MARKER'],
  },
]);

const MARKER = 'E2E_SECRET_MARKER';
const RULE_ID = 'attached-e2e/secret-marker';

// `runMode: 'attached'` is a RETIRED settings value that the schema rewrites to
// 'standalone' on read, so this is what an attached device genuinely reports.
// Nothing in the capture path branches on it either way.
const settings = (): WorkspaceSettings => ({
  specVersion: 1,
  runMode: 'standalone',
  policy: 'redact',
  historicalAccess: 'full',
  dataSharesInPlace: true,
  vaultKeyCustody: 'file',
  vaultInlineReveal: 'masked',
});

/** A local store whose exception ledger answers however the test says. */
function makeLocalStore(opts: {
  bundle: PolicyBundle;
  consumeException: (id: string) => Promise<boolean>;
}): DataGateway & LocalStoreMaintenance {
  return {
    recordCapture: () => Promise.resolve(),
    ensureInventory: () => Promise.resolve({}),
    recordAuditEvent: () => Promise.resolve(),
    recordLlmCall: () => Promise.resolve(),
    recordLlmCalls: () => Promise.resolve(),
    recordToolCalls: () => Promise.resolve(),
    recordConfigScan: () => Promise.resolve(),
    configInventoryReport: () =>
      Promise.resolve({
        scannedAt: null,
        skills: [],
        hooks: [],
        mcpServers: [],
        configFiles: [],
        topics: [],
      }),
    readSessionProvider: () => Promise.resolve(undefined),
    facets: () => Promise.resolve({ hosts: [], harnesses: [], osVersions: [], projects: [] }),
    getPolicyBundle: () => Promise.resolve(opts.bundle),
    consumeException: opts.consumeException,
    recordBlockedDetection: () => Promise.resolve(),
    recentFindings: () => Promise.resolve([]),
    healthSummary: () =>
      Promise.resolve({
        findings: 0,
        byAction: {} as never,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        coverage: 0,
      }),
    activityByDay: () => Promise.resolve([]),
    tokenReports: () => Promise.resolve([]),
    knownContentHashes: () => Promise.resolve(new Set<string>()),
    scanLedger: () => Promise.resolve(new Map()),
    recordScanned: () => Promise.resolve(),
    getRuleProbeVerdict: () => Promise.resolve(undefined),
    setRuleProbeVerdict: () => Promise.resolve(),
    openAtRestKeysForPath: () => Promise.resolve([]),
    resolvedAtRestKeysForPath: () => Promise.resolve([]),
    insertResolution: () => Promise.resolve(),
    recordProjectEgress: () =>
      Promise.resolve({
        destinations: 0,
        endpoints: 0,
        callSites: 0,
        truncated: false,
        droppedFiles: [],
      }),
    close: () => Promise.resolve(),
    sweepTerminalExceptions: () => Promise.resolve(0),
    capWarnEraEnforcement: () => ({ capped: 0 }),
    recordProjectFiles: () => Promise.resolve(),
    reconcileWorktreeProjects: () => Promise.resolve(),
    staleBinaryNotice: () => null,
    markCaptureDelivered: () => undefined,
  };
}

const noopClient = (): AttachedClient => ({
  ingestEvents: () => Promise.resolve({ accepted: 0 } as never),
  ingestInventory: () => Promise.resolve({}),
  recordAuditEvent: () => Promise.resolve(),
  reportStorePosture: () => Promise.resolve({}),
});

/** The backend is irrelevant to this decision; run every forward, ignore it. */
const passthrough = (): ForwardPolicy => ({
  run: async <T>(op: () => Promise<T>): Promise<ForwardResult<T>> => {
    try {
      return { ok: true, value: await op() };
    } catch {
      return { ok: false, reason: 'unreachable' };
    }
  },
});

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-attached-e2e-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function buildRuntime(consumeException: (id: string) => Promise<boolean>) {
  const key = loadOrCreateFingerprintKey(dir);
  const exception: ExceptionBundleEntry = {
    id: randomUUID(),
    ruleId: RULE_ID,
    valueFingerprint: fingerprintValue(key, MARKER),
    keyVersion: key.version,
    capability: 'suppress',
    expiresAt: null,
    maxUses: null,
    useCount: 0,
    conditions: null,
  };
  const bundle: PolicyBundle = {
    version: 'local',
    policies: [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: RULE_ID },
        action: 'block',
        enabled: true,
      },
    ],
    rules: [],
    exceptions: [exception],
    customKeywords: [],
    fetchedAt: '2026-01-01T00:00:00.000Z',
  };
  const consume = vi.fn(consumeException);
  const local = makeLocalStore({ bundle, consumeException: consume });
  const gateway = new AttachedDataGateway({
    dataDir: dir,
    local,
    client: noopClient(),
    readCachedBundle: () => Promise.resolve(null),
    forward: passthrough(),
  });
  return { runtime: createPluginRuntime(gateway, settings(), { dataDir: dir }), consume };
}

describe('consumeException end-to-end through runtime.capture', () => {
  it('a local store that REFUSES to consume leaves the block standing', async () => {
    const { runtime, consume } = buildRuntime(() =>
      Promise.reject(new Error('local store locked')),
    );
    const result = await runtime.processText(MARKER);
    await runtime.close();

    // The exception matched by fingerprint, so the runtime genuinely reached
    // the consume — this is what separates fail-secure from never-evaluated.
    expect(consume).toHaveBeenCalledTimes(1);
    // A rejection means the grant was NOT spent, so it cannot apply. Wrapping
    // the composite's consumeException in `catch { return true }` would turn
    // exactly this store failure into a granted bypass.
    expect(result.action).toBe('block');
  });

  it('a local store that DECLINES (returns false) also leaves the block standing', async () => {
    const { runtime, consume } = buildRuntime(() => Promise.resolve(false));
    const result = await runtime.processText(MARKER);
    await runtime.close();

    expect(consume).toHaveBeenCalledTimes(1);
    expect(result.action).toBe('block');
  });

  // The positive control. Without it the two tests above would still pass if the
  // exception never matched at all — they would be asserting nothing about
  // consume, only that a block blocks. This is the case that proves the grant is
  // genuinely live on this exact capture, so the two refusals above are really
  // testing the refusal and not a misconfigured fixture.
  it('a local store that GRANTS the exception stops enforcing the same capture', async () => {
    const { runtime, consume } = buildRuntime(() => Promise.resolve(true));
    const result = await runtime.processText(MARKER);
    await runtime.close();

    expect(consume).toHaveBeenCalledTimes(1);
    // 'log', not 'allow': with no enforced findings left the runtime returns its
    // benign DEFAULT decision — the detection still happened and is still
    // recorded, it is just no longer enforced. What matters here is only that
    // the same input that blocks above stops blocking when the grant is spent.
    expect(result.action).toBe('log');
  });
});
