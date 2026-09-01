import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { DataGateway, LocalStoreMaintenance } from '@akasecurity/plugin-sdk';
import { createPluginRuntime, registerRulePack } from '@akasecurity/plugin-sdk';
import type { Policy, PolicyBundle, WorkspaceSettings } from '@akasecurity/schema';
import { Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { ForwardPolicy, ForwardResult } from '../../src/attached/forward-policy';
import type { AttachedClient } from '../../src/attached/gateway.ts';
import { AttachedDataGateway } from '../../src/attached/gateway.ts';

/**
 * The composed policy bundle, judged by what the RUNTIME does with it.
 *
 * The unit suite next door asserts on the merged array, and for most of
 * `mergeRaiseOnly` that is the right level. It cannot reach this bug. The two
 * policies below sit on DIFFERENT keys — `rule:` and `category:` — so they never
 * contend, both survive any merge, and the array is entirely reasonable to look
 * at. What makes the outcome wrong is `resolveAction`'s precedence: it consults
 * `ruleActionIndex` first and returns unconditionally, so the tenant's
 * ruleId-targeted policy silently overrides the user's category-wide one. Only
 * an assertion that runs the real resolution can fail on that.
 *
 * And the compiled-in floor cannot stand in for the local policy here.
 * DEFAULT_ACTIONS is derived from `severityFloorPolicy`, which returns only
 * 'warn' or 'monitor' — so the floor is never 'redact' or 'block', and every
 * local block policy sits strictly above anything a floor-only clamp can see.
 * That is what makes this reachable rather than theoretical.
 */
const MARKER = 'POLICY_E2E_SECRET_MARKER';
const RULE_ID = 'attached-policy-e2e/secret-marker';

/**
 * A LOCALLY INSTALLED marketplace pack, modelled faithfully: registered with the
 * detection engine so it genuinely matches, and declared in the LOCAL bundle's
 * `rules` — but absent from `bundledDetections()`, which reads the compiled-in
 * BUNDLED_PACKS rather than the registry. That is the same shape a pack the user
 * installed on this device has, and it is the shape whose category the composed
 * map could not resolve at all until the local rules were seeded into it.
 */
const RAW_MARKER_RULE = {
  specVersion: 1,
  id: RULE_ID,
  name: 'Attached policy e2e secret marker',
  category: 'secret',
  severity: 'critical',
  matcher: { type: 'keyword', keywords: [MARKER] },
  examples: [MARKER],
};

registerRulePack('attached-policy-e2e-pack', [RAW_MARKER_RULE]);

// Parsed through the real schema rather than cast: the bundle carries RULES,
// and `Rule.parse` is what fills in the defaults (`caseSensitive`) that a raw
// pack literal leaves out — the same call `registerRulePack` makes internally,
// so both sides see one rule rather than two that merely look alike.
const MARKER_RULE = Rule.parse(RAW_MARKER_RULE);

const settings = (): WorkspaceSettings => ({
  specVersion: 1,
  runMode: 'standalone',
  policy: 'redact',
  historicalAccess: 'full',
  dataSharesInPlace: true,
  vaultKeyCustody: 'file',
  vaultInlineReveal: 'masked',
});

const policy = (target: Policy['target'], action: Policy['action']): Policy => ({
  id: randomUUID(),
  scope: 'global',
  target,
  action,
  enabled: true,
});

const bundleOf = (
  policies: Policy[],
  version: string,
  rules: PolicyBundle['rules'] = [],
): PolicyBundle => ({
  version,
  policies,
  rules,
  customKeywords: [],
  fetchedAt: '2026-01-01T00:00:00.000Z',
});

function makeLocalStore(bundle: PolicyBundle): DataGateway & LocalStoreMaintenance {
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
    getPolicyBundle: () => Promise.resolve(bundle),
    consumeException: () => Promise.resolve(false),
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
  dir = mkdtempSync(join(tmpdir(), 'aka-attached-policy-e2e-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function buildRuntime(localPolicies: Policy[], remotePolicies: Policy[]) {
  const gateway = new AttachedDataGateway({
    dataDir: dir,
    local: makeLocalStore(bundleOf(localPolicies, 'local', [MARKER_RULE])),
    client: noopClient(),
    readCachedBundle: () => Promise.resolve(bundleOf(remotePolicies, 'tenant')),
    forward: passthrough(),
  });
  return { gateway, runtime: createPluginRuntime(gateway, settings(), { dataDir: dir }) };
}

describe('the composed bundle, resolved by the real runtime', () => {
  it('a tenant ruleId ALLOW cannot switch off a local category BLOCK', async () => {
    const { gateway, runtime } = buildRuntime(
      [policy({ category: 'secret' }, 'block')],
      [policy({ ruleId: RULE_ID }, 'allow')],
    );

    // The array itself is the reason a unit assertion misses this: two policies
    // on two keys, neither obviously wrong, nothing dropped.
    const merged = await gateway.getPolicyBundle();
    expect(merged.policies).toHaveLength(2);

    const result = await runtime.processText(MARKER);
    await runtime.close();
    // Unclamped, the rule index answers 'allow' and the device stops blocking
    // secrets — from a bundle read off disk with no signature or provenance
    // check.
    expect(result.action).toBe('block');
  });

  it('the same tenant policy still RAISES enforcement where it is stronger', async () => {
    // The positive control. Without it the test above would pass against a
    // clamp that simply ignored tenant ruleId policies altogether, which would
    // break the feature rather than secure it.
    const { runtime } = buildRuntime(
      [policy({ category: 'secret' }, 'warn')],
      [policy({ ruleId: RULE_ID }, 'block')],
    );
    const result = await runtime.processText(MARKER);
    await runtime.close();
    expect(result.action).toBe('block');
  });

  it('with no local policy at all, the tenant policy resolves as sent', async () => {
    // The second control: the clamp must not invent enforcement the device
    // never had. 'warn' is the compiled-in floor for `secret`, which the tenant
    // policy already meets, so it passes through untouched.
    const { runtime } = buildRuntime([], [policy({ ruleId: RULE_ID }, 'warn')]);
    const result = await runtime.processText(MARKER);
    await runtime.close();
    expect(result.action).toBe('warn');
  });
});
