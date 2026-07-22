import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { BlockedDetectionInput } from '@akasecurity/persistence';
import type {
  EventMetadata,
  ExceptionBundleEntry,
  PolicyBundle,
  WorkspaceSettings,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { CaptureRecord, DataGateway } from '../src/data-gateway.ts';
import { fingerprintValue, loadOrCreateFingerprintKey } from '../src/fingerprint.ts';
import { registerRulePack } from '../src/rule-packs.ts';
import { createPluginRuntime } from '../src/runtime.ts';

// The cold-start floor no longer resolves a bare category to block/redact, so
// tests that need to exercise exception-consumption or the blocked-detections
// ledger inject an explicit enforcing Policy per test, targeting these markers'
// ruleIds. Unique to this file so they never collide with other suites' packs
// or with the real bundled rules.
registerRulePack('exception-test-pack', [
  {
    specVersion: 1,
    id: 'ex/secret-marker',
    name: 'Exception-test secret marker',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'keyword', keywords: ['EX_SECRET_MARKER'] },
    examples: ['EX_SECRET_MARKER'],
  },
  {
    specVersion: 1,
    id: 'ex/pii-marker',
    name: 'Exception-test PII marker',
    category: 'pii',
    severity: 'medium',
    matcher: { type: 'keyword', keywords: ['EX_PII_MARKER'] },
    examples: ['EX_PII_MARKER'],
  },
]);

function settings(policy: 'redact' | 'warn' = 'redact'): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy,
    historicalAccess: 'full',
    dataSharesInPlace: true,
  };
}

function bundle(exceptions?: ExceptionBundleEntry[]): PolicyBundle {
  return {
    version: 'test',
    policies: [],
    rules: [],
    ...(exceptions ? { exceptions } : {}),
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
  };
}

function entry(overrides: Partial<ExceptionBundleEntry> & { valueFingerprint: string }) {
  return {
    id: randomUUID(),
    ruleId: 'ex/secret-marker',
    keyVersion: 1,
    expiresAt: null,
    maxUses: null,
    useCount: 0,
    conditions: null,
    ...overrides,
  } satisfies ExceptionBundleEntry;
}

interface FakeGateway extends DataGateway {
  records: CaptureRecord[];
  consumed: string[];
  blocked: BlockedDetectionInput[];
}

function fakeGateway(
  b: PolicyBundle,
  opts?: {
    consume?: (id: string) => Promise<boolean>;
    recordBlocked?: (entry: BlockedDetectionInput) => Promise<void>;
  },
): FakeGateway {
  const records: CaptureRecord[] = [];
  const consumed: string[] = [];
  const blocked: BlockedDetectionInput[] = [];
  return {
    records,
    consumed,
    blocked,
    recordCapture: (record) => {
      records.push(record);
      return Promise.resolve();
    },
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
    getPolicyBundle: () => Promise.resolve(b),
    consumeException: (id) => {
      consumed.push(id);
      return opts?.consume ? opts.consume(id) : Promise.resolve(true);
    },
    recordBlockedDetection: (e) => {
      if (opts?.recordBlocked) return opts.recordBlocked(e);
      blocked.push(e);
      return Promise.resolve();
    },
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
    openAtRestKeysForPath: () => Promise.resolve([]),
    resolvedAtRestKeysForPath: () => Promise.resolve([]),
    insertResolution: () => Promise.resolve(),
    recordProjectEgress: () => Promise.resolve(),
    close: () => Promise.resolve(),
  };
}

function exceptionIdsOf(record: CaptureRecord | undefined): string[] | undefined {
  return (record?.event.metadata as (EventMetadata & { exceptionIds?: string[] }) | undefined)
    ?.exceptionIds;
}

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-runtime-ex-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('exception evaluation — downgrade to allow', () => {
  it('downgrades a matched block to allow, stamps metadata.exceptionIds, records the finding as allow', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const ex = entry({ valueFingerprint: fingerprintValue(key, 'EX_SECRET_MARKER') });
    const b = bundle([ex]);
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const text = 'deploy with EX_SECRET_MARKER now';
    const result = await rt.capture({ kind: 'prompt', sourceTool: 'claude-code', text });
    await rt.close();

    // No remaining enforced findings → the benign default decision.
    expect(result.action).toBe('log');
    expect(result.text).toBe(text);
    expect(gw.consumed).toEqual([ex.id]);
    // The finding is still recorded — as 'allow' — and the event carries the id.
    expect(gw.records).toHaveLength(1);
    expect(gw.records[0]?.findings[0]?.actionTaken).toBe('allow');
    expect(exceptionIdsOf(gw.records[0])).toEqual([ex.id]);
    // Stored content still masks the excepted span (at-rest hygiene unchanged).
    expect(gw.records[0]?.event.content).not.toContain('EX_SECRET_MARKER');
    // Nothing was blocked → no ledger rows.
    expect(gw.blocked).toHaveLength(0);
    expect(result.blockedReferences).toBeUndefined();
  });

  it('does NOT consume an active grant when the detection is Monitor (log-only)', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const ex = entry({ valueFingerprint: fingerprintValue(key, 'EX_SECRET_MARKER') });
    const b = bundle([ex]);
    // The secret detection is set to Monitor: its findings resolve to 'log', never
    // block/redact, so there is no enforcement for the grant to bypass — and its
    // use budget must be preserved (nothing to consume).
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'log',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const result = await rt.processText('deploy with EX_SECRET_MARKER now');
    await rt.close();

    expect(result.action).toBe('log');
    expect(gw.consumed).toEqual([]);
  });

  it('mixed capture: the excepted value passes while an unexcepted finding still enforces', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const ex = entry({ valueFingerprint: fingerprintValue(key, 'EX_SECRET_MARKER') });
    const b = bundle([ex]);
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/pii-marker' },
        action: 'redact',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const result = await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'send EX_SECRET_MARKER and EX_PII_MARKER',
    });
    await rt.close();

    // The PII finding still redacts; the excepted secret passes through intact.
    expect(result.action).toBe('redact');
    expect(result.text).toContain('EX_SECRET_MARKER');
    expect(result.text).not.toContain('EX_PII_MARKER');
    const byRule = new Map(gw.records[0]?.findings.map((f) => [f.ruleId, f.actionTaken] as const));
    expect(byRule.get('ex/secret-marker')).toBe('allow');
    expect(byRule.get('ex/pii-marker')).toBe('redact');
    // The still-enforced pair lands in the blocked-detections ledger.
    expect(gw.blocked).toHaveLength(1);
    expect(gw.blocked[0]?.ruleId).toBe('ex/pii-marker');
    expect(result.blockedReferences).toEqual([
      {
        reference: gw.blocked[0]?.reference,
        ruleId: gw.blocked[0]?.ruleId,
        maskedValue: gw.blocked[0]?.maskedValue,
      },
    ]);
  });

  it('consumes once per unique (rule, value) pair and downgrades every span', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const ex = entry({ valueFingerprint: fingerprintValue(key, 'EX_SECRET_MARKER') });
    const b = bundle([ex]);
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const result = await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'EX_SECRET_MARKER twice: EX_SECRET_MARKER',
    });
    await rt.close();

    expect(gw.consumed).toHaveLength(1);
    expect(result.action).toBe('log');
    expect(result.findings).toHaveLength(2);
    expect(gw.records[0]?.findings.every((f) => f.actionTaken === 'allow')).toBe(true);
  });
});

describe('exception evaluation — fail secure', () => {
  it('still blocks when consume returns false', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const ex = entry({ valueFingerprint: fingerprintValue(key, 'EX_SECRET_MARKER') });
    const b = bundle([ex]);
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b, { consume: () => Promise.resolve(false) });
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const result = await rt.processText('EX_SECRET_MARKER');
    await rt.close();
    expect(result.action).toBe('block');
    expect(result.text).toBeNull();
  });

  it('still blocks when consume throws', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const ex = entry({ valueFingerprint: fingerprintValue(key, 'EX_SECRET_MARKER') });
    const b = bundle([ex]);
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b, { consume: () => Promise.reject(new Error('locked')) });
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const result = await rt.processText('EX_SECRET_MARKER');
    await rt.close();
    expect(result.action).toBe('block');
  });

  it('never matches an entry written under a different key version', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const ex = entry({
      valueFingerprint: fingerprintValue(key, 'EX_SECRET_MARKER'),
      keyVersion: key.version + 1,
    });
    const b = bundle([ex]);
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    expect((await rt.processText('EX_SECRET_MARKER')).action).toBe('block');
    expect(gw.consumed).toHaveLength(0);
    await rt.close();
  });

  it('never matches an expired entry or an exhausted use budget', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const fp = fingerprintValue(key, 'EX_SECRET_MARKER');
    const secretBlockPolicy = {
      id: randomUUID(),
      scope: 'global' as const,
      target: { ruleId: 'ex/secret-marker' },
      action: 'block' as const,
      enabled: true,
    };
    const expired = entry({
      valueFingerprint: fp,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    });
    const bExpired = bundle([expired]);
    bExpired.policies = [secretBlockPolicy];
    const gwExpired = fakeGateway(bExpired);
    const rtExpired = createPluginRuntime(gwExpired, settings(), { dataDir: dir });
    expect((await rtExpired.processText('EX_SECRET_MARKER')).action).toBe('block');
    expect(gwExpired.consumed).toHaveLength(0);
    await rtExpired.close();

    const exhausted = entry({ valueFingerprint: fp, maxUses: 1, useCount: 1 });
    const bExhausted = bundle([exhausted]);
    bExhausted.policies = [secretBlockPolicy];
    const gwExhausted = fakeGateway(bExhausted);
    const rtExhausted = createPluginRuntime(gwExhausted, settings(), { dataDir: dir });
    expect((await rtExhausted.processText('EX_SECRET_MARKER')).action).toBe('block');
    expect(gwExhausted.consumed).toHaveLength(0);
    await rtExhausted.close();
  });

  it('skips evaluation entirely without a dataDir', async () => {
    const ex = entry({ valueFingerprint: 'irrelevant' });
    const b = bundle([ex]);
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings());
    expect((await rt.processText('EX_SECRET_MARKER')).action).toBe('block');
    expect(gw.consumed).toHaveLength(0);
    await rt.close();
  });
});

describe('exception evaluation — conditions', () => {
  it('applies when conditions.repo matches the capture metadata', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const ex = entry({
      valueFingerprint: fingerprintValue(key, 'EX_SECRET_MARKER'),
      conditions: { repo: 'org/payments' },
    });
    const b = bundle([ex]);
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const result = await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'EX_SECRET_MARKER',
      metadata: { repo: 'org/payments' },
    });
    await rt.close();
    expect(result.action).toBe('log');
    expect(gw.consumed).toEqual([ex.id]);
  });

  it('never matches on a repo mismatch, or when the condition has no capture fact', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const ex = entry({
      valueFingerprint: fingerprintValue(key, 'EX_SECRET_MARKER'),
      conditions: { repo: 'org/payments' },
    });
    const b = bundle([ex]);
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const mismatch = await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'EX_SECRET_MARKER',
      metadata: { repo: 'org/other' },
    });
    expect(mismatch.action).toBe('block');

    // Condition present but no metadata at all (e.g. the processText path):
    // an absent fact never satisfies a narrowing — NO match.
    const noFact = await rt.processText('EX_SECRET_MARKER');
    expect(noFact.action).toBe('block');
    expect(gw.consumed).toHaveLength(0);
    await rt.close();
  });
});

describe('no exceptions in the bundle — behavior unchanged, zero footprint', () => {
  it('a benign capture creates no key file — zero footprint until enforcement fires', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    expect((await rt.processText('nothing to see here')).action).toBe('log');
    await rt.close();

    // Nothing was enforced and no grants rode the bundle: no fingerprint work,
    // no ledger rows, and — decisive for upgrade footprint — no key file.
    expect(existsSync(join(dir, 'exception.key'))).toBe(false);
    expect(gw.consumed).toHaveLength(0);
    expect(gw.blocked).toHaveLength(0);
  });

  it('the first block mints the key so its ledger row is approvable', async () => {
    const b = bundle();
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const blocked = await rt.processText('EX_SECRET_MARKER');
    await rt.close();

    expect(blocked.action).toBe('block');
    expect(blocked.text).toBeNull();
    // The block is the moment the exception feature becomes relevant: the key
    // now exists, the ledger row was written under it, and the returned ref
    // carries the SAME masked preview as the ledger row.
    expect(existsSync(join(dir, 'exception.key'))).toBe(true);
    expect(gw.consumed).toHaveLength(0);
    expect(gw.blocked).toHaveLength(1);
    expect(blocked.blockedReferences?.[0]?.reference).toBe(gw.blocked[0]?.reference);
    expect(blocked.blockedReferences?.[0]?.maskedValue).toBe(gw.blocked[0]?.maskedValue);
  });
});

describe('blocked-detections ledger', () => {
  it('capture: a block records one ledger row per unique pair and returns its reference', async () => {
    const key = loadOrCreateFingerprintKey(dir); // key exists → ledger active
    const b = bundle();
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const result = await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'EX_SECRET_MARKER twice: EX_SECRET_MARKER',
      metadata: { sessionId: 'sess-1', repo: 'org/payments' },
    });
    await rt.close();

    expect(result.action).toBe('block');
    // Same value twice → ONE row.
    expect(gw.blocked).toHaveLength(1);
    const row = gw.blocked[0];
    expect(row?.ruleId).toBe('ex/secret-marker');
    expect(row?.category).toBe('secret');
    expect(row?.valueFingerprint).toBe(fingerprintValue(key, 'EX_SECRET_MARKER'));
    expect(row?.keyVersion).toBe(key.version);
    expect(row?.maskedValue).not.toContain('EX_SECRET_MARKER');
    expect(row?.sessionId).toBe('sess-1');
    expect(row?.repo).toBe('org/payments');
    expect(row?.reference).toMatch(/^[0-9a-f]{6}$/);
    expect(result.blockedReferences).toEqual([
      { reference: row?.reference, ruleId: row?.ruleId, maskedValue: row?.maskedValue },
    ]);
  });

  it('processText: a block records a ledger row too (no event write, null provenance)', async () => {
    loadOrCreateFingerprintKey(dir);
    const b = bundle();
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const result = await rt.processText('run with EX_SECRET_MARKER');
    await rt.close();

    expect(result.action).toBe('block');
    expect(gw.records).toHaveLength(0); // processText never writes an event
    expect(gw.blocked).toHaveLength(1);
    expect(gw.blocked[0]?.sessionId).toBeNull();
    expect(gw.blocked[0]?.repo).toBeNull();
    expect(result.blockedReferences).toEqual([
      {
        reference: gw.blocked[0]?.reference,
        ruleId: gw.blocked[0]?.ruleId,
        maskedValue: gw.blocked[0]?.maskedValue,
      },
    ]);
  });

  it('a failing ledger write never affects the decision', async () => {
    loadOrCreateFingerprintKey(dir);
    const b = bundle();
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b, {
      recordBlocked: () => Promise.reject(new Error('disk full')),
    });
    const rt = createPluginRuntime(gw, settings(), { dataDir: dir });

    const result = await rt.processText('EX_SECRET_MARKER');
    await rt.close();
    expect(result.action).toBe('block');
    expect(result.blockedReferences).toBeUndefined();
  });
});

describe('exception evaluation under settings.policy warn', () => {
  it('still evaluates and consumes an active grant (the global ceiling no longer short-circuits it)', async () => {
    const key = loadOrCreateFingerprintKey(dir);
    const ex = entry({ valueFingerprint: fingerprintValue(key, 'EX_SECRET_MARKER') });
    const b = bundle([ex]);
    b.policies = [
      {
        id: randomUUID(),
        scope: 'global',
        target: { ruleId: 'ex/secret-marker' },
        action: 'block',
        enabled: true,
      },
    ];
    const gw = fakeGateway(b);
    const rt = createPluginRuntime(gw, settings('warn'), { dataDir: dir });

    const result = await rt.processText('deploy with EX_SECRET_MARKER now');
    await rt.close();

    expect(gw.consumed).toEqual([ex.id]);
    expect(result.action).toBe('log');
  });
});
