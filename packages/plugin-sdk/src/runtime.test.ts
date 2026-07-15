import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { PolicyBundle, Rule, WorkspaceSettings } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { CaptureRecord, DataGateway } from './data-gateway.ts';
import { registerRulePack } from './rule-packs.ts';
import { createPluginRuntime } from './runtime.ts';

// Markers resolved by DEFAULT_ACTIONS (secret: warn, pii: warn) when the
// bundle carries no explicit policy. Registered into the global bundled packs.
registerRulePack('test-pack', [
  {
    specVersion: 1,
    id: 'test/secret-marker',
    name: 'Test secret marker',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'keyword', keywords: ['SECRET_MARKER'] },
    examples: ['SECRET_MARKER'],
  },
  {
    specVersion: 1,
    id: 'test/pii-marker',
    name: 'Test PII marker',
    category: 'pii',
    severity: 'medium',
    matcher: { type: 'keyword', keywords: ['PII_MARKER'] },
    examples: ['PII_MARKER'],
  },
]);

// A rule that exists ONLY in a pulled bundle (not in the bundled packs), used to
// prove getPolicyBundle().rules are registered into the engine.
const PULLED_RULE: Rule = {
  specVersion: 1,
  id: 'pulled/secret-marker',
  name: 'Pulled secret marker',
  category: 'secret',
  severity: 'critical',
  matcher: { type: 'keyword', keywords: ['PULLED_MARKER'], caseSensitive: false },
  examples: ['PULLED_MARKER'],
};

function settings(policy: 'redact' | 'warn' = 'redact'): WorkspaceSettings {
  return { specVersion: 1, runMode: 'standalone', policy, historicalAccess: 'session-only' };
}

function bundle(rules: Rule[] = []): PolicyBundle {
  return {
    version: 'test',
    policies: [],
    rules,
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
  };
}

// A fake gateway: returns a fixed bundle and records every recordCapture call.
function fakeGateway(b: PolicyBundle): DataGateway & { records: CaptureRecord[] } {
  const records: CaptureRecord[] = [];
  return {
    records,
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
    openAtRestKeysForPath: () => Promise.resolve([]),
    resolvedAtRestKeysForPath: () => Promise.resolve([]),
    insertResolution: () => Promise.resolve(),
    close: () => Promise.resolve(),
  };
}

describe('createPluginRuntime — decisions from the pulled bundle (DEFAULT_ACTIONS fallback)', () => {
  it('passes benign text through as log', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    expect(await rt.processText('nothing to see here')).toMatchObject({
      action: 'log',
      text: 'nothing to see here',
    });
    await rt.close();
  });

  it('warns on secrets by default (severity-floor cold start)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    const result = await rt.processText('deploy with SECRET_MARKER now');
    expect(result.action).toBe('warn');
    expect(result.text).toBe('deploy with SECRET_MARKER now');
    expect(result.findings.map((f) => f.ruleId)).toContain('test/secret-marker');
    await rt.close();
  });

  it('warns on PII by default (severity-floor cold start)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    expect(await rt.processText('contact PII_MARKER please')).toMatchObject({
      action: 'warn',
      text: 'contact PII_MARKER please',
    });
    await rt.close();
  });

  it('warn mode downgrades block/redact to warn and leaves text intact', async () => {
    const rt = createPluginRuntime(
      fakeGateway({
        ...bundle(),
        policies: [
          {
            id: randomUUID(),
            scope: 'global',
            target: { category: 'secret' },
            action: 'block',
            enabled: true,
          },
        ],
      }),
      settings('warn'),
    );
    expect(await rt.processText('deploy with SECRET_MARKER now')).toMatchObject({
      action: 'warn',
      text: 'deploy with SECRET_MARKER now',
    });
    await rt.close();
  });
});

// A ruleId-targeted policy is how the standalone gateway carries a detection's
// per-detection Monitor/Warn/Redact/Block assignment (installed_packs.policy_id)
// into enforcement. It must win over both the category default and an explicit
// category policy — otherwise "set this detection to Monitor" never takes effect.
describe('createPluginRuntime — per-detection (ruleId-targeted) policies', () => {
  function bundleWithPolicies(policies: PolicyBundle['policies']): PolicyBundle {
    return { ...bundle(), policies };
  }

  it('downgrades a would-be block to log when the rule is set to Monitor', async () => {
    const rt = createPluginRuntime(
      fakeGateway(
        bundleWithPolicies([
          {
            id: '11111111-1111-4111-8111-111111111111',
            scope: 'global',
            target: { ruleId: 'test/secret-marker' },
            action: 'log',
            enabled: true,
          },
        ]),
      ),
      settings(),
    );
    // Without the ruleId policy this secret would warn (DEFAULT_ACTIONS); the
    // Monitor assignment takes it down to log.
    expect(await rt.processText('deploy with SECRET_MARKER now')).toMatchObject({
      action: 'log',
      text: 'deploy with SECRET_MARKER now',
    });
    await rt.close();
  });

  it('a ruleId policy beats an explicit category policy for the same category', async () => {
    const rt = createPluginRuntime(
      fakeGateway(
        bundleWithPolicies([
          {
            id: '22222222-2222-4222-8222-222222222222',
            scope: 'global',
            target: { category: 'secret' },
            action: 'block',
            enabled: true,
          },
          {
            id: '33333333-3333-4333-8333-333333333333',
            scope: 'global',
            target: { ruleId: 'test/secret-marker' },
            action: 'log',
            enabled: true,
          },
        ]),
      ),
      settings(),
    );
    expect((await rt.processText('deploy with SECRET_MARKER now')).action).toBe('log');
    await rt.close();
  });

  it('falls back to the category default when the ruleId policy is disabled', async () => {
    const rt = createPluginRuntime(
      fakeGateway(
        bundleWithPolicies([
          {
            id: '44444444-4444-4444-8444-444444444444',
            scope: 'global',
            target: { ruleId: 'test/secret-marker' },
            action: 'log',
            enabled: false,
          },
        ]),
      ),
      settings(),
    );
    // Disabled → ignored → secret warns via DEFAULT_ACTIONS.
    expect((await rt.processText('deploy with SECRET_MARKER now')).action).toBe('warn');
    await rt.close();
  });

  it('collapses mixed Block + Monitor detections in one input to the worst action (block)', async () => {
    const rt = createPluginRuntime(
      fakeGateway(
        bundleWithPolicies([
          {
            id: '55555555-5555-4555-8555-555555555555',
            scope: 'global',
            target: { ruleId: 'test/secret-marker' },
            action: 'block',
            enabled: true,
          },
          {
            id: '66666666-6666-4666-8666-666666666666',
            scope: 'global',
            target: { ruleId: 'test/pii-marker' },
            action: 'log',
            enabled: true,
          },
        ]),
      ),
      settings(),
    );
    // One input trips both a Block detection and a Monitor detection → block wins.
    const result = await rt.processText('SECRET_MARKER and PII_MARKER together');
    expect(result.action).toBe('block');
    expect(result.text).toBeNull();
    await rt.close();
  });
});

describe('rules pull', () => {
  it('detects with rules pulled from the bundle (not just bundled packs)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle([PULLED_RULE])), settings());
    const result = await rt.processText('ship PULLED_MARKER today');
    expect(result.action).toBe('warn');
    expect(result.findings.map((f) => f.ruleId)).toContain('pulled/secret-marker');
    await rt.close();
  });
});

describe('rulesComplete — the bundle rules replace the compiled-in packs', () => {
  it('scans ONLY the bundle rules when the bundle marks them complete', async () => {
    const complete = { ...bundle([PULLED_RULE]), rulesComplete: true };
    const rt = createPluginRuntime(fakeGateway(complete), settings());
    // The bundled test-pack marker is NOT in the complete ruleset → passes through.
    expect(await rt.processText('deploy with SECRET_MARKER now')).toMatchObject({
      action: 'log',
      text: 'deploy with SECRET_MARKER now',
    });
    // The snapshot rule still detects.
    const result = await rt.processText('ship PULLED_MARKER today');
    expect(result.action).toBe('warn');
    expect(result.findings.map((f) => f.ruleId)).toContain('pulled/secret-marker');
    await rt.close();
  });

  it('respects a complete-and-empty ruleset (user disabled every pack)', async () => {
    const rt = createPluginRuntime(fakeGateway({ ...bundle([]), rulesComplete: true }), settings());
    expect(await rt.processText('deploy with SECRET_MARKER now')).toMatchObject({
      action: 'log',
      text: 'deploy with SECRET_MARKER now',
    });
    await rt.close();
  });

  it('keeps bundled packs when rulesComplete is absent (historical composition)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle([])), settings());
    const result = await rt.processText('deploy with SECRET_MARKER now');
    expect(result.action).toBe('warn');
    await rt.close();
  });
});

describe('capture', () => {
  it('records the event + masked findings and returns the same decision', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    const result = await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'deploy with SECRET_MARKER now',
    });
    expect(result.action).toBe('warn');
    await rt.close();

    expect(gw.records).toHaveLength(1);
    const record = gw.records[0];
    expect(record?.findings).toHaveLength(1);
    expect(record?.findings[0]?.ruleId).toBe('test/secret-marker');
    expect(record?.findings[0]?.actionTaken).toBe('warn');
    // The raw secret is masked before it reaches the gateway.
    expect(record?.findings[0]?.maskedMatch).not.toContain('SECRET_MARKER');
    // Stored content has the secret masked; content_hash is of the original.
    expect(record?.event.content).not.toContain('SECRET_MARKER');
    expect(record?.event.content).toContain('[REDACTED:SECRET]');
  });

  it('stamps the supplied occurredAt on the event (historical backfill)', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    const occurredAt = '2026-05-01T09:00:00.000Z';
    await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'SECRET_MARKER',
      occurredAt,
    });
    await rt.close();
    expect(gw.records[0]?.event.occurredAt).toBe(occurredAt);
  });

  it("persist 'with-findings' skips benign text but records hits", async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture(
      { kind: 'prompt', sourceTool: 'claude-code', text: 'nothing here' },
      {
        persist: 'with-findings',
      },
    );
    expect(gw.records).toHaveLength(0); // benign → nothing stored
    await rt.capture(
      { kind: 'prompt', sourceTool: 'claude-code', text: 'SECRET_MARKER' },
      {
        persist: 'with-findings',
      },
    );
    expect(gw.records).toHaveLength(1); // a hit → recorded
    await rt.close();
  });
});

describe('rulesetFingerprint', () => {
  it('is stable across runtimes over the same effective ruleset', async () => {
    const rt1 = createPluginRuntime(fakeGateway(bundle()), settings());
    const rt2 = createPluginRuntime(fakeGateway(bundle()), settings());
    expect(await rt1.rulesetFingerprint()).toBe(await rt2.rulesetFingerprint());
    await rt1.close();
    await rt2.close();
  });

  it('changes when the pulled bundle adds a rule', async () => {
    const without = createPluginRuntime(fakeGateway(bundle()), settings());
    const withPulled = createPluginRuntime(fakeGateway(bundle([PULLED_RULE])), settings());
    expect(await without.rulesetFingerprint()).not.toBe(await withPulled.rulesetFingerprint());
    await without.close();
    await withPulled.close();
  });

  it('returns a non-reusable nonce when the bundle pull fails (fail toward rescan)', async () => {
    const broken: DataGateway = {
      ...fakeGateway(bundle()),
      getPolicyBundle: () => Promise.reject(new Error('offline')),
    };
    const rt = createPluginRuntime(broken, settings());
    const first = await rt.rulesetFingerprint();
    expect(first).toMatch(/^unresolved-/);
    await rt.close();
  });
});

describe('capture — dedupe threading', () => {
  it("threads dedupe: 'content-hash' through to the gateway record", async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture(
      { kind: 'code_change', sourceTool: 'claude-code', text: 'SECRET_MARKER' },
      { persist: 'with-findings', dedupe: 'content-hash' },
    );
    expect(gw.records[0]?.dedupe).toBe('content-hash');
    await rt.close();
  });

  it('leaves dedupe unset on the live hook path', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({ kind: 'prompt', sourceTool: 'claude-code', text: 'SECRET_MARKER' });
    expect(gw.records[0]?.dedupe).toBeUndefined();
    await rt.close();
  });
});

describe('capture — appliesTo file-context threading', () => {
  // A Python-only rule delivered via the pulled bundle, so this test does not
  // pollute the global bundled packs shared by other tests.
  const pyOnlyRule: Rule = {
    specVersion: 1,
    id: 'pulled/py-only-marker',
    name: 'Python-only marker',
    category: 'code_flaw',
    severity: 'high',
    matcher: { type: 'keyword', keywords: ['PY_ONLY_MARKER'], caseSensitive: false },
    appliesTo: { extensions: ['.py'] },
    examples: ['PY_ONLY_MARKER'],
  };

  it('gates a scoped rule by the capture metadata filePath', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle([pyOnlyRule])), settings());
    const tsResult = await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'PY_ONLY_MARKER',
      metadata: { filePath: '/repo/src/app.ts' },
    });
    expect(tsResult.findings.map((f) => f.ruleId)).not.toContain('pulled/py-only-marker');

    const pyResult = await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'PY_ONLY_MARKER',
      metadata: { filePath: '/repo/src/app.py' },
    });
    expect(pyResult.findings.map((f) => f.ruleId)).toContain('pulled/py-only-marker');
    await rt.close();
  });

  it('runs scoped rules when no file context exists (prompt path)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle([pyOnlyRule])), settings());
    const result = await rt.processText('PY_ONLY_MARKER');
    expect(result.findings.map((f) => f.ruleId)).toContain('pulled/py-only-marker');
    await rt.close();
  });
});

describe('capture — at-rest finding_key', () => {
  it('is stable across two captures of the same rule/path/value (re-scan reconciliation)', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'aka-runtime-fk-'));
    try {
      const gw1 = fakeGateway(bundle());
      const rt1 = createPluginRuntime(gw1, settings(), { dataDir });
      await rt1.capture({
        kind: 'code_change',
        sourceTool: 'claude-code',
        text: 'deploy with SECRET_MARKER now',
        metadata: { filePath: '/repo/src/a.ts' },
      });
      await rt1.close();

      // A second scan (fresh runtime instance — a hook is short-lived — but the
      // SAME dataDir, so the same on-disk fingerprint key is read back).
      const gw2 = fakeGateway(bundle());
      const rt2 = createPluginRuntime(gw2, settings(), { dataDir });
      await rt2.capture({
        kind: 'code_change',
        sourceTool: 'claude-code',
        text: 'deploy with SECRET_MARKER now',
        metadata: { filePath: '/repo/src/a.ts' },
      });
      await rt2.close();

      const key1 = gw1.records[0]?.findings[0]?.findingKey;
      const key2 = gw2.records[0]?.findings[0]?.findingKey;
      expect(key1).toMatch(/^[0-9a-f]{64}$/);
      expect(key1).toBe(key2);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it('changes when the file path changes (same rule/value, different location)', async () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'aka-runtime-fk-'));
    try {
      const gw = fakeGateway(bundle());
      const rt = createPluginRuntime(gw, settings(), { dataDir });
      await rt.capture({
        kind: 'code_change',
        sourceTool: 'claude-code',
        text: 'deploy with SECRET_MARKER now',
        metadata: { filePath: '/repo/src/a.ts' },
      });
      await rt.capture({
        kind: 'code_change',
        sourceTool: 'claude-code',
        text: 'deploy with SECRET_MARKER now',
        metadata: { filePath: '/repo/src/b.ts' },
      });
      await rt.close();

      const keyA = gw.records[0]?.findings[0]?.findingKey;
      const keyB = gw.records[1]?.findings[0]?.findingKey;
      expect(keyA).toBeDefined();
      expect(keyA).not.toBe(keyB);
    } finally {
      rmSync(dataDir, { recursive: true, force: true });
    }
  });

  it('never attaches a finding_key to in-flight (prompt) findings', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'deploy with SECRET_MARKER now',
    });
    await rt.close();
    expect(gw.records[0]?.findings[0]?.findingKey).toBeUndefined();
  });

  it('falls back to the masked match when no fingerprint key is available (no dataDir)', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings()); // no dataDir → keyForLedger() is null
    await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'deploy with SECRET_MARKER now',
      metadata: { filePath: '/repo/src/a.ts' },
    });
    await rt.close();
    expect(gw.records[0]?.findings[0]?.findingKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it('gives two distinct secrets in the same file two distinct finding_keys', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'SECRET_MARKER and PII_MARKER both here',
      metadata: { filePath: '/repo/src/a.ts' },
    });
    await rt.close();

    const keys = gw.records[0]?.findings.map((f) => f.findingKey) ?? [];
    expect(keys).toHaveLength(2);
    expect(new Set(keys).size).toBe(2);
  });
});

describe('capture() — CaptureResult.findingKeys (scanner re-scan resolver hook)', () => {
  it('echoes the at-rest finding_keys produced onto the returned decision', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    const result = await rt.capture({
      kind: 'code_change',
      sourceTool: 'claude-code',
      text: 'SECRET_MARKER and PII_MARKER both here',
      metadata: { filePath: '/repo/src/a.ts' },
    });
    await rt.close();

    const recordedKeys = gw.records[0]?.findings.map((f) => f.findingKey) ?? [];
    expect(result.findingKeys).toHaveLength(2);
    expect(result.findingKeys).toEqual(recordedKeys);
  });

  it('leaves findingKeys unset for in-flight (prompt) captures — nothing to correlate against', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    const result = await rt.capture(
      { kind: 'prompt', sourceTool: 'claude-code', text: 'deploy with SECRET_MARKER now' },
      { persist: 'always' },
    );
    await rt.close();
    expect(result.findingKeys).toBeUndefined();
  });

  it('leaves findingKeys unset when the with-findings short-circuit returns before persisting', async () => {
    const gw = fakeGateway(bundle());
    const rt = createPluginRuntime(gw, settings());
    const result = await rt.capture(
      {
        kind: 'code_change',
        sourceTool: 'claude-code',
        text: 'nothing sensitive here',
        metadata: { filePath: '/repo/src/a.ts' },
      },
      { persist: 'with-findings' },
    );
    await rt.close();
    expect(result.findingKeys).toBeUndefined();
    expect(gw.records).toHaveLength(0);
  });
});
