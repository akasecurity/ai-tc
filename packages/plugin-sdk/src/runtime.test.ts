import type { PolicyBundle, Rule, WorkspaceSettings } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { CaptureRecord, DataGateway } from './data-gateway.ts';
import { registerRulePack } from './rule-packs.ts';
import { createPluginRuntime } from './runtime.ts';

// Markers resolved by DEFAULT_ACTIONS (secret: block, pii: redact) when the
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
    readSessionProvider: () => Promise.resolve(undefined),
    facets: () => Promise.resolve({ hosts: [], harnesses: [], osVersions: [], projects: [] }),
    getPolicyBundle: () => Promise.resolve(b),
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

  it('blocks secrets by default', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    const result = await rt.processText('deploy with SECRET_MARKER now');
    expect(result.action).toBe('block');
    expect(result.text).toBeNull();
    expect(result.findings.map((f) => f.ruleId)).toContain('test/secret-marker');
    await rt.close();
  });

  it('redacts PII by default', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings());
    expect(await rt.processText('contact PII_MARKER please')).toMatchObject({
      action: 'redact',
      text: 'contact [REDACTED:PII] please',
    });
    await rt.close();
  });

  it('warn mode downgrades block/redact to warn and leaves text intact', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle()), settings('warn'));
    expect(await rt.processText('deploy with SECRET_MARKER now')).toMatchObject({
      action: 'warn',
      text: 'deploy with SECRET_MARKER now',
    });
    await rt.close();
  });
});

describe('rules pull', () => {
  it('detects with rules pulled from the bundle (not just bundled packs)', async () => {
    const rt = createPluginRuntime(fakeGateway(bundle([PULLED_RULE])), settings());
    const result = await rt.processText('ship PULLED_MARKER today');
    expect(result.action).toBe('block');
    expect(result.findings.map((f) => f.ruleId)).toContain('pulled/secret-marker');
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
    expect(result.action).toBe('block');
    await rt.close();

    expect(gw.records).toHaveLength(1);
    const record = gw.records[0];
    expect(record?.findings).toHaveLength(1);
    expect(record?.findings[0]?.ruleId).toBe('test/secret-marker');
    expect(record?.findings[0]?.actionTaken).toBe('block');
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
