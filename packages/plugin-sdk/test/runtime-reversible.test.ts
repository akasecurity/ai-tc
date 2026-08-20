import { randomUUID } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { MatchResult } from '@akasecurity/detections';
import type { PolicyBundle, WorkspaceSettings } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { DataGateway } from '../src/data-gateway.ts';
import { registerRulePack } from '../src/rule-packs.ts';
import { createPluginRuntime } from '../src/runtime.ts';

// Redact & Vault is a SECOND AXIS over the `redact` action, not a fifth action:
// two detections can both be redacting while only one keeps a recoverable copy.
// This file is about that split surviving the trip from the policy bundle to the
// CaptureResult, because everything downstream — which spans become pointers and
// which are destroyed — reads it and nothing else can recompute it.
//
// It exists because the filter that performs the split was, on arrival,
// invisible: replacing it with `redactFindings` (vault everything) left the
// whole package green.

registerRulePack('reversible-test-pack', [
  {
    specVersion: 1,
    id: 'rev/keeps',
    name: 'Vaulted marker',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'keyword', keywords: ['KEEP_MARKER'] },
    examples: ['KEEP_MARKER'],
  },
  {
    specVersion: 1,
    id: 'rev/destroys',
    name: 'One-way marker',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'keyword', keywords: ['BURN_MARKER'] },
    examples: ['BURN_MARKER'],
  },
]);

function settings(): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
  };
}

// Both markers are redacted; `reversibleRuleIds` decides which of them is kept.
function bundle(reversibleRuleIds?: string[]): PolicyBundle {
  return {
    version: 'test',
    policies: (['rev/keeps', 'rev/destroys'] as const).map((ruleId) => ({
      id: randomUUID(),
      scope: 'global' as const,
      target: { ruleId },
      action: 'redact' as const,
      enabled: true,
    })),
    ...(reversibleRuleIds === undefined ? {} : { reversibleRuleIds }),
    rules: [],
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
  };
}

function fakeGateway(b: PolicyBundle): DataGateway {
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
    getRuleProbeVerdict: () => Promise.resolve(undefined),
    setRuleProbeVerdict: () => Promise.resolve(),
    openAtRestKeysForPath: () => Promise.resolve([]),
    resolvedAtRestKeysForPath: () => Promise.resolve([]),
    insertResolution: () => Promise.resolve(),
    recordProjectEgress: () =>
      Promise.resolve({ destinations: 0, endpoints: 0, callSites: 0, extractions: 0 }),
    recordProjectFiles: () => Promise.resolve(),
    reconcileWorktreeProjects: () => Promise.resolve(),
    close: () => Promise.resolve(),
  } as unknown as DataGateway;
}

async function capture(
  text: string,
  reversibleRuleIds?: string[],
): Promise<{ action: string; enforced: MatchResult[]; reversible: MatchResult[] }> {
  const dir = mkdtempSync(join(tmpdir(), 'aka-reversible-'));
  try {
    const runtime = createPluginRuntime(fakeGateway(bundle(reversibleRuleIds)), settings(), {
      dataDir: dir,
    });
    const result = await runtime.processText(text);
    await runtime.close();
    return {
      action: result.action,
      enforced: result.enforcedFindings ?? [],
      reversible: result.reversibleFindings ?? [],
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const ids = (findings: MatchResult[]): string[] =>
  [...new Set(findings.map((f) => f.ruleId))].sort();

describe('reversibleFindings — the per-detection custody split', () => {
  it('is the SUBSET of enforced findings whose own detection chose to keep', async () => {
    // The load-bearing case. Both rules redact; only one vaults. A capture that
    // returned every enforced finding here would vault a value the other
    // detection's policy said to destroy.
    const out = await capture('KEEP_MARKER and BURN_MARKER', ['rev/keeps']);
    expect(out.action).toBe('redact');
    expect(ids(out.enforced)).toEqual(['rev/destroys', 'rev/keeps']);
    expect(ids(out.reversible)).toEqual(['rev/keeps']);
  });

  it('is empty when no detection chose the reversible archetype', async () => {
    // The default posture, and the one every machine has until someone assigns
    // Redact & Vault: redaction is one-way.
    const out = await capture('KEEP_MARKER and BURN_MARKER', []);
    expect(ids(out.enforced)).toEqual(['rev/destroys', 'rev/keeps']);
    expect(out.reversible).toEqual([]);
  });

  it('is empty when the bundle omits the field entirely', async () => {
    // An older bundle producer, or an on-disk cache written before the archetype
    // existed. Defaulting to "keep nothing" is the safe direction: the worst
    // outcome is a value destroyed that could have been recovered, not a value
    // retained that the policy said to destroy.
    const out = await capture('KEEP_MARKER and BURN_MARKER');
    expect(out.enforced.length).toBeGreaterThan(0);
    expect(out.reversible).toEqual([]);
  });

  it('never names a rule that is not being enforced', async () => {
    // A bundle may mark a rule reversible whose finding resolved to some other
    // action. Only a value actually being stripped is ever kept, so a
    // reversible id with no enforced finding contributes nothing.
    const out = await capture('KEEP_MARKER', ['rev/keeps', 'rev/destroys', 'rev/absent']);
    expect(ids(out.enforced)).toEqual(['rev/keeps']);
    expect(ids(out.reversible)).toEqual(['rev/keeps']);
  });

  it('every reversible finding is also an enforced one', async () => {
    // The pairing downstream code relies on: a caller rewrites `enforced` and
    // keeps `reversible`, so a reversible finding outside the enforced set would
    // be a value vaulted without being removed from the request.
    const out = await capture('KEEP_MARKER and BURN_MARKER', ['rev/keeps']);
    for (const finding of out.reversible) expect(out.enforced).toContain(finding);
  });
});
