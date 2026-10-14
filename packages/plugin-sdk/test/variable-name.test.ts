import type { MatchResult } from '@akasecurity/detections';
import type { PolicyBundle, WorkspaceSettings } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { CaptureRecord, DataGateway } from '../src/data-gateway.ts';
import { registerRulePack } from '../src/rule-packs.ts';
import { createPluginRuntime } from '../src/runtime.ts';
import { createVaultGlue } from '../src/tokenize.ts';
import type { TokenizeValueMeta, VaultCore } from '../src/vault-glue.ts';

registerRulePack('variable-name-pack', [
  {
    specVersion: 1,
    id: 'test/assigned-marker',
    name: 'Test assigned marker',
    category: 'secret',
    severity: 'critical',
    matcher: { type: 'keyword', keywords: ['ASSIGNED_MARKER'] },
    examples: ['ASSIGNED_MARKER'],
  },
]);

const MARKER = 'ASSIGNED_MARKER';
const NAME = ['STRIPE', 'SECRET', 'KEY'].join('_');
const EQ = String.fromCharCode(61);

function settings(): WorkspaceSettings {
  return {
    specVersion: 1,
    runMode: 'standalone',
    policy: 'redact',
    historicalAccess: 'session-only',
    dataSharesInPlace: true,
    vaultKeyCustody: 'file',
    vaultInlineReveal: 'masked',
    redactFallback: 'warn',
    bodyRetention: { enabled: false, retainDays: 30 },
  };
}

function recordingGateway(): DataGateway & { records: CaptureRecord[] } {
  const bundle: PolicyBundle = {
    version: 'test',
    policies: [],
    rules: [],
    customKeywords: [],
    fetchedAt: new Date().toISOString(),
  };
  const records: CaptureRecord[] = [];
  const gateway: Partial<DataGateway> = {
    recordCapture: (record) => {
      records.push(record);
      return Promise.resolve();
    },
    getPolicyBundle: () => Promise.resolve(bundle),
    consumeException: () => Promise.resolve(false),
    recordBlockedDetection: () => Promise.resolve(),
    close: () => Promise.resolve(),
  };
  return Object.assign(gateway as DataGateway, { records });
}

describe('capture — the variable a secret is assigned to', () => {
  async function recorded(text: string) {
    const gw = recordingGateway();
    const rt = createPluginRuntime(gw, settings());
    await rt.capture({ kind: 'code_change', sourceTool: 'claude-code', text });
    await rt.close();
    return gw.records[0]?.findings.find((f) => f.ruleId === 'test/assigned-marker');
  }

  it('records the variable name on the finding, never the value', async () => {
    const finding = await recorded(['export ', NAME, EQ, MARKER].join(''));
    expect(finding?.variableName).toBe(NAME);
    expect(finding?.variableName).not.toContain(MARKER);
  });

  it('leaves names off a decision that records nothing', async () => {
    const rt = createPluginRuntime(recordingGateway(), settings());
    const result = await rt.processText(['export ', NAME, EQ, MARKER].join(''));
    await rt.close();
    const finding = result.findings.find((f) => f.ruleId === 'test/assigned-marker');
    expect(finding).toBeDefined();
    expect(finding).not.toHaveProperty('variableName');
  });

  it('records no name when the secret is not assigned', async () => {
    const finding = await recorded(['deploy with ', MARKER].join(''));
    expect(finding).toBeDefined();
    expect(finding).not.toHaveProperty('variableName');
  });
});

describe('tokenizeText — the vault row learns the variable name', () => {
  it('passes the finding’s variable name to the vault', async () => {
    const seen: TokenizeValueMeta[] = [];
    const vault: VaultCore = {
      tokenize: (_raw, meta) => {
        seen.push(meta);
        return Promise.resolve(`[[aka:secret:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`);
      },
      detokenize: () => Promise.reject(new Error('unused')),
      describePointer: () => Promise.reject(new Error('unused')),
      resolvePointerIdentity: () => Promise.reject(new Error('unused')),
    };
    const glue = createVaultGlue({ vault });
    const text = [NAME, EQ, MARKER].join('');
    const start = NAME.length + 1;
    const match: MatchResult = {
      ruleId: 'test/assigned-marker',
      category: 'secret',
      severity: 'critical',
      span: { start, end: start + MARKER.length },
      rawMatch: MARKER,
      confidence: 0.9,
      variableName: NAME,
    };
    await glue.tokenizeText(text, { findings: [match] });
    expect(seen.map((m) => m.variableName)).toEqual([NAME]);
  });
});
