import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { PolicyBundle, WorkspaceSettings } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { DataGateway } from '../src/data-gateway.ts';
import { scanText } from '../src/mask.ts';
import { dropShieldedFindings, shieldPointers } from '../src/pointer-shield.ts';
import { registerRulePack } from '../src/rule-packs.ts';
import { createPluginRuntime } from '../src/runtime.ts';

const SETTINGS: WorkspaceSettings = {
  specVersion: 1,
  runMode: 'standalone',
  policy: 'redact',
  historicalAccess: 'session-only',
  dataSharesInPlace: true,
  vaultKeyCustody: 'file',
  vaultInlineReveal: 'masked',
};

const EMPTY_BUNDLE: PolicyBundle = {
  version: 'test',
  policies: [],
  rules: [],
  customKeywords: [],
  fetchedAt: new Date().toISOString(),
};

// The minimal gateway the runtime accepts; nothing here records or enforces.
function inertGateway(): DataGateway {
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
    getPolicyBundle: () => Promise.resolve(EMPTY_BUNDLE),
    consumeException: () => Promise.resolve(false),
    recordBlockedDetection: () => Promise.resolve(),
    recentFindings: () => Promise.resolve([]),
    healthSummary: () =>
      Promise.resolve({
        totalEvents: 0,
        totalFindings: 0,
        byCategory: {},
        byAction: { warn: 0, redact: 0, block: 0, allow: 0, log: 0 },
      }),
    getRuleProbeVerdicts: () => Promise.resolve([]),
    recordRuleProbeVerdicts: () => Promise.resolve(),
    close: () => Promise.resolve(),
  } as unknown as DataGateway;
}

const POINTER = `[[aka:secret:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
const SECRET = 'AKIAIOSFODNN7EXAMPLE';

// A deliberately hostile rule that matches base32 runs — the shape of a pointer
// body. Installed packs are user-supplied, so a rule like this can always
// exist; the shield is what keeps it away from pointers.
registerRulePack('shield-test-pack', [
  {
    specVersion: 1,
    id: 'shield-test/base32-run',
    name: 'Base32 run (hostile fixture)',
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: '[A-Z2-7]{20,}' },
    examples: ['AAAAAAAAAAAAAAAAAAAAAAAAAA'],
  },
]);

describe('shieldPointers', () => {
  it('blanks pointer spans with same-length filler', () => {
    const text = `before ${POINTER} after`;
    const shielded = shieldPointers(text);
    expect(shielded.text.length).toBe(text.length);
    expect(shielded.text).toBe(`before ${' '.repeat(POINTER.length)} after`);
    expect(shielded.spans).toEqual([{ start: 7, end: 7 + POINTER.length }]);
  });

  it('keeps every non-pointer offset identical', () => {
    const text = `a ${POINTER} ${SECRET} z`;
    const shielded = shieldPointers(text);
    const secretAt = text.indexOf(SECRET);
    expect(shielded.text.slice(secretAt, secretAt + SECRET.length)).toBe(SECRET);
  });

  it('passes pointer-free text through untouched', () => {
    const shielded = shieldPointers('nothing here');
    expect(shielded.text).toBe('nothing here');
    expect(shielded.spans).toEqual([]);
  });

  it('does not blank a lookalike with an invented category', () => {
    const lookalike = `[[aka:bogus:AE.${'A'.repeat(26)}.${'B'.repeat(16)}]]`;
    expect(shieldPointers(lookalike).spans).toEqual([]);
  });
});

describe('dropShieldedFindings', () => {
  it('drops a finding that touches a shielded span', () => {
    const findings = [
      { span: { start: 0, end: 10 } },
      { span: { start: 5, end: 25 } },
      { span: { start: 30, end: 40 } },
    ];
    expect(dropShieldedFindings(findings, [{ start: 8, end: 28 }])).toEqual([
      { span: { start: 30, end: 40 } },
    ]);
  });
});

describe('the scan surfaces never see a pointer', () => {
  it('a bare pointer yields zero findings even under a hostile rule', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'aka-shield-'));
    try {
      const runtime = createPluginRuntime(inertGateway(), SETTINGS, { dataDir: dir });
      const result = await runtime.processText(POINTER);
      expect(result.findings).toEqual([]);
      expect(result.action).not.toBe('block');
      await runtime.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a secret beside a pointer is still caught, with correct span and match', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'aka-shield-'));
    try {
      const runtime = createPluginRuntime(inertGateway(), SETTINGS, { dataDir: dir });
      const text = `${POINTER} key=${SECRET}`;
      const result = await runtime.processText(text);
      const hit = result.findings.find((f) => f.rawMatch === SECRET);
      if (hit === undefined) throw new Error('expected the secret to be found');
      expect(text.slice(hit.span.start, hit.span.end)).toBe(SECRET);
      await runtime.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the mask path also shields pointers', () => {
    const { masked, findings } = scanText(POINTER);
    expect(masked).toBe(POINTER);
    expect(findings).toEqual([]);
  });
});
