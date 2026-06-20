import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { PluginConfig } from './config.ts';
import { createLocalStore } from './local-store.ts';
import { registerRulePack } from './rule-packs.ts';
import { createPluginRuntime } from './runtime.ts';

// Markers resolved by the seeded default policies (secret: block, pii: redact).
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

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-runtime-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function config(policy: 'redact' | 'warn' = 'redact'): PluginConfig {
  return {
    settings: { specVersion: 1, runMode: 'standalone', policy },
    dataDir: dir,
    dbPath: join(dir, 'aka.db'),
    settingsDir: dir,
    onboarded: true,
    backend: null,
  };
}

describe('createPluginRuntime — decisions from seeded default policies', () => {
  it('passes benign text through as log', () => {
    const rt = createPluginRuntime(config());
    expect(rt.processText('nothing to see here')).toMatchObject({
      action: 'log',
      text: 'nothing to see here',
    });
    rt.close();
  });

  it('blocks secrets by default', () => {
    const rt = createPluginRuntime(config());
    const result = rt.processText('deploy with SECRET_MARKER now');
    expect(result.action).toBe('block');
    expect(result.text).toBeNull();
    expect(result.findings.map((f) => f.ruleId)).toContain('test/secret-marker');
    rt.close();
  });

  it('redacts PII by default', () => {
    const rt = createPluginRuntime(config());
    expect(rt.processText('contact PII_MARKER please')).toMatchObject({
      action: 'redact',
      text: 'contact [REDACTED:PII] please',
    });
    rt.close();
  });

  it('warn redaction mode downgrades block/redact to warn and leaves text intact', () => {
    const rt = createPluginRuntime(config('warn'));
    expect(rt.processText('deploy with SECRET_MARKER now')).toMatchObject({
      action: 'warn',
      text: 'deploy with SECRET_MARKER now',
    });
    expect(rt.processText('contact PII_MARKER please')).toMatchObject({
      action: 'warn',
      text: 'contact PII_MARKER please',
    });
    rt.close();
  });
});

describe('capture', () => {
  it('records the event + findings and returns the same decision', () => {
    const rt = createPluginRuntime(config());
    const result = rt.capture({
      kind: 'prompt',
      sourceTool: 'claude-code',
      text: 'deploy with SECRET_MARKER now',
    });
    expect(result.action).toBe('block');
    rt.close();

    const store = createLocalStore(dir);
    const findings = store.recentFindings();
    store.close();
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('test/secret-marker');
    expect(findings[0]?.actionTaken).toBe('block');
  });
});
