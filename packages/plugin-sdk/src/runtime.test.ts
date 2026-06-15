import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { registerRulePack } from './rule-packs.ts';
import { createPluginRuntime } from './runtime.ts';

// No policy bundle on disk → DEFAULT_ACTIONS apply (secret: block, pii: redact)
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

async function makeRuntime() {
  const dir = await mkdtemp(join(tmpdir(), 'aka-runtime-'));
  return createPluginRuntime({ backendUrl: '', token: '', dataDir: dir });
}

describe('runtime without a synced policy bundle', () => {
  it('passes benign text through', async () => {
    const runtime = await makeRuntime();
    const result = await runtime.processText('nothing to see here');
    expect(result.action).toBe('log');
    expect(result.text).toBe('nothing to see here');
  });

  it('blocks secrets by default', async () => {
    const runtime = await makeRuntime();
    const result = await runtime.processText('deploy with SECRET_MARKER now');
    expect(result.action).toBe('block');
    expect(result.text).toBeNull();
    expect(result.findings.map((f) => f.ruleId)).toContain('test/secret-marker');
  });

  it('redacts PII by default', async () => {
    const runtime = await makeRuntime();
    const result = await runtime.processText('contact PII_MARKER please');
    expect(result.action).toBe('redact');
    expect(result.text).toBe('contact [REDACTED:PII] please');
  });

  it('reports policy as absent and stale', async () => {
    const runtime = await makeRuntime();
    expect(await runtime.policyStatus()).toEqual({ present: false, stale: true, version: null });
  });
});
