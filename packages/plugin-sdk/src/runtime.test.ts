import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { createPolicyStore } from './policy-store.ts';
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

describe('runtime with synced installed-pack rules', () => {
  it('enforces rules delivered in the synced bundle (not just bundled packs)', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aka-runtime-installed-'));
    const store = createPolicyStore(dir);
    await store.write({
      version: '1',
      policies: [],
      // A rule that exists ONLY in the synced bundle — no bundled pack has it.
      rules: [
        {
          specVersion: 1,
          id: 'aka-labs/installed-marker',
          name: 'Installed marker',
          category: 'secret',
          severity: 'critical',
          matcher: { type: 'keyword', keywords: ['INSTALLED_MARKER'], caseSensitive: false },
        },
      ],
      customKeywords: [],
      fetchedAt: new Date().toISOString(),
    });

    const runtime = createPluginRuntime({ backendUrl: '', token: '', dataDir: dir });
    const result = await runtime.processText('here is INSTALLED_MARKER value');

    // secret → block via DEFAULT_ACTIONS, proving the synced rule was registered.
    expect(result.action).toBe('block');
    expect(result.findings.map((f) => f.ruleId)).toContain('aka-labs/installed-marker');
  });
});
