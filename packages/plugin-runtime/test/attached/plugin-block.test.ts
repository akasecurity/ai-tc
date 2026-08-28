import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import type { PolicyBundle } from '@akasecurity/schema';
import { StorePosturePlugin } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { createPluginBlock, readManifestBuild } from '../../src/attached/plugin-block.ts';
import { createPolicyStore } from '../../src/attached/policy-store.ts';

async function dir(): Promise<string> {
  return await mkdtemp(join(tmpdir(), 'aka-plugin-block-'));
}

const bundle = (version: string): PolicyBundle => ({
  version,
  policies: [],
  rules: [],
  customKeywords: [],
  fetchedAt: '2026-08-19T00:00:00.000Z',
});

const BUILD = { package: '@akasecurity/ai-tc-claude-code', version: '0.9.8' };

describe('createPluginBlock', () => {
  it('reports identity plus the cached bundle version and its fetch stamp', async () => {
    const d = await dir();
    const store = createPolicyStore(d);
    await store.write(bundle('sha256:abc123'));
    const block = await createPluginBlock(BUILD, store)();
    if (!block) throw new Error('expected a block');
    expect(() => StorePosturePlugin.parse(block)).not.toThrow();
    expect(block).toMatchObject({
      package: '@akasecurity/ai-tc-claude-code',
      version: '0.9.8',
      ossVersion: null,
      policyBundleVersion: 'sha256:abc123',
    });
    // write() stamps fetchedAtMs itself, so the block carries a real epoch.
    expect(block.policyFetchedAt).toBeGreaterThan(0);
  });

  it('reports identity with null policy fields when no bundle is cached', async () => {
    // The first report after attach: the sync child has not run yet, and the
    // identity half must not wait for it.
    const d = await dir();
    const block = await createPluginBlock(BUILD, createPolicyStore(d))();
    expect(() => StorePosturePlugin.parse(block)).not.toThrow();
    expect(block).toMatchObject({
      package: '@akasecurity/ai-tc-claude-code',
      version: '0.9.8',
      policyBundleVersion: null,
      policyFetchedAt: null,
    });
  });

  it('a corrupt cache behaves like no cache — identity still reports', async () => {
    const d = await dir();
    const store = createPolicyStore(d);
    await writeFile(store.file, '{ not json', 'utf8');
    const block = await createPluginBlock(BUILD, store)();
    expect(block).toMatchObject({
      package: '@akasecurity/ai-tc-claude-code',
      version: '0.9.8',
      policyBundleVersion: null,
      policyFetchedAt: null,
    });
  });

  it('an unusable fetch stamp reports null rather than an invalid epoch', async () => {
    // A cache written before fetchedAtMs existed reads back as 0, and the wire
    // shape wants a positive stamp. The bundle version must still travel.
    const d = await dir();
    const store = createPolicyStore(d);
    await writeFile(store.file, JSON.stringify({ bundle: bundle('v7') }), 'utf8');
    const block = await createPluginBlock(BUILD, store)();
    expect(() => StorePosturePlugin.parse(block)).not.toThrow();
    expect(block).toMatchObject({ policyBundleVersion: 'v7', policyFetchedAt: null });
  });

  it('a stamp outside the wire bounds reports null; the bundle version still travels', async () => {
    // The cache reads fetchedAtMs tolerantly (any number parses) while the
    // receiver enforces the schema's epoch ceiling — and reportStorePosture
    // sends the body unvalidated, so an out-of-range stamp forwarded verbatim
    // would fail the whole snapshot at the receiver. The bound is taken from
    // the wire shape itself, not re-spelled here.
    const d = await dir();
    const store = createPolicyStore(d);
    await writeFile(
      store.file,
      JSON.stringify({ bundle: bundle('v7'), fetchedAtMs: 9_000_000_000_000_000 }),
      'utf8',
    );
    const block = await createPluginBlock(BUILD, store)();
    if (!block) throw new Error('expected a block');
    expect(() => StorePosturePlugin.parse(block)).not.toThrow();
    expect(block).toMatchObject({ policyBundleVersion: 'v7', policyFetchedAt: null });
  });

  it('a bundle version past the wire cap reports null; the stamp still travels', async () => {
    // PolicyBundle.version is an unbounded string, the wire field caps at 200.
    const d = await dir();
    const store = createPolicyStore(d);
    await writeFile(
      store.file,
      JSON.stringify({ bundle: bundle('v'.repeat(201)), fetchedAtMs: 1_779_500_000_000 }),
      'utf8',
    );
    const block = await createPluginBlock(BUILD, store)();
    if (!block) throw new Error('expected a block');
    expect(() => StorePosturePlugin.parse(block)).not.toThrow();
    expect(block).toMatchObject({
      policyBundleVersion: null,
      policyFetchedAt: 1_779_500_000_000,
    });
  });

  it('passes ossVersion through when the build records one', async () => {
    const d = await dir();
    const block = await createPluginBlock(
      { ...BUILD, ossVersion: '0.9.8' },
      createPolicyStore(d),
    )();
    expect(block?.ossVersion).toBe('0.9.8');
  });
});

describe('readManifestBuild', () => {
  async function manifestAt(d: string, content: string): Promise<URL> {
    const path = join(d, 'plugin.json');
    await writeFile(path, content, 'utf8');
    return pathToFileURL(path);
  }

  it('reads the package identity from a manifest carrying a version', async () => {
    const url = await manifestAt(await dir(), JSON.stringify({ name: 'aka', version: '0.9.8' }));
    expect(readManifestBuild(url, '@akasecurity/ai-tc-claude-code')).toEqual({
      package: '@akasecurity/ai-tc-claude-code',
      version: '0.9.8',
    });
  });

  it('a versionless manifest yields undefined rather than a half identity', async () => {
    const url = await manifestAt(await dir(), JSON.stringify({ name: 'aka' }));
    expect(readManifestBuild(url, '@akasecurity/ai-tc-claude-code')).toBeUndefined();
  });

  it('a missing manifest yields undefined — the report goes out without a block', async () => {
    const url = pathToFileURL(join(await dir(), 'nowhere', 'plugin.json'));
    expect(readManifestBuild(url, '@akasecurity/ai-tc-claude-code')).toBeUndefined();
  });

  it('memoises per manifest URL — one read per process, misses included', async () => {
    // The manifest cannot change under a running process, so the first answer
    // stands even when the bytes on disk move; a different URL reads fresh.
    const d = await dir();
    const url = await manifestAt(d, JSON.stringify({ version: '1.0.0' }));
    expect(readManifestBuild(url, 'pkg')?.version).toBe('1.0.0');
    await writeFile(join(d, 'plugin.json'), JSON.stringify({ version: '2.0.0' }), 'utf8');
    expect(readManifestBuild(url, 'pkg')?.version).toBe('1.0.0');

    const other = await manifestAt(await dir(), JSON.stringify({ version: '3.0.0' }));
    expect(readManifestBuild(other, 'pkg')?.version).toBe('3.0.0');
  });
});
