import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { readInstalledVersion } from '../../src/attached/install-record.ts';

// The host's plugin layout, built under a temp directory: the install root is
// <plugins>/cache/<marketplace>/<plugin>/<version>/ and the install record sits
// at <plugins>/installed_plugins.json. Never the real ~/.claude.
async function layout(
  options: { marketplace?: string; plugin?: string; version?: string } = {},
): Promise<{ root: string; pluginsDir: string }> {
  const pluginsDir = join(await mkdtemp(join(tmpdir(), 'aka-install-record-')), 'plugins');
  const root = join(
    pluginsDir,
    'cache',
    options.marketplace ?? 'akasecurity',
    options.plugin ?? 'ai-tc',
    options.version ?? '0.9.14',
  );
  await mkdir(root, { recursive: true });
  return { root, pluginsDir };
}

async function writeRecord(pluginsDir: string, content: string): Promise<void> {
  await writeFile(join(pluginsDir, 'installed_plugins.json'), content, 'utf8');
}

// An entry's installPath names a directory the host installed into. The reader
// checks it exists (never reads it), so a default that does is any directory
// that is there; the dangling cases name a path that is not.
function record(
  version: unknown,
  scope = 'managed',
  installPath: unknown = tmpdir(),
): Record<string, unknown> {
  return {
    scope,
    installPath,
    version,
    installedAt: '2026-09-28T00:00:00.000Z',
    lastUpdated: '2026-09-28T00:00:00.000Z',
  };
}

function ledger(plugins: Record<string, unknown>): string {
  return JSON.stringify({ version: 2, plugins });
}

describe('readInstalledVersion', () => {
  it('reads the version the install record names for the plugin installed at the root', async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(pluginsDir, ledger({ 'ai-tc@akasecurity': [record('0.9.14')] }));
    expect(await readInstalledVersion(root)).toBe('0.9.14');
  });

  it('reports the record, not the root: a copy still running from the old directory reads the new install', async () => {
    const { root, pluginsDir } = await layout({ version: '0.9.13' });
    await writeRecord(pluginsDir, ledger({ 'ai-tc@akasecurity': [record('0.9.14')] }));
    expect(await readInstalledVersion(root)).toBe('0.9.14');
  });

  it('takes the newest version across install scopes', async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(
      pluginsDir,
      ledger({
        'ai-tc@akasecurity': [
          record('0.9.13', 'user'),
          record('0.9.15'),
          record('0.9.9', 'project'),
        ],
      }),
    );
    expect(await readInstalledVersion(root)).toBe('0.9.15');
  });

  it('skips a record whose version is missing, unparseable, not a string or past the wire bound', async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(
      pluginsDir,
      ledger({
        'ai-tc@akasecurity': [
          record(null),
          record('garbage'),
          record(7),
          record(`1.0.0-${'x'.repeat(64)}`),
          null,
          record('0.9.12'),
        ],
      }),
    );
    expect(await readInstalledVersion(root)).toBe('0.9.12');
  });

  it("keys by the root's plugin and marketplace, never by another entry", async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(
      pluginsDir,
      ledger({ 'other@akasecurity': [record('9.9.9')], 'ai-tc@elsewhere': [record('8.8.8')] }),
    );
    expect(await readInstalledVersion(root)).toBeNull();
  });

  it('accepts the root with a trailing separator, as a file URL converts it', async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(pluginsDir, ledger({ 'ai-tc@akasecurity': [record('0.9.14')] }));
    expect(await readInstalledVersion(`${root}/`)).toBe('0.9.14');
  });

  it('reads null with no install record file', async () => {
    const { root } = await layout();
    expect(await readInstalledVersion(root)).toBeNull();
  });

  it('reads null for a record that is not JSON, is JSON null, or holds no list for the plugin', async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(pluginsDir, '{ not json');
    expect(await readInstalledVersion(root)).toBeNull();
    await writeRecord(pluginsDir, 'null');
    expect(await readInstalledVersion(root)).toBeNull();
    await writeRecord(pluginsDir, ledger({ 'ai-tc@akasecurity': { version: '0.9.14' } }));
    expect(await readInstalledVersion(root)).toBeNull();
  });

  it('skips an entry whose install path is gone, reading the older one that is still there', async () => {
    // The record names a newer version at a directory that no longer exists
    // while an older install is intact: the newer one is not on disk.
    const { root, pluginsDir } = await layout();
    await writeRecord(
      pluginsDir,
      ledger({
        'ai-tc@akasecurity': [
          record('0.9.15', 'managed', join(pluginsDir, 'cache', 'akasecurity', 'ai-tc', '0.9.15')),
          record('0.9.14', 'user', root),
        ],
      }),
    );
    expect(await readInstalledVersion(root)).toBe('0.9.14');
  });

  it('reads null when the only entry is dangling', async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(
      pluginsDir,
      ledger({
        'ai-tc@akasecurity': [
          record('0.9.15', 'managed', join(pluginsDir, 'cache', 'akasecurity', 'ai-tc', '0.9.15')),
        ],
      }),
    );
    expect(await readInstalledVersion(root)).toBeNull();
  });

  it('keeps an entry that names no install path string: only a path that is named and gone is dangling', async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(
      pluginsDir,
      ledger({ 'ai-tc@akasecurity': [{ ...record('0.9.14'), installPath: undefined }] }),
    );
    expect(await readInstalledVersion(root)).toBe('0.9.14');
  });

  it('reads null for a root outside the host layout, even with a matching record beside it', async () => {
    // The root has the marketplace/plugin/version shape, but the directory
    // above the marketplace is not named cache. A reader that skipped the
    // layout check would open <dir>/installed_plugins.json and find this entry
    // by key.
    const dir = await mkdtemp(join(tmpdir(), 'aka-install-record-checkout-'));
    const outside = join(dir, 'notcache', 'akasecurity', 'ai-tc', '0.9.14');
    await mkdir(outside, { recursive: true });
    await writeFile(
      join(dir, 'installed_plugins.json'),
      ledger({ 'ai-tc@akasecurity': [record('0.9.14')] }),
      'utf8',
    );
    expect(await readInstalledVersion(outside)).toBeNull();
  });
});
