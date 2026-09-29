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

function record(version: unknown, scope = 'managed'): Record<string, unknown> {
  return {
    scope,
    installPath: '/not/read/by/the/reader',
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
    expect(readInstalledVersion(root)).toBe('0.9.14');
  });

  it('reports the record, not the root: a copy still running from the old directory reads the new install', async () => {
    const { root, pluginsDir } = await layout({ version: '0.9.13' });
    await writeRecord(pluginsDir, ledger({ 'ai-tc@akasecurity': [record('0.9.14')] }));
    expect(readInstalledVersion(root)).toBe('0.9.14');
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
    expect(readInstalledVersion(root)).toBe('0.9.15');
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
    expect(readInstalledVersion(root)).toBe('0.9.12');
  });

  it("keys by the root's plugin and marketplace, never by another entry", async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(
      pluginsDir,
      ledger({ 'other@akasecurity': [record('9.9.9')], 'ai-tc@elsewhere': [record('8.8.8')] }),
    );
    expect(readInstalledVersion(root)).toBeNull();
  });

  it('accepts the root with a trailing separator, as a file URL converts it', async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(pluginsDir, ledger({ 'ai-tc@akasecurity': [record('0.9.14')] }));
    expect(readInstalledVersion(`${root}/`)).toBe('0.9.14');
  });

  it('reads null with no install record file', async () => {
    const { root } = await layout();
    expect(readInstalledVersion(root)).toBeNull();
  });

  it('reads null for a record that is not JSON, is JSON null, or holds no list for the plugin', async () => {
    const { root, pluginsDir } = await layout();
    await writeRecord(pluginsDir, '{ not json');
    expect(readInstalledVersion(root)).toBeNull();
    await writeRecord(pluginsDir, 'null');
    expect(readInstalledVersion(root)).toBeNull();
    await writeRecord(pluginsDir, ledger({ 'ai-tc@akasecurity': { version: '0.9.14' } }));
    expect(readInstalledVersion(root)).toBeNull();
  });

  it('reads null for a root outside the host layout, such as a checkout', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'aka-install-record-checkout-'));
    const checkout = join(dir, 'plugins', 'claude-code');
    await mkdir(checkout, { recursive: true });
    await writeFile(
      join(dir, 'installed_plugins.json'),
      ledger({ 'claude-code@plugins': [record('0.9.14')] }),
      'utf8',
    );
    expect(readInstalledVersion(checkout)).toBeNull();
  });
});
