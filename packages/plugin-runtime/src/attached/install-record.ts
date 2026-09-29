import { readFile, stat } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';

import { compareBinaryVersions, isParseableBinaryVersion } from '@akasecurity/persistence';
import { StorePosturePlugin } from '@akasecurity/schema';

/**
 * The newest version the host's install record holds for the plugin installed
 * at `installRoot` whose install directory is still on disk, or null when no
 * usable version can be read: no record (a plugin run from a checkout), no
 * entry with a valid version, or no entry whose `installPath` exists.
 *
 * `installRoot` is the directory the running plugin was loaded from. The host
 * installs a marketplace plugin into
 * `<plugins>/cache/<marketplace>/<plugin>/<version>/` and keeps its install
 * record at `<plugins>/installed_plugins.json`, keyed `<plugin>@<marketplace>`,
 * so both the file and the key are derived from the root itself: no home
 * directory and no environment variable is read, and a relocated config
 * directory is followed for free. A root outside that layout (a plugin run from
 * a checkout) has no record and reads null.
 *
 * The record is found by NAME, never by matching the root's own version
 * directory: after an update the running copy still sits in the old version's
 * directory while the record already names the new one, and that lead is
 * exactly what this reports. The record holds one entry per install scope; the
 * newest parseable version across them is returned, and a version past the wire
 * bound is skipped rather than sent, since the receiver would refuse the whole
 * snapshot over it. An entry whose `installPath` is a string naming a path that
 * no longer exists is skipped too: the record then names a version that is not
 * on disk, and a caller would otherwise report it as installed. The path is
 * only checked for existence with a stat, which follows a symlink, and is never
 * opened: any existing path counts, whatever it is.
 *
 * Best-effort — one small local file read once per report, plus one stat per
 * entry. Asynchronous, so a caller that bounds it with a timer keeps the read
 * inside that bound. Every failure reads null; nothing here throws.
 */
export async function readInstalledVersion(installRoot: string): Promise<string | null> {
  try {
    const versionDir = resolve(installRoot);
    const pluginDir = dirname(versionDir);
    const marketplaceDir = dirname(pluginDir);
    const cacheDir = dirname(marketplaceDir);
    if (basename(cacheDir) !== 'cache') return null;
    const key = `${basename(pluginDir)}@${basename(marketplaceDir)}`;
    const record = JSON.parse(
      await readFile(join(dirname(cacheDir), 'installed_plugins.json'), 'utf8'),
    ) as { plugins?: unknown } | null;
    const plugins = record?.plugins;
    if (typeof plugins !== 'object' || plugins === null || !Object.hasOwn(plugins, key)) {
      return null;
    }
    const entries = (plugins as Record<string, unknown>)[key];
    if (!Array.isArray(entries)) return null;
    let newest: string | null = null;
    for (const entry of entries as unknown[]) {
      const { version, installPath } = (entry ?? {}) as {
        version?: unknown;
        installPath?: unknown;
      };
      if (typeof version !== 'string' || !isParseableBinaryVersion(version)) continue;
      if (!StorePosturePlugin.shape.installedVersion.safeParse(version).success) continue;
      // Cheapest checks first: only an entry that could beat the current
      // newest costs a stat.
      if (newest !== null && compareBinaryVersions(version, newest) <= 0) continue;
      if (typeof installPath === 'string' && !(await exists(installPath))) continue;
      newest = version;
    }
    return newest;
  } catch {
    return null;
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}
