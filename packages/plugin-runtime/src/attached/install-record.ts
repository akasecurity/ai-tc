import { readFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';

import { compareBinaryVersions, isParseableBinaryVersion } from '@akasecurity/persistence';
import { StorePosturePlugin } from '@akasecurity/schema';

/**
 * The newest version the host's install record holds for the plugin installed
 * at `installRoot`, or null when there is no record to read.
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
 * snapshot over it.
 *
 * Best-effort and synchronous — one small local file, read once per report.
 * Every failure reads null; nothing here throws.
 */
export function readInstalledVersion(installRoot: string): string | null {
  try {
    const versionDir = resolve(installRoot);
    const pluginDir = dirname(versionDir);
    const marketplaceDir = dirname(pluginDir);
    const cacheDir = dirname(marketplaceDir);
    if (basename(cacheDir) !== 'cache') return null;
    const key = `${basename(pluginDir)}@${basename(marketplaceDir)}`;
    const record = JSON.parse(
      readFileSync(join(dirname(cacheDir), 'installed_plugins.json'), 'utf8'),
    ) as { plugins?: unknown } | null;
    const plugins = record?.plugins;
    if (typeof plugins !== 'object' || plugins === null || !Object.hasOwn(plugins, key)) {
      return null;
    }
    const entries = (plugins as Record<string, unknown>)[key];
    if (!Array.isArray(entries)) return null;
    let newest: string | null = null;
    for (const entry of entries as unknown[]) {
      const version = (entry as { version?: unknown } | null)?.version;
      if (typeof version !== 'string' || !isParseableBinaryVersion(version)) continue;
      if (!StorePosturePlugin.shape.installedVersion.safeParse(version).success) continue;
      if (newest === null || compareBinaryVersions(version, newest) > 0) newest = version;
    }
    return newest;
  } catch {
    return null;
  }
}
