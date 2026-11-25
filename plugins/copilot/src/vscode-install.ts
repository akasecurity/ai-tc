// Registering this plugin with VS Code agent mode, as pure functions over the
// text of VS Code's user settings.json, so they unit-test without a real file.
//
// VS Code loads a plugin from a folder listed in `chat.pluginLocations`, and
// runs its hooks only while `chat.plugins.enabled` and `chat.useHooks` are on.
// Install sets the two switches and adds this package's folder to the list;
// uninstall removes the folder and leaves the switches, which other plugins
// may rely on.
import { join } from 'node:path';

import { parseJsonc, removeProperty, setProperty } from './jsonc-edit.ts';

export const PLUGINS_ENABLED = 'chat.plugins.enabled';
export const USE_HOOKS = 'chat.useHooks';
export const PLUGIN_LOCATIONS = 'chat.pluginLocations';

/** The editions whose user settings this script can find on its own. */
export type VsCodeEdition = 'stable' | 'insiders';

const PRODUCT_DIR: Record<VsCodeEdition, string> = {
  stable: 'Code',
  insiders: 'Code - Insiders',
};

/**
 * VS Code's user settings.json for an edition, at the location VS Code uses
 * by default on each platform. A portable install or a custom user-data
 * directory keeps it elsewhere; the CLI takes `--settings` for those.
 */
export function vsCodeSettingsPath(
  home: string,
  platform: NodeJS.Platform,
  edition: VsCodeEdition = 'stable',
): string {
  const product = PRODUCT_DIR[edition];
  if (platform === 'darwin') {
    return join(home, 'Library', 'Application Support', product, 'User', 'settings.json');
  }
  if (platform === 'win32') {
    return join(home, 'AppData', 'Roaming', product, 'User', 'settings.json');
  }
  return join(home, '.config', product, 'User', 'settings.json');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The settings text with this plugin registered at `pluginDir`. Entries in
 * `chat.pluginLocations` that `isOwnFolder` recognises as an earlier copy of
 * this plugin are dropped, so reinstalling from a new folder leaves one entry.
 * Throws on text that is not a JSONC object, or a `chat.pluginLocations` that
 * is not an object, so the caller refuses rather than overwriting it.
 */
export function installInSettings(
  text: string,
  pluginDir: string,
  isOwnFolder: (path: string) => boolean,
): string {
  const parsed = parseJsonc(text);
  const current = parsed[PLUGIN_LOCATIONS] ?? {};
  if (!isRecord(current)) throw new Error(`expected "${PLUGIN_LOCATIONS}" to be an object`);
  const locations: Record<string, unknown> = {};
  for (const [path, enabled] of Object.entries(current)) {
    if (path !== pluginDir && !isOwnFolder(path)) locations[path] = enabled;
  }
  locations[pluginDir] = true;
  let next = setProperty(text, PLUGINS_ENABLED, true);
  next = setProperty(next, USE_HOOKS, true);
  return setProperty(next, PLUGIN_LOCATIONS, locations);
}

/**
 * The settings text with every folder `isOwnFolder` recognises, and
 * `pluginDir`, removed from `chat.pluginLocations`. The key goes when it is
 * left empty. The two switches are left as they are.
 */
export function uninstallFromSettings(
  text: string,
  pluginDir: string,
  isOwnFolder: (path: string) => boolean,
): string {
  const parsed = parseJsonc(text);
  const current = parsed[PLUGIN_LOCATIONS];
  if (current === undefined) return text;
  if (!isRecord(current)) throw new Error(`expected "${PLUGIN_LOCATIONS}" to be an object`);
  const kept = Object.fromEntries(
    Object.entries(current).filter(([path]) => path !== pluginDir && !isOwnFolder(path)),
  );
  if (Object.keys(kept).length === Object.keys(current).length) return text;
  return Object.keys(kept).length === 0
    ? removeProperty(text, PLUGIN_LOCATIONS)
    : setProperty(text, PLUGIN_LOCATIONS, kept);
}
