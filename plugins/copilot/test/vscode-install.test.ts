import { chmodSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../test/helpers/remove-tree.ts';
import { parseJsonc } from '../src/jsonc-edit.ts';
import {
  installInSettings,
  PLUGIN_LOCATIONS,
  PLUGINS_ENABLED,
  uninstallFromSettings,
  USE_HOOKS,
  vsCodeSettingsPath,
} from '../src/vscode-install.ts';
import { applyVsCodeInstall, isPluginFolder, main } from '../src/vscode-install-cli.ts';
import tsupConfig from '../tsup.config.ts';

const PLUGIN = '/home/someone/aka-copilot/package';
const OLD = '/home/someone/old-aka/package';
const OTHER = '/home/someone/other-plugin';
const isOld = (path: string): boolean => path === OLD;

describe('vsCodeSettingsPath', () => {
  it('uses VS Code’s default user settings location on each platform', () => {
    expect(vsCodeSettingsPath('/h', 'linux')).toBe(
      join('/h', '.config', 'Code', 'User', 'settings.json'),
    );
    expect(vsCodeSettingsPath('/h', 'darwin')).toBe(
      join('/h', 'Library', 'Application Support', 'Code', 'User', 'settings.json'),
    );
    expect(vsCodeSettingsPath('/h', 'win32')).toBe(
      join('/h', 'AppData', 'Roaming', 'Code', 'User', 'settings.json'),
    );
    expect(vsCodeSettingsPath('/h', 'linux', 'insiders')).toBe(
      join('/h', '.config', 'Code - Insiders', 'User', 'settings.json'),
    );
  });
});

describe('installInSettings', () => {
  it('turns on plugins and hooks and adds the folder, keeping everything else', () => {
    const before =
      '{\n    // mine\n    "editor.fontSize": 14,\n    "chat.pluginLocations": { "' +
      OTHER +
      '": true },\n}\n';
    const after = installInSettings(before, PLUGIN, isOld);
    const parsed = parseJsonc(after);
    expect(parsed[PLUGINS_ENABLED]).toBe(true);
    expect(parsed[USE_HOOKS]).toBe(true);
    expect(parsed[PLUGIN_LOCATIONS]).toEqual({ [OTHER]: true, [PLUGIN]: true });
    expect(parsed['editor.fontSize']).toBe(14);
    expect(after).toContain('// mine');
  });

  it('replaces an earlier copy of this plugin rather than adding a second', () => {
    const before = JSON.stringify({ [PLUGIN_LOCATIONS]: { [OLD]: true, [OTHER]: false } });
    const parsed = parseJsonc(installInSettings(before, PLUGIN, isOld));
    expect(parsed[PLUGIN_LOCATIONS]).toEqual({ [OTHER]: false, [PLUGIN]: true });
  });

  it('is idempotent', () => {
    const once = installInSettings('', PLUGIN, isOld);
    expect(installInSettings(once, PLUGIN, isOld)).toBe(once);
  });

  it('refuses a chat.pluginLocations that is not an object', () => {
    expect(() => installInSettings('{"chat.pluginLocations": []}', PLUGIN, isOld)).toThrow();
  });

  // Otherwise the edit lands on the first copy, JSON.parse reads the second,
  // and the installer reports a switch on that VS Code reads as off.
  it('refuses a settings file that repeats a switch it sets', () => {
    expect(() =>
      installInSettings('{"chat.useHooks": false, "chat.useHooks": false}', PLUGIN, isOld),
    ).toThrow(/appears more than once/u);
  });

  it('installs into a settings file that holds only comments', () => {
    const next = installInSettings('// my settings\n', PLUGIN, isOld);
    expect(next.startsWith('// my settings\n')).toBe(true);
    expect(parseJsonc(next)['chat.useHooks']).toBe(true);
  });
});

describe('uninstallFromSettings', () => {
  it('removes this plugin’s folders and keeps the switches and other plugins', () => {
    const installed = installInSettings(
      JSON.stringify({ [PLUGIN_LOCATIONS]: { [OTHER]: true } }),
      PLUGIN,
      isOld,
    );
    const parsed = parseJsonc(uninstallFromSettings(installed, PLUGIN, isOld));
    expect(parsed[PLUGIN_LOCATIONS]).toEqual({ [OTHER]: true });
    expect(parsed[PLUGINS_ENABLED]).toBe(true);
    expect(parsed[USE_HOOKS]).toBe(true);
  });

  it('drops chat.pluginLocations when nothing is left in it', () => {
    const installed = installInSettings('', PLUGIN, isOld);
    expect(parseJsonc(uninstallFromSettings(installed, PLUGIN, isOld))).not.toHaveProperty(
      PLUGIN_LOCATIONS,
    );
  });

  it('leaves the text alone when the plugin was never registered', () => {
    const text = '{"a": 1}';
    expect(uninstallFromSettings(text, PLUGIN, isOld)).toBe(text);
    const other = JSON.stringify({ [PLUGIN_LOCATIONS]: { [OTHER]: true } });
    expect(uninstallFromSettings(other, PLUGIN, isOld)).toBe(other);
  });
});

describe('the installer on disk', () => {
  let home: string;
  let pluginDir: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-copilot-vscode-'));
    pluginDir = join(home, 'aka-copilot', 'package');
    mkdirSync(pluginDir, { recursive: true });
    writeFileSync(join(pluginDir, 'plugin.json'), JSON.stringify({ name: 'aka-copilot' }));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    removeTrees([home]);
  });

  it('recognises a folder holding this plugin, and nothing else', () => {
    expect(isPluginFolder(pluginDir)).toBe(true);
    expect(isPluginFolder(home)).toBe(false);
    expect(isPluginFolder(join(home, 'missing'))).toBe(false);
  });

  it('creates settings.json, then removes its entry again', () => {
    const path = vsCodeSettingsPath(home, 'linux');
    expect(applyVsCodeInstall(path, 'install', pluginDir)).toBe(true);
    expect(parseJsonc(readFileSync(path, 'utf8'))[PLUGIN_LOCATIONS]).toEqual({ [pluginDir]: true });
    expect(applyVsCodeInstall(path, 'uninstall', pluginDir)).toBe(true);
    expect(parseJsonc(readFileSync(path, 'utf8'))).not.toHaveProperty(PLUGIN_LOCATIONS);
    expect(applyVsCodeInstall(path, 'uninstall', pluginDir)).toBe(false);
  });

  it('leaves a file it cannot parse untouched', () => {
    const path = vsCodeSettingsPath(home, 'linux');
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, '{ not json');
    expect(() => applyVsCodeInstall(path, 'install', pluginDir)).toThrow();
    expect(readFileSync(path, 'utf8')).toBe('{ not json');
  });

  it.skipIf(process.platform === 'win32')('keeps the file’s permission bits', () => {
    const path = vsCodeSettingsPath(home, 'linux');
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, '{}', { mode: 0o600 });
    chmodSync(path, 0o600);
    applyVsCodeInstall(path, 'install', pluginDir);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  function capture(): { out: string[]; err: string[] } {
    const out: string[] = [];
    const err: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      out.push(String(chunk));
      return true;
    });
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      err.push(String(chunk));
      return true;
    });
    return { out, err };
  }

  it('main installs into the edition and path the flags name', () => {
    const { out } = capture();
    expect(main(['node', 'x', '--insiders'], home, 'darwin', pluginDir)).toBe(0);
    const insiders = vsCodeSettingsPath(home, 'darwin', 'insiders');
    expect(parseJsonc(readFileSync(insiders, 'utf8'))[USE_HOOKS]).toBe(true);
    const custom = join(home, 'portable', 'settings.json');
    expect(main(['node', 'x', '--settings', custom], home, 'darwin', pluginDir)).toBe(0);
    expect(parseJsonc(readFileSync(custom, 'utf8'))[PLUGINS_ENABLED]).toBe(true);
    expect(out.join('')).toContain('registered the AKA plugin');
  });

  it('main reports an uninstall that changed nothing, and fails on a bad file or flag', () => {
    const { out, err } = capture();
    expect(main(['node', 'x', '--uninstall'], home, 'linux', pluginDir)).toBe(0);
    expect(out.join('')).toContain('nothing changed');
    expect(main(['node', 'x', '--settings'], home, 'linux', pluginDir)).toBe(1);
    const path = vsCodeSettingsPath(home, 'linux');
    mkdirSync(join(path, '..'), { recursive: true });
    writeFileSync(path, '[');
    expect(main(['node', 'x'], home, 'linux', pluginDir)).toBe(1);
    expect(err.join('')).toContain('could not update');
  });

  it('is a build entry', () => {
    expect(Object.keys((tsupConfig as { entry: Record<string, string> }).entry)).toContain(
      'vscode-install',
    );
  });
});
