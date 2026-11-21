// `node scripts/vscode-install.js` — registers this plugin with VS Code agent
// mode by editing VS Code's user settings.json. Run it from the unpacked
// package folder that should stay installed; VS Code loads the plugin from
// there.
//
//   --uninstall        remove the plugin's folder from chat.pluginLocations
//   --insiders         edit VS Code Insiders' settings instead
//   --settings <path>  edit this settings.json (a portable install, or a
//                      custom user-data directory)
//
// Every line the edit does not change is kept, comments included. A file
// that is not a JSON object is left untouched and the run fails.
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  installInSettings,
  uninstallFromSettings,
  type VsCodeEdition,
  vsCodeSettingsPath,
} from './vscode-install.ts';

/** The `name` this plugin's own plugin.json carries. */
const PLUGIN_NAME = 'aka-copilot';

/** The mode a settings.json this script creates is given. */
const NEW_FILE_MODE = 0o644;

/** The folder layout the documented install unpacks into: `aka-copilot/package`. */
const DOCUMENTED_LAYOUT = /(^|[\\/])aka-copilot[\\/]package[\\/]?$/u;

/**
 * Whether `dir` holds a copy of this plugin, or held one: a folder that is gone
 * but sits at the documented `aka-copilot/package` layout is an earlier copy
 * removed by an update, so its entry is dropped rather than left behind. A
 * folder that still exists is recognised only by its manifest, so another
 * plugin's entry is never removed.
 */
export function isPluginFolder(dir: string): boolean {
  if (!existsSync(dir)) return DOCUMENTED_LAYOUT.test(dir);
  try {
    const manifest = JSON.parse(readFileSync(join(dir, 'plugin.json'), 'utf8')) as {
      name?: unknown;
    };
    return manifest.name === PLUGIN_NAME;
  } catch {
    return false;
  }
}

function readText(path: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return '';
    throw error;
  }
}

/** Write `text` to `path` through a sibling temp file, keeping the file's mode. */
function writeKeepingMode(path: string, text: string): void {
  let existing: { mode: number } | undefined;
  try {
    existing = statSync(path);
  } catch {
    existing = undefined;
  }
  // The file belongs to the user, so a rewrite keeps its permission bits; the
  // rename publishes the temp file's bits, not the original's.
  const fileMode = existing === undefined ? NEW_FILE_MODE : existing.mode & 0o777;
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.aka-${String(process.pid)}.tmp`;
  try {
    writeFileSync(temp, text, { mode: fileMode, flag: 'wx' });
    chmodSync(temp, fileMode);
    renameSync(temp, path);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
}

/** Apply an install or uninstall to the settings file at `path`. Returns whether it changed. */
export function applyVsCodeInstall(
  path: string,
  mode: 'install' | 'uninstall',
  pluginDir: string,
  isOwnFolder: (dir: string) => boolean = isPluginFolder,
): boolean {
  const before = readText(path);
  const after =
    mode === 'install'
      ? installInSettings(before, pluginDir, isOwnFolder)
      : uninstallFromSettings(before, pluginDir, isOwnFolder);
  if (after === before) return false;
  writeKeepingMode(path, after);
  return true;
}

interface Options {
  mode: 'install' | 'uninstall';
  edition: VsCodeEdition;
  settings: string | undefined;
}

function parseArgs(argv: readonly string[]): Options {
  const at = argv.indexOf('--settings');
  const settings = at === -1 ? undefined : argv[at + 1];
  if (at !== -1 && (settings === undefined || settings.startsWith('--'))) {
    throw new Error('--settings needs a path');
  }
  return {
    mode: argv.includes('--uninstall') ? 'uninstall' : 'install',
    edition: argv.includes('--insiders') ? 'insiders' : 'stable',
    settings: settings === undefined ? undefined : resolve(settings),
  };
}

export function main(
  argv: readonly string[] = process.argv,
  home: string = homedir(),
  platform: NodeJS.Platform = process.platform,
  pluginDir: string = dirname(dirname(fileURLToPath(import.meta.url))),
): number {
  let options: Options;
  try {
    options = parseArgs(argv.slice(2));
  } catch (error) {
    process.stderr.write(`aka: ${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
  const path = options.settings ?? vsCodeSettingsPath(home, platform, options.edition);
  let changed: boolean;
  try {
    changed = applyVsCodeInstall(path, options.mode, pluginDir);
  } catch (error) {
    process.stderr.write(
      `aka: could not update ${path}: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return 1;
  }
  const done =
    options.mode === 'install'
      ? `registered the AKA plugin at ${pluginDir} in ${path}. Reload VS Code, then run \`aka init\` if you have not.`
      : changed
        ? `removed the AKA plugin from ${path}. Reload VS Code.`
        : `the AKA plugin was not registered in ${path}; nothing changed.`;
  process.stdout.write(`aka: ${done}\n`);
  return 0;
}
