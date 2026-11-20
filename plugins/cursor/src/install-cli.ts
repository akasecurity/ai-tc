// `node scripts/install.js` — registers this plugin's hooks in the user-level
// Cursor hooks file, `~/.cursor/hooks.json`. `--uninstall` removes them.
//
// The command for each hook names this process's own node binary and the
// `scripts/` directory this file was run from, so run it from the copy of the
// package that should stay installed. Entries of the user's own are kept; a
// file this script cannot parse is left untouched and the run fails, rather
// than being overwritten.
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { mergeOwnHooks, parseHooksFile, removeOwnHooks } from './install.ts';

export function cursorHooksPath(home: string = homedir()): string {
  return join(home, '.cursor', 'hooks.json');
}

function readParsed(path: string): unknown {
  let raw: string;
  try {
    raw = readFileSync(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
  return JSON.parse(raw);
}

/** The mode a hooks file this script creates is given. */
const NEW_FILE_MODE = 0o644;

/** Apply an install or uninstall to the hooks file at `path`. */
export function applyInstall(
  path: string,
  mode: 'install' | 'uninstall',
  nodePath: string,
  scriptsDir: string,
): void {
  const existing = statOrUndefined(path);
  const file = parseHooksFile(readParsed(path));
  const next =
    mode === 'install' ? mergeOwnHooks(file, nodePath, scriptsDir) : removeOwnHooks(file);
  mkdirSync(dirname(path), { recursive: true });
  // The file belongs to the user, so a rewrite keeps its permission bits; the
  // rename below publishes the temp file's bits, not the original's.
  const fileMode = existing === undefined ? NEW_FILE_MODE : existing.mode & 0o777;
  // Written beside the target and renamed over it, so Cursor never reads a
  // half-written file. `wx` refuses a path that already exists, including a
  // symlink planted there.
  const temp = `${path}.aka-${String(process.pid)}.tmp`;
  try {
    writeFileSync(temp, `${JSON.stringify(next, null, 2)}\n`, { mode: fileMode, flag: 'wx' });
    // The write's mode passes through the umask; the chmod makes it exact.
    chmodSync(temp, fileMode);
    renameSync(temp, path);
  } catch (error) {
    rmSync(temp, { force: true });
    throw error;
  }
}

function statOrUndefined(path: string): { mode: number } | undefined {
  try {
    return statSync(path);
  } catch {
    return undefined;
  }
}

export function main(argv: readonly string[] = process.argv): number {
  const mode = argv.includes('--uninstall') ? 'uninstall' : 'install';
  const path = cursorHooksPath();
  const scriptsDir = dirname(fileURLToPath(import.meta.url));
  try {
    applyInstall(path, mode, process.execPath, scriptsDir);
  } catch (error) {
    process.stderr.write(
      `aka: could not update ${path}: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return 1;
  }
  process.stdout.write(
    mode === 'install'
      ? `aka: registered the AKA hooks in ${path}. Restart Cursor, then run \`aka init\` if you have not.\n`
      : `aka: removed the AKA hooks from ${path}.\n`,
  );
  return 0;
}
