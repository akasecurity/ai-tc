// What the hook launcher (launch.ts) does, with the process, the filesystem and
// the importer passed in, so it runs in-process under test. launch.ts supplies
// the real ones and calls runLauncher; it loads a hook body on import, and this
// module does nothing on import.
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  BODY_LOAD_FAILED,
  bodyScriptFor,
  CACHE_DIR_MODE,
  compileCacheDir,
} from './launch-paths.ts';

/** The part of `process` the launcher touches. */
export interface LauncherProcess {
  exit(code: number): void;
  readonly stderr: { write(chunk: string, callback: () => void): unknown };
}

export interface LauncherIo {
  /** The launcher's own module URL; the body it loads sits beside it. */
  readonly launcherUrl: string;
  readonly pluginVersion: string;
  readonly homedir: () => string;
  readonly mkdirSync: (dir: string, options: { recursive: true; mode: number }) => unknown;
  /** Absent on a Node without the export, which runs the hook uncached. */
  readonly enableCompileCache: ((dir: string) => unknown) | undefined;
  /** Loads the body module at a file URL. */
  readonly importBody: (href: string) => Promise<unknown>;
  readonly process: LauncherProcess;
}

async function loadBody(io: LauncherIo): Promise<void> {
  try {
    // Created here, owner-only, rather than left to Node: on a machine where
    // this is the first thing to touch ~/.aka, Node's own recursive create
    // would make ~/.aka itself with the default, wider mode.
    if (io.enableCompileCache !== undefined) {
      const dir = compileCacheDir(io.homedir(), io.pluginVersion);
      io.mkdirSync(dir, { recursive: true, mode: CACHE_DIR_MODE });
      io.enableCompileCache(dir);
    }
  } catch {
    // No cache: the body is compiled from source, as it would be without one.
  }
  await io.importBody(pathToFileURL(bodyScriptFor(fileURLToPath(io.launcherUrl))).href);
}

/**
 * Turns on the compile cache when it can, then loads the hook body. A body
 * that cannot be loaded, or throws while it loads, writes BODY_LOAD_FAILED to
 * stderr and exits 0 with nothing on stdout. Once loaded, the body exits on
 * its own.
 */
export async function runLauncher(io: LauncherIo): Promise<void> {
  try {
    await loadBody(io);
  } catch {
    // Exit from the write's callback: process.exit does not wait for a pending
    // pipe write, so exiting straight after it can drop the line.
    const exit = (): void => {
      io.process.exit(0);
    };
    try {
      io.process.stderr.write(`${BODY_LOAD_FAILED}\n`, exit);
    } catch {
      exit();
    }
  }
}
