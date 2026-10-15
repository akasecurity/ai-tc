// The launcher's work, driven in-process through runLauncher's arguments. The
// built launcher is driven out of process by test/e2e/hook-launcher.e2e.test.ts;
// these cases pin the same contract with every dependency observable.
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  BODY_LOAD_FAILED,
  bodyScriptFor,
  CACHE_DIR_MODE,
  compileCacheDir,
} from '../../src/hooks/launch-paths.ts';
import { type LauncherIo, runLauncher } from '../../src/hooks/launch-run.ts';

const HOME = join('/', 'home', 'launcher-test');
const LAUNCHER_PATH = join('/', 'plugin', 'scripts', 'pre-tool-use.js');
const VERSION = '9.9.9';
const BODY_HREF = pathToFileURL(bodyScriptFor(LAUNCHER_PATH)).href;

interface Recorded {
  readonly calls: string[];
  readonly stderr: string[];
  readonly exits: number[];
  /** The callback handed to the last stderr write, not yet run. */
  pendingWrite: (() => void) | undefined;
}

function harness(overrides: Partial<LauncherIo> = {}): { io: LauncherIo; seen: Recorded } {
  const seen: Recorded = { calls: [], stderr: [], exits: [], pendingWrite: undefined };
  const io: LauncherIo = {
    launcherUrl: pathToFileURL(LAUNCHER_PATH).href,
    pluginVersion: VERSION,
    homedir: () => HOME,
    mkdirSync: (dir, options) => {
      seen.calls.push(`mkdir ${dir} ${options.mode.toString(8)} ${String(options.recursive)}`);
    },
    enableCompileCache: (dir) => {
      seen.calls.push(`cache ${dir}`);
    },
    importBody: (href) => {
      seen.calls.push(`import ${href}`);
      return Promise.resolve();
    },
    process: {
      exit: (code) => {
        seen.exits.push(code);
      },
      stderr: {
        write: (chunk, callback) => {
          seen.stderr.push(chunk);
          seen.pendingWrite = callback;
          return true;
        },
      },
    },
    ...overrides,
  };
  return { io, seen };
}

const CACHE_DIR = compileCacheDir(HOME, VERSION);
const MKDIR = `mkdir ${CACHE_DIR} ${CACHE_DIR_MODE.toString(8)} true`;

let stdoutWrites = 0;

beforeEach(() => {
  stdoutWrites = 0;
  vi.spyOn(process.stdout, 'write').mockImplementation(() => {
    stdoutWrites += 1;
    return true;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  // Failing open is the absence of output: nothing the launcher does reaches
  // stdout, on any path.
  expect(stdoutWrites).toBe(0);
});

describe('runLauncher turns on the compile cache', () => {
  it('creates the cache directory owner-only, enables it, then loads the body', async () => {
    const { io, seen } = harness();
    await runLauncher(io);
    expect(seen.calls).toEqual([MKDIR, `cache ${CACHE_DIR}`, `import ${BODY_HREF}`]);
    expect(seen.stderr).toEqual([]);
    expect(seen.exits).toEqual([]);
  });

  it('runs the hook uncached on a Node without enableCompileCache', async () => {
    const { io, seen } = harness({ enableCompileCache: undefined });
    await runLauncher(io);
    expect(seen.calls).toEqual([`import ${BODY_HREF}`]);
    expect(seen.stderr).toEqual([]);
    expect(seen.exits).toEqual([]);
  });

  const fails = (): never => {
    throw new Error('refused');
  };

  it.each([
    ['the home directory cannot be read', { homedir: fails }],
    ['the cache directory cannot be made', { mkdirSync: fails }],
    ['the cache cannot be enabled', { enableCompileCache: fails }],
  ] as const)('still loads the body when %s', async (_case, override) => {
    const { io, seen } = harness(override);
    await runLauncher(io);
    expect(seen.calls.at(-1)).toBe(`import ${BODY_HREF}`);
    expect(seen.stderr).toEqual([]);
    expect(seen.exits).toEqual([]);
  });
});

describe('runLauncher fails open when the body cannot be loaded', () => {
  const failingImport = (): Promise<unknown> => Promise.reject(new Error('cannot load body'));

  it('writes the one fixed stderr line and exits 0 only once the write is done', async () => {
    const { io, seen } = harness({ importBody: failingImport });
    await runLauncher(io);
    expect(seen.stderr).toEqual([`${BODY_LOAD_FAILED}\n`]);
    // The exit waits on the write's callback, so a pending pipe write is not
    // dropped by exiting under it.
    expect(seen.exits).toEqual([]);
    seen.pendingWrite?.();
    expect(seen.exits).toEqual([0]);
  });

  it('exits 0 at once when the stderr write itself throws', async () => {
    const exits: number[] = [];
    const { io } = harness({
      importBody: failingImport,
      process: {
        exit: (code) => {
          exits.push(code);
        },
        stderr: {
          write: () => {
            throw new Error('EPIPE');
          },
        },
      },
    });
    await runLauncher(io);
    expect(exits).toEqual([0]);
  });

  it('fails open the same way when the body throws while it loads', async () => {
    const { io, seen } = harness({
      importBody: () => {
        throw new TypeError('thrown synchronously');
      },
    });
    await runLauncher(io);
    expect(seen.stderr).toEqual([`${BODY_LOAD_FAILED}\n`]);
    seen.pendingWrite?.();
    expect(seen.exits).toEqual([0]);
  });

  it('names no path and nothing from the failure on stderr', async () => {
    const { io, seen } = harness({
      importBody: () => Promise.reject(new Error(`cannot load ${BODY_HREF}`)),
    });
    await runLauncher(io);
    expect(seen.stderr).toHaveLength(1);
    expect(seen.stderr[0]).not.toContain(HOME);
    expect(seen.stderr[0]).not.toContain('scripts');
    expect(seen.stderr[0]).not.toContain('cannot load');
  });
});
