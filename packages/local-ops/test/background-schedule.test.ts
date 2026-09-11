import { afterEach, describe, expect, it, vi } from 'vitest';

import type { BackgroundScheduleDeps } from '../src/background-schedule.ts';
import {
  BACKGROUND_SYNC_INTERVAL_SECONDS,
  backgroundSyncLabel,
  installBackgroundSync,
  renderPlist,
  triggerHistorySyncRun,
  uninstallBackgroundSync,
} from '../src/background-schedule.ts';

// No real launchctl call, filesystem write, or LaunchAgents directory in this
// suite — every I/O and platform seam is injected, so it runs identically
// (and touches nothing) whether the runner is macOS, Linux or Windows.

const BASE = '/home/x';
const OTHER_BASE = '/tmp/scratch';
const DOMAIN = `gui/${String(process.getuid?.() ?? 0)}`;
const LABEL = backgroundSyncLabel(BASE);
const PLIST_PATH = `/Users/x/Library/LaunchAgents/${LABEL}.plist`;

function harness(overrides: Partial<BackgroundScheduleDeps> = {}) {
  const files = new Map<string, string>();
  const launchctlCalls: string[][] = [];
  const mkdirCalls: string[] = [];
  const deps: BackgroundScheduleDeps = {
    platform: 'darwin',
    homeDir: () => '/Users/x',
    // Built from the arguments it is actually called with, not a hardcoded
    // constant: a stub that ignores `subcommand`/`extraArgs` cannot tell a
    // correct `base` from a wrong one, since it returns the same payload
    // either way. This is what makes the plist-content assertions below (and
    // the two-bases case) prove `base` really reaches `reinvoke`, rather than
    // merely matching a literal the harness happened to embed.
    reinvoke: (subcommand, extraArgs = []) => ({
      command: '/usr/bin/aka',
      args: [subcommand, ...extraArgs],
    }),
    readFile: (p) => files.get(p) ?? null,
    writeFile: (p, data) => {
      files.set(p, data);
    },
    mkdir: (dir) => {
      mkdirCalls.push(dir);
    },
    removeFile: (p) => {
      files.delete(p);
    },
    runLaunchctl: (args) => {
      launchctlCalls.push(args);
      return true;
    },
    ...overrides,
  };
  return { deps, files, launchctlCalls, mkdirCalls };
}

let restoreStderr: (() => void) | undefined;

/** Every line written to stderr, joined — so `toContain` is a substring test. */
function captureStderr(): { lines: () => string } {
  const written: string[] = [];
  const spy = vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    written.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
    return true;
  });
  restoreStderr = () => {
    spy.mockRestore();
  };
  return { lines: () => written.join('') };
}

afterEach(() => {
  restoreStderr?.();
  restoreStderr = undefined;
});

describe('installBackgroundSync', () => {
  it('does nothing on a non-darwin platform', () => {
    const { deps, files, launchctlCalls } = harness({ platform: 'linux' });
    installBackgroundSync(BASE, deps);
    expect(files.size).toBe(0);
    expect(launchctlCalls).toEqual([]);
  });

  it('does nothing when the CLI cannot resolve a re-invocation (plain node, no entry)', () => {
    const { deps, files, launchctlCalls } = harness({ reinvoke: () => null });
    installBackgroundSync(BASE, deps);
    expect(files.size).toBe(0);
    expect(launchctlCalls).toEqual([]);
  });

  it('writes the plist and (re)loads it via bootout then bootstrap', () => {
    const { deps, files, launchctlCalls, mkdirCalls } = harness();
    installBackgroundSync(BASE, deps);

    expect(mkdirCalls).toEqual(['/Users/x/Library/LaunchAgents']);
    const content = files.get(PLIST_PATH);
    expect(content).toBeDefined();
    expect(content).toContain(`<string>${LABEL}</string>`);
    expect(content).toContain('<string>/usr/bin/aka</string>');
    expect(content).toContain('<string>sync-history</string>');
    expect(content).toContain('<string>--run</string>');
    expect(content).toContain('<string>--home</string>');
    expect(content).toContain(`<string>${BASE}</string>`);
    expect(content).toContain(`<integer>${String(BACKGROUND_SYNC_INTERVAL_SECONDS)}</integer>`);

    expect(launchctlCalls).toEqual([
      ['bootout', `${DOMAIN}/${LABEL}`],
      ['bootstrap', DOMAIN, PLIST_PATH],
    ]);
  });

  it('is idempotent: an already-current plist is neither rewritten nor reloaded', () => {
    const { deps, launchctlCalls } = harness();
    installBackgroundSync(BASE, deps);
    launchctlCalls.length = 0;

    let wrote = false;
    installBackgroundSync(BASE, {
      ...deps,
      writeFile: () => {
        wrote = true;
      },
    });

    expect(wrote).toBe(false);
    expect(launchctlCalls).toEqual([]);
  });

  it('rewrites and reloads when the target has changed (the binary moved)', () => {
    const { deps, files, launchctlCalls } = harness();
    installBackgroundSync(BASE, deps);
    launchctlCalls.length = 0;

    installBackgroundSync(BASE, {
      ...deps,
      reinvoke: (subcommand, extraArgs = []) => ({
        command: '/usr/local/bin/aka',
        args: [subcommand, ...extraArgs],
      }),
    });

    expect(files.get(PLIST_PATH)).toContain('<string>/usr/local/bin/aka</string>');
    expect(launchctlCalls).toHaveLength(2);
    expect(launchctlCalls[0]?.[0]).toBe('bootout');
    expect(launchctlCalls[1]?.[0]).toBe('bootstrap');
  });

  it('reports a bootstrap failure instead of swallowing it silently', () => {
    const { deps, launchctlCalls } = harness({
      runLaunchctl: (args) => {
        launchctlCalls.push(args);
        return args[0] !== 'bootstrap';
      },
    });
    const stderr = captureStderr();

    installBackgroundSync(BASE, deps);

    expect(stderr.lines()).toContain('bootstrap failed');
    expect(stderr.lines()).toContain(LABEL);
  });

  it('gives two different AKA homes their own plist and label, never colliding', () => {
    const { deps: depsA, files: filesA } = harness();
    installBackgroundSync(BASE, depsA);

    const { deps: depsB, files: filesB } = harness();
    installBackgroundSync(OTHER_BASE, depsB);

    const labelA = backgroundSyncLabel(BASE);
    const labelB = backgroundSyncLabel(OTHER_BASE);
    expect(labelA).not.toBe(labelB);

    const pathA = `/Users/x/Library/LaunchAgents/${labelA}.plist`;
    const pathB = `/Users/x/Library/LaunchAgents/${labelB}.plist`;
    expect(pathA).not.toBe(pathB);
    expect(filesA.get(pathA)).toContain(`<string>${BASE}</string>`);
    expect(filesB.get(pathB)).toContain(`<string>${OTHER_BASE}</string>`);
  });

  it('never throws even when every seam throws', () => {
    const deps: BackgroundScheduleDeps = {
      platform: 'darwin',
      homeDir: () => {
        throw new Error('boom');
      },
    };
    expect(() => {
      installBackgroundSync(BASE, deps);
    }).not.toThrow();
  });
});

describe('uninstallBackgroundSync', () => {
  it('does nothing on a non-darwin platform', () => {
    const { deps, files, launchctlCalls } = harness({ platform: 'linux' });
    files.set(PLIST_PATH, 'stale');
    uninstallBackgroundSync(BASE, deps);
    expect(files.has(PLIST_PATH)).toBe(true);
    expect(launchctlCalls).toEqual([]);
  });

  it('bootouts the job and removes the plist', () => {
    const { deps, files, launchctlCalls } = harness();
    files.set(PLIST_PATH, 'whatever was there');

    uninstallBackgroundSync(BASE, deps);

    expect(files.has(PLIST_PATH)).toBe(false);
    expect(launchctlCalls).toEqual([['bootout', `${DOMAIN}/${LABEL}`]]);
  });

  it('targets only the base it was given, leaving a sibling home untouched', () => {
    const otherLabel = backgroundSyncLabel(OTHER_BASE);
    const otherPath = `/Users/x/Library/LaunchAgents/${otherLabel}.plist`;
    const { deps, files, launchctlCalls } = harness();
    files.set(PLIST_PATH, 'this machine, real home');
    files.set(otherPath, 'this machine, --home /tmp/scratch');

    uninstallBackgroundSync(BASE, deps);

    expect(files.has(PLIST_PATH)).toBe(false);
    expect(files.has(otherPath)).toBe(true);
    expect(launchctlCalls).toEqual([['bootout', `${DOMAIN}/${LABEL}`]]);
  });

  it('never throws even when every seam throws', () => {
    // `homeDir` does not throw until `plistPath` is built, which is AFTER the
    // bootout call — so `runLaunchctl` MUST be injected here even though this
    // case is about the throw, not about launchctl: without it, this test used
    // to run the real `launchctl bootout` against the developer's own gui
    // domain on every `pnpm test`.
    const deps: BackgroundScheduleDeps = {
      platform: 'darwin',
      homeDir: () => {
        throw new Error('boom');
      },
      runLaunchctl: () => true,
    };
    expect(() => {
      uninstallBackgroundSync(BASE, deps);
    }).not.toThrow();
  });
});

describe('renderPlist', () => {
  it('XML-escapes a hostile argument rather than splicing it in raw', () => {
    const content = renderPlist(LABEL, [
      '/usr/bin/aka',
      'sync-history',
      '--home',
      '/tmp/a & b <c> "d" \'e\'',
    ]);
    expect(content).toContain('&amp;');
    expect(content).toContain('&lt;c&gt;');
    expect(content).toContain('&quot;d&quot;');
    expect(content).toContain('&apos;e&apos;');
    expect(content).not.toContain(' & ');
  });
});

describe('backgroundSyncLabel', () => {
  it('is deterministic for the same base and distinct across bases', () => {
    expect(backgroundSyncLabel(BASE)).toBe(backgroundSyncLabel(BASE));
    expect(backgroundSyncLabel(BASE)).not.toBe(backgroundSyncLabel(OTHER_BASE));
  });
});

// Starting a pass by hand shares the scheduler's argv on purpose: a pass started
// by a person and a pass started on a timer must be the same pass, or the two
// surfaces describing them diverge.
describe('triggerHistorySyncRun', () => {
  const BASE = '/Users/x/.aka';
  // Non-optional, because `BackgroundScheduleDeps['reinvoke']` includes
  // `undefined` and exactOptionalPropertyTypes refuses that for an optional
  // property. Naming the function type keeps the stubs honest instead.
  type Reinvoke = (
    subcommand: string,
    extraArgs?: string[],
  ) => { command: string; args: string[] } | null;

  it('spawns the same argv the scheduler installs', () => {
    const spawned: { command: string; args: readonly string[] }[] = [];
    const reinvoke = vi.fn(() => ({
      command: '/usr/bin/aka',
      args: ['sync-history', '--run', '--home', BASE],
    }));

    const result = triggerHistorySyncRun(BASE, {
      reinvoke: reinvoke as unknown as Reinvoke,
      startDetached: (command, args) => {
        spawned.push({ command, args });
      },
    });

    expect(reinvoke).toHaveBeenCalledWith('sync-history', ['--run', '--home', BASE]);
    expect(result.started).toBe(true);
    // The CHILD's argv, not merely what the builder was handed: this is what
    // decides whether the pass a person started is the pass the timer starts.
    expect(spawned).toEqual([
      { command: '/usr/bin/aka', args: ['sync-history', '--run', '--home', BASE] },
    ]);
  });

  it('reports a spawn that throws rather than claiming it started', () => {
    const result = triggerHistorySyncRun(BASE, {
      reinvoke: (() => ({
        command: 'aka',
        args: ['sync-history'],
      })) as unknown as Reinvoke,
      startDetached: () => {
        throw new Error('EACCES');
      },
    });
    expect(result).toEqual({ started: false, reason: 'spawn-failed' });
  });

  // Its neighbour returns early off darwin because a LaunchAgent is a macOS
  // object. A child process is not, and copying that gate would make the control
  // do nothing at all on Linux and Windows while reporting success.
  it('starts on a platform that has no LaunchAgent', () => {
    const spawned: string[] = [];
    const result = triggerHistorySyncRun(BASE, {
      platform: 'linux',
      reinvoke: (() => ({
        command: 'node',
        args: ['cli.js', 'sync-history', '--run', '--home', BASE],
      })) as unknown as Reinvoke,
      startDetached: (command) => {
        spawned.push(command);
      },
    });
    expect(result.started).toBe(true);
    expect(spawned).toEqual(['node']);
  });

  // The passive callers of this argv swallow the null — a scheduler that cannot
  // install is best-effort background work. A control somebody pressed is not.
  it('reports, rather than swallows, having nothing to re-invoke', () => {
    const spawned: string[] = [];
    const result = triggerHistorySyncRun(BASE, {
      reinvoke: (() => null) as unknown as Reinvoke,
      startDetached: (command) => {
        spawned.push(command);
      },
    });
    expect(result).toEqual({ started: false, reason: 'no-cli-entry' });
    // And nothing was started: the report is not a label on a child that ran.
    expect(spawned).toEqual([]);
  });
});
