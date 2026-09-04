import { describe, expect, it } from 'vitest';

import type { BackgroundScheduleDeps } from '../src/background-schedule.ts';
import {
  BACKGROUND_SYNC_INTERVAL_SECONDS,
  BACKGROUND_SYNC_LABEL,
  installBackgroundSync,
  renderPlist,
  uninstallBackgroundSync,
} from '../src/background-schedule.ts';

// No real launchctl call, filesystem write, or LaunchAgents directory in this
// suite — every I/O and platform seam is injected, so it runs identically
// (and touches nothing) whether the runner is macOS, Linux or Windows.

const REINVOKE = { command: '/usr/bin/aka', args: ['sync-history', '--run', '--home', '/home/x'] };
const DOMAIN = `gui/${String(process.getuid?.() ?? 0)}`;
const PLIST_PATH = '/Users/x/Library/LaunchAgents/com.akasecurity.aka.background-sync.plist';

function harness(overrides: Partial<BackgroundScheduleDeps> = {}) {
  const files = new Map<string, string>();
  const launchctlCalls: string[][] = [];
  const mkdirCalls: string[] = [];
  const deps: BackgroundScheduleDeps = {
    platform: 'darwin',
    homeDir: () => '/Users/x',
    reinvoke: () => REINVOKE,
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

describe('installBackgroundSync', () => {
  it('does nothing on a non-darwin platform', () => {
    const { deps, files, launchctlCalls } = harness({ platform: 'linux' });
    installBackgroundSync('/home/x', deps);
    expect(files.size).toBe(0);
    expect(launchctlCalls).toEqual([]);
  });

  it('does nothing when the CLI cannot resolve a re-invocation (plain node, no entry)', () => {
    const { deps, files, launchctlCalls } = harness({ reinvoke: () => null });
    installBackgroundSync('/home/x', deps);
    expect(files.size).toBe(0);
    expect(launchctlCalls).toEqual([]);
  });

  it('writes the plist and (re)loads it via bootout then bootstrap', () => {
    const { deps, files, launchctlCalls, mkdirCalls } = harness();
    installBackgroundSync('/home/x', deps);

    expect(mkdirCalls).toEqual(['/Users/x/Library/LaunchAgents']);
    const content = files.get(PLIST_PATH);
    expect(content).toBeDefined();
    expect(content).toContain(`<string>${BACKGROUND_SYNC_LABEL}</string>`);
    expect(content).toContain('<string>/usr/bin/aka</string>');
    expect(content).toContain('<string>sync-history</string>');
    expect(content).toContain('<string>--run</string>');
    expect(content).toContain('<string>--home</string>');
    expect(content).toContain('<string>/home/x</string>');
    expect(content).toContain(`<integer>${String(BACKGROUND_SYNC_INTERVAL_SECONDS)}</integer>`);

    expect(launchctlCalls).toEqual([
      ['bootout', `${DOMAIN}/${BACKGROUND_SYNC_LABEL}`],
      ['bootstrap', DOMAIN, PLIST_PATH],
    ]);
  });

  it('is idempotent: an already-current plist is neither rewritten nor reloaded', () => {
    const { deps, launchctlCalls } = harness();
    installBackgroundSync('/home/x', deps);
    launchctlCalls.length = 0;

    let wrote = false;
    installBackgroundSync('/home/x', {
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
    installBackgroundSync('/home/x', deps);
    launchctlCalls.length = 0;

    installBackgroundSync('/home/x', {
      ...deps,
      reinvoke: () => ({ command: '/usr/local/bin/aka', args: ['sync-history', '--run'] }),
    });

    expect(files.get(PLIST_PATH)).toContain('<string>/usr/local/bin/aka</string>');
    expect(launchctlCalls).toHaveLength(2);
    expect(launchctlCalls[0]?.[0]).toBe('bootout');
    expect(launchctlCalls[1]?.[0]).toBe('bootstrap');
  });

  it('never throws even when every seam throws', () => {
    const deps: BackgroundScheduleDeps = {
      platform: 'darwin',
      homeDir: () => {
        throw new Error('boom');
      },
    };
    expect(() => {
      installBackgroundSync('/home/x', deps);
    }).not.toThrow();
  });
});

describe('uninstallBackgroundSync', () => {
  it('does nothing on a non-darwin platform', () => {
    const { deps, files, launchctlCalls } = harness({ platform: 'linux' });
    files.set(PLIST_PATH, 'stale');
    uninstallBackgroundSync(deps);
    expect(files.has(PLIST_PATH)).toBe(true);
    expect(launchctlCalls).toEqual([]);
  });

  it('bootouts the job and removes the plist', () => {
    const { deps, files, launchctlCalls } = harness();
    files.set(PLIST_PATH, 'whatever was there');

    uninstallBackgroundSync(deps);

    expect(files.has(PLIST_PATH)).toBe(false);
    expect(launchctlCalls).toEqual([['bootout', `${DOMAIN}/${BACKGROUND_SYNC_LABEL}`]]);
  });

  it('never throws even when every seam throws', () => {
    const deps: BackgroundScheduleDeps = {
      platform: 'darwin',
      homeDir: () => {
        throw new Error('boom');
      },
    };
    expect(() => {
      uninstallBackgroundSync(deps);
    }).not.toThrow();
  });
});

describe('renderPlist', () => {
  it('XML-escapes a hostile argument rather than splicing it in raw', () => {
    const content = renderPlist([
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
