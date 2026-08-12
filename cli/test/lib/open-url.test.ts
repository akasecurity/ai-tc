import type { ChildProcess, SpawnOptions } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import type { OpenerCommand } from '../../src/lib/open-url.ts';
import { openUrl, openUrlCommand } from '../../src/lib/open-url.ts';

const URL_UNDER_TEST = 'http://127.0.0.1:4319/security';

// What `spawn` really hands back, reduced to the two members openUrl touches:
// an EventEmitter (which is what makes an unlistened 'error' fatal) and unref.
// Modelling it as a real EventEmitter rather than a spy object is the point —
// the crash this file pins is EventEmitter's own behaviour, so a stand-in that
// only counted `.on` calls would agree about the wiring and disagree about the
// consequence.
class FakeChild extends EventEmitter {
  unrefCount = 0;
  unref(): this {
    this.unrefCount += 1;
    return this;
  }
}

interface SpawnRecord {
  command: string;
  args: readonly string[];
  options: SpawnOptions;
  child: FakeChild;
}

/** Run openUrl with the spawn seam captured; returns what it asked for. */
function recordSpawn(url: string, platform?: NodeJS.Platform): SpawnRecord {
  const calls: SpawnRecord[] = [];
  const spawn = (command: string, args: readonly string[], options: SpawnOptions): ChildProcess => {
    const child = new FakeChild();
    calls.push({ command, args, options, child });
    return child as unknown as ChildProcess;
  };
  openUrl(url, platform === undefined ? { spawn } : { platform, spawn });
  const [call] = calls;
  if (call === undefined) throw new Error('openUrl spawned nothing');
  expect(calls).toHaveLength(1);
  return call;
}

// -------------------------------------------------------------------------
// The three branches, on every runner
// -------------------------------------------------------------------------

// Branch coverage, driven by injection so all three run wherever this suite
// runs. It is deliberately NOT the whole of this file: injecting 'win32' on a
// Mac proves the mapping, not that `cmd /c start ""` is what the CLI reaches
// for on Windows — the default binding is a separate claim, pinned below on
// each platform in turn.
describe('openUrlCommand', () => {
  it('opens with `open` on darwin', () => {
    expect(openUrlCommand('darwin', URL_UNDER_TEST)).toEqual<OpenerCommand>({
      command: 'open',
      args: [URL_UNDER_TEST],
    });
  });

  it('opens with `cmd /c start ""` on win32, title slot first', () => {
    // The '' is the console TITLE `start` would otherwise read the URL as. Drop
    // it and Windows opens a blank console window named after the URL, with no
    // browser and no error — the failure mode is a silent no-op, which is why
    // the argv is pinned positionally rather than by "contains the url".
    expect(openUrlCommand('win32', URL_UNDER_TEST)).toEqual<OpenerCommand>({
      command: 'cmd',
      args: ['/c', 'start', '', URL_UNDER_TEST],
    });
  });

  it('opens with `xdg-open` on linux', () => {
    expect(openUrlCommand('linux', URL_UNDER_TEST)).toEqual<OpenerCommand>({
      command: 'xdg-open',
      args: [URL_UNDER_TEST],
    });
  });

  it('falls back to `xdg-open` on the other unix platforms', () => {
    // The branch is `else`, not `=== 'linux'`, and these are the platforms that
    // reach it: freebsd and friends carry xdg-open the same way linux does.
    for (const platform of ['freebsd', 'openbsd', 'netbsd', 'sunos', 'aix'] as const) {
      expect(openUrlCommand(platform, URL_UNDER_TEST).command).toBe('xdg-open');
    }
  });
});

// -------------------------------------------------------------------------
// The default binding — each platform asserts its own branch, on its own runner
// -------------------------------------------------------------------------

// This is the half injection cannot buy. `openUrl` resolves `deps.platform ??
// process.platform`, and a default rewritten to a literal — or a mapping edited
// so two platforms share a branch — leaves every injected case above green.
// Each case below runs on exactly one runner and names the literal it expects
// there, so the mapping is pinned to the platform rather than to itself.
describe('the opener this platform actually gets', () => {
  it.runIf(process.platform === 'darwin')('is `open` on macOS', () => {
    expect(openUrlCommand(process.platform, URL_UNDER_TEST)).toEqual<OpenerCommand>({
      command: 'open',
      args: [URL_UNDER_TEST],
    });
    const call = recordSpawn(URL_UNDER_TEST);
    expect(call.command).toBe('open');
    expect(call.args).toEqual([URL_UNDER_TEST]);
  });

  it.runIf(process.platform === 'win32')('is `cmd /c start ""` on Windows', () => {
    expect(openUrlCommand(process.platform, URL_UNDER_TEST)).toEqual<OpenerCommand>({
      command: 'cmd',
      args: ['/c', 'start', '', URL_UNDER_TEST],
    });
    const call = recordSpawn(URL_UNDER_TEST);
    expect(call.command).toBe('cmd');
    expect(call.args).toEqual(['/c', 'start', '', URL_UNDER_TEST]);
  });

  it.runIf(process.platform === 'linux')('is `xdg-open` on Linux', () => {
    expect(openUrlCommand(process.platform, URL_UNDER_TEST)).toEqual<OpenerCommand>({
      command: 'xdg-open',
      args: [URL_UNDER_TEST],
    });
    const call = recordSpawn(URL_UNDER_TEST);
    expect(call.command).toBe('xdg-open');
    expect(call.args).toEqual([URL_UNDER_TEST]);
  });
});

// Whether the program named for this platform is one the platform actually has.
// A mapping can be internally consistent and still name nothing — and the
// failure is invisible, because a missing opener is swallowed by design. Only
// the platform itself can answer, and only for the two that ship an opener:
// xdg-open comes from a desktop package, so a headless Linux legitimately has
// none, which is the case the swallow exists for and is pinned below instead.
describe('the opener this platform names exists here', () => {
  it.runIf(process.platform === 'darwin')('macOS ships /usr/bin/open', () => {
    expect(openUrlCommand('darwin', URL_UNDER_TEST).command).toBe('open');
    expect(existsSync('/usr/bin/open')).toBe(true);
  });

  it.runIf(process.platform === 'win32')('Windows resolves `cmd`', () => {
    // Resolution, not behaviour: `cmd /c exit 0` returns without opening
    // anything, and a `cmd` that could not be found throws ENOENT here.
    expect(() => execFileSync('cmd', ['/c', 'exit', '0'], { stdio: 'ignore' })).not.toThrow();
  });
});

// -------------------------------------------------------------------------
// The spawn wiring
// -------------------------------------------------------------------------

describe('openUrl', () => {
  it('spawns detached with no stdio, and unrefs', () => {
    // Detached + unref is what lets the browser outlive `aka dashboard`;
    // stdio 'ignore' is what stops the opener writing over the CLI's own
    // output on the terminal they share.
    const call = recordSpawn(URL_UNDER_TEST, 'linux');
    expect(call.options).toEqual({ stdio: 'ignore', detached: true });
    expect(call.child.unrefCount).toBe(1);
  });

  it('survives a missing opener — the ENOENT that arrives as an event, not a throw', () => {
    // The headless case the swallow is written for, and the one a try/catch
    // cannot reach: spawn returns a child and reports ENOENT asynchronously.
    // An EventEmitter with no 'error' listener THROWS on emit, so without the
    // listener this is an uncaught exception on a later tick — fatal to the
    // whole command, with the dashboard server already up and the parent gone.
    const call = recordSpawn(URL_UNDER_TEST, 'linux');
    const enoent = Object.assign(new Error('spawn xdg-open ENOENT'), { code: 'ENOENT' });
    expect(() => call.child.emit('error', enoent)).not.toThrow();
    expect(call.child.listenerCount('error')).toBeGreaterThan(0);
  });

  it('swallows a spawn that throws synchronously', () => {
    // The other failure route, and the one the original try/catch covered.
    const spawn = (): ChildProcess => {
      throw new Error('EINVAL');
    };
    expect(() => {
      openUrl(URL_UNDER_TEST, { platform: 'linux', spawn });
    }).not.toThrow();
  });

  it('passes the URL through unchanged', () => {
    // Anything that re-encoded, trimmed or split the url would open the wrong
    // page. The fixture deliberately carries a query string but NO cmd
    // metacharacter: `&` would survive this assertion and still break on
    // Windows, because cmd re-parses the command line after node has declined
    // to quote it (see openUrlCommand). Asserting an `&` url round-trips here
    // would document a shape the win32 branch does not actually support.
    const url = 'http://127.0.0.1:4319/security?range=7d';
    expect(url).not.toMatch(/[&|^<>]/);
    expect(recordSpawn(url, 'linux').args).toEqual([url]);
    expect(recordSpawn(url, 'win32').args).toEqual(['/c', 'start', '', url]);
  });
});
