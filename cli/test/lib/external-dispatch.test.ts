import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { COMMAND_SPECS } from '../../src/command-manifest.ts';
import type { ExternalSpawn } from '../../src/lib/external-dispatch.ts';
import {
  commandOnPath,
  dispatchExternal,
  externalDispatchSupported,
  isExternalCommandName,
  shouldDispatchExternal,
} from '../../src/lib/external-dispatch.ts';

const dispatchModuleUrl = new URL('../../src/lib/external-dispatch.ts', import.meta.url).href;

afterEach(() => {
  vi.restoreAllMocks();
});

describe('shouldDispatchExternal', () => {
  // The core safety property: a built-in never dispatches externally, so an
  // `aka-<builtin>` executable on PATH can never shadow a shipped command.
  it.each(COMMAND_SPECS.map((spec) => spec.name))('never dispatches built-in %s', (name) => {
    expect(shouldDispatchExternal(name, true)).toBe(false);
  });

  it.each(['__update-refresh', '__dashboard-server'])(
    'never dispatches hidden command %s',
    (name) => {
      expect(shouldDispatchExternal(name, true)).toBe(false);
      expect(shouldDispatchExternal(name, false)).toBe(false);
    },
  );

  it('dispatches a non-built-in with a dispatchable name', () => {
    expect(shouldDispatchExternal('claude', false)).toBe(true);
  });

  it('does not dispatch a non-built-in with an ineligible name', () => {
    expect(shouldDispatchExternal('--help', false)).toBe(false);
  });
});

describe('commandOnPath', () => {
  it.runIf(process.platform !== 'win32')('finds a command that exists', () => {
    expect(commandOnPath('sh')).toBe(true);
  });

  it.runIf(process.platform !== 'win32')('does not find one that does not', () => {
    expect(commandOnPath('aka-definitely-not-installed-xyz')).toBe(false);
  });

  it.runIf(process.platform !== 'win32')('emits nothing on stdout or stderr', () => {
    // The probe runs on every unrecognized command, so any output it leaks —
    // including a Node deprecation warning from `shell: true` — would surface
    // on ordinary typos.
    const probe = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import { commandOnPath } from ${JSON.stringify(dispatchModuleUrl)};
         commandOnPath('aka-definitely-not-installed-xyz');`,
      ],
      { encoding: 'utf8' },
    );
    expect(probe.stdout).toBe('');
    expect(probe.stderr).toBe('');
  });
});

describe('externalDispatchSupported', () => {
  it.each(['darwin', 'linux'] as NodeJS.Platform[])('is enabled on %s', (platform) => {
    expect(externalDispatchSupported(platform)).toBe(true);
  });

  it('is disabled on win32', () => {
    expect(externalDispatchSupported('win32')).toBe(false);
  });
});

describe('isExternalCommandName', () => {
  it.each(['claude', 'foo-bar', 'k2'])('accepts %j', (name) => {
    expect(isExternalCommandName(name)).toBe(true);
  });

  it.each(['__dashboard-server', '-h', '--help', '../x', 'a/b', 'A', 'has_underscore', ''])(
    'rejects %j',
    (name) => {
      expect(isExternalCommandName(name)).toBe(false);
    },
  );
});

describe('dispatchExternal', () => {
  const spawnReturning = (
    result: ReturnType<ExternalSpawn>,
  ): ExternalSpawn & ReturnType<typeof vi.fn> =>
    vi.fn().mockReturnValue(result) as ExternalSpawn & ReturnType<typeof vi.fn>;

  it('spawns aka-<command> with the verbatim argv, inheriting stdio', () => {
    const spawn = spawnReturning({ status: 0 });

    const result = dispatchExternal('claude', ['--resume', 'x'], { spawn, platform: 'darwin' });

    expect(spawn).toHaveBeenCalledWith('aka-claude', ['--resume', 'x'], { stdio: 'inherit' });
    expect(result).toEqual({ found: true, status: 0 });
  });

  it('propagates a nonzero exit status', () => {
    const spawn = spawnReturning({ status: 3 });
    expect(dispatchExternal('claude', [], { spawn, platform: 'linux' })).toEqual({
      found: true,
      status: 3,
    });
  });

  it('reports a signal-terminated child as 128 + the signal number', () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const spawn = spawnReturning({ status: null, signal: 'SIGINT' });

    expect(dispatchExternal('claude', [], { spawn, platform: 'linux' })).toEqual({
      found: true,
      status: 130,
    });
    expect(stderr.mock.calls.map((c) => String(c[0])).join('')).toContain('terminated by SIGINT');
  });

  it('falls back to status 1 when the child died with no reported signal', () => {
    const spawn = spawnReturning({ status: null });
    expect(dispatchExternal('claude', [], { spawn, platform: 'linux' })).toEqual({
      found: true,
      status: 1,
    });
  });

  it('reports not-found on ENOENT when nothing by that name is on PATH', () => {
    const error: NodeJS.ErrnoException = new Error('spawnSync aka-claude ENOENT');
    error.code = 'ENOENT';
    const spawn = spawnReturning({ status: null, error });

    expect(
      dispatchExternal('claude', [], { spawn, platform: 'darwin', exists: () => false }),
    ).toEqual({ found: false, status: 1 });
  });

  it('reports found-but-failed on ENOENT when the executable does exist on PATH', () => {
    // A shebang naming a missing absolute interpreter fails with ENOENT even
    // though aka-claude itself is present; that is a broken command, not a
    // missing one.
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const error: NodeJS.ErrnoException = new Error('spawnSync aka-claude ENOENT');
    error.code = 'ENOENT';
    const spawn = spawnReturning({ status: null, error });

    expect(
      dispatchExternal('claude', [], { spawn, platform: 'darwin', exists: () => true }),
    ).toEqual({ found: true, status: 1 });
    expect(stderr.mock.calls.map((c) => String(c[0])).join('')).toContain('aka: aka-claude:');
  });

  it('treats a non-ENOENT spawn error as found-but-failed and writes it to stderr', () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const error: NodeJS.ErrnoException = new Error('spawnSync aka-claude EACCES');
    error.code = 'EACCES';
    const spawn = spawnReturning({ status: null, error });

    expect(dispatchExternal('claude', [], { spawn, platform: 'linux' })).toEqual({
      found: true,
      status: 1,
    });
    const message = stderr.mock.calls.map((c) => String(c[0])).join('');
    expect(message).toContain('aka: aka-claude: spawnSync aka-claude EACCES');
  });

  it('reports not-found on win32 without spawning', () => {
    const spawn = spawnReturning({ status: 0 });

    expect(dispatchExternal('claude', [], { spawn, platform: 'win32' })).toEqual({
      found: false,
      status: 1,
    });
    expect(spawn).not.toHaveBeenCalled();
  });

  it.runIf(process.platform !== 'win32')(
    'runs a real executable found on the injected PATH and propagates its exit status',
    () => {
      const binDir = mkdtempSync(join(tmpdir(), 'aka-external-bin-'));
      const name = `probe-${Date.now().toString(36)}`;
      const script = join(binDir, `aka-${name}`);
      writeFileSync(script, '#!/bin/sh\nexit 7\n');
      chmodSync(script, 0o755);
      // Resolve against the temp dir only, via the spawn options — no
      // process.env read or mutation.
      const spawn: ExternalSpawn = (cmd, args, opts) =>
        spawnSync(cmd, args, { ...opts, env: { PATH: binDir } });
      const exists = (cmd: string) => existsSync(join(binDir, cmd));

      try {
        expect(dispatchExternal(name, [], { spawn, exists })).toEqual({ found: true, status: 7 });
        expect(dispatchExternal(`${name}-missing`, [], { spawn, exists })).toEqual({
          found: false,
          status: 1,
        });
      } finally {
        rmSync(binDir, { recursive: true, force: true });
      }
    },
  );
});
