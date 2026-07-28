import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ExternalSpawn } from '../../src/lib/external-dispatch.ts';
import { dispatchExternal, isExternalCommandName } from '../../src/lib/external-dispatch.ts';

afterEach(() => {
  vi.restoreAllMocks();
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

    const result = dispatchExternal('claude', ['--resume', 'x'], spawn, 'darwin');

    expect(spawn).toHaveBeenCalledWith('aka-claude', ['--resume', 'x'], { stdio: 'inherit' });
    expect(result).toEqual({ found: true, status: 0 });
  });

  it('propagates a nonzero exit status', () => {
    const spawn = spawnReturning({ status: 3 });
    expect(dispatchExternal('claude', [], spawn, 'linux')).toEqual({ found: true, status: 3 });
  });

  it('maps a null status (signal-terminated child) to status 1', () => {
    const spawn = spawnReturning({ status: null });
    expect(dispatchExternal('claude', [], spawn, 'linux')).toEqual({ found: true, status: 1 });
  });

  it('reports not-found on ENOENT so the caller falls through to unknown-command', () => {
    const error: NodeJS.ErrnoException = new Error('spawnSync aka-claude ENOENT');
    error.code = 'ENOENT';
    const spawn = spawnReturning({ status: null, error });

    expect(dispatchExternal('claude', [], spawn, 'darwin')).toEqual({ found: false, status: 1 });
  });

  it('treats a non-ENOENT spawn error as found-but-failed and writes it to stderr', () => {
    const stderr = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const error: NodeJS.ErrnoException = new Error('spawnSync aka-claude EACCES');
    error.code = 'EACCES';
    const spawn = spawnReturning({ status: null, error });

    expect(dispatchExternal('claude', [], spawn, 'linux')).toEqual({ found: true, status: 1 });
    const message = stderr.mock.calls.map((c) => String(c[0])).join('');
    expect(message).toContain('aka: aka-claude: spawnSync aka-claude EACCES');
  });

  it('reports not-found on win32 without spawning', () => {
    const spawn = spawnReturning({ status: 0 });

    expect(dispatchExternal('claude', [], spawn, 'win32')).toEqual({ found: false, status: 1 });
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

      try {
        expect(dispatchExternal(name, [], spawn)).toEqual({ found: true, status: 7 });
        expect(dispatchExternal(`${name}-missing`, [], spawn)).toEqual({
          found: false,
          status: 1,
        });
      } finally {
        rmSync(binDir, { recursive: true, force: true });
      }
    },
  );
});
