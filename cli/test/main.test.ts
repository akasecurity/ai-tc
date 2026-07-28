import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { ExternalSpawn } from '../src/lib/external-dispatch.ts';
import { main } from '../src/main.ts';

// The wiring in main() — which argv reaches the child, which names are allowed to
// dispatch at all, and what happens when nothing answers — held in place by
// nothing but a comment until these ran. dispatchExternal's own behaviour is
// covered in test/lib/external-dispatch.test.ts; this file only pins the seam.

const silence = (stream: NodeJS.WriteStream) => vi.spyOn(stream, 'write').mockReturnValue(true);

let stdout: ReturnType<typeof silence>;
let stderr: ReturnType<typeof silence>;
let exitCode: typeof process.exitCode;

beforeEach(() => {
  exitCode = process.exitCode;
  stdout = silence(process.stdout);
  stderr = silence(process.stderr);
});

afterEach(() => {
  vi.restoreAllMocks();
  // main() reports failure by setting process.exitCode; left set, it would fail
  // the whole vitest run.
  process.exitCode = exitCode;
});

const written = (spy: ReturnType<typeof silence>): string =>
  spy.mock.calls.map((call) => String(call[0])).join('');

// A spawn that reports the child ran and exited with `status`.
const spawnExiting = (status: number): ExternalSpawn & ReturnType<typeof vi.fn> =>
  vi.fn().mockReturnValue({ status }) as ExternalSpawn & ReturnType<typeof vi.fn>;

// A spawn that reports nothing by that name exists, the way spawnSync does.
const spawnMissing = (): ExternalSpawn & ReturnType<typeof vi.fn> => {
  const error: NodeJS.ErrnoException = new Error('spawnSync ENOENT');
  error.code = 'ENOENT';
  return vi.fn().mockReturnValue({ status: null, error }) as ExternalSpawn &
    ReturnType<typeof vi.fn>;
};

describe('main — external dispatch wiring', () => {
  it('forwards the verbatim tail, including --no-update-check', async () => {
    // An external command owns its whole argv. Passing the filtered `rest` here
    // would silently swallow the flag on its way to the child.
    const spawn = spawnExiting(0);

    await main(['claude', '--no-update-check', '--resume'], { spawn, platform: 'darwin' });

    expect(spawn).toHaveBeenCalledWith('aka-claude', ['--no-update-check', '--resume'], {
      stdio: 'inherit',
    });
  });

  it('propagates the external command exit status', async () => {
    const spawn = spawnExiting(3);

    await main(['claude'], { spawn, platform: 'darwin' });

    expect(process.exitCode).toBe(3);
    expect(written(stderr)).toBe('');
  });

  it('never dispatches a built-in', async () => {
    const spawn = spawnExiting(0);

    await main(['completion'], { spawn, platform: 'darwin' });

    expect(spawn).not.toHaveBeenCalled();
    expect(written(stdout)).toContain('completion');
  });

  it('dispatches `constructor` rather than treating it as a built-in', async () => {
    // COMMANDS is an object literal, so a truthy `COMMANDS[command]` lookup finds
    // the inherited `Object` here — the one prototype name that also passes
    // isExternalCommandName. It must reach dispatch, then report unknown.
    const spawn = spawnMissing();

    await main(['constructor'], { spawn, platform: 'darwin', exists: () => false });

    expect(spawn).toHaveBeenCalledWith('aka-constructor', [], { stdio: 'inherit' });
    expect(written(stderr)).toContain("unknown command 'constructor'");
    expect(process.exitCode).toBe(1);
  });

  it('falls through to the unknown-command error when nothing answers', async () => {
    const spawn = spawnMissing();

    await main(['nope-not-installed'], { spawn, platform: 'darwin', exists: () => false });

    expect(spawn).toHaveBeenCalledWith('aka-nope-not-installed', [], { stdio: 'inherit' });
    expect(written(stderr)).toContain("unknown command 'nope-not-installed'");
    expect(process.exitCode).toBe(1);
  });

  it('does not dispatch a flag-like first argument', async () => {
    const spawn = spawnExiting(0);

    await main(['--nope'], { spawn, platform: 'darwin' });

    expect(spawn).not.toHaveBeenCalled();
    expect(written(stderr)).toContain("unknown command '--nope'");
  });
});
