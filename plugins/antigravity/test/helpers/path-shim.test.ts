import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  assertShimResolves,
  SHIM_NEEDS_SHELL,
  shimMarker,
  shimmedPath,
  WINDOWS_SYSTEM_DIRS,
  WINDOWS_SYSTEM_ENV,
  writeCommandShim,
} from './path-shim.ts';

// Every case here reaches its shim the way the platform can reach one: a win32
// shim is a `.cmd`, so it needs a shell, and the child needs System32 + COMSPEC
// before that shell can be spawned at all. These used to be SKIPPED on win32
// instead, which cost more than the cases themselves: the refusal cases below
// then passed there for the wrong reason, since a shell-free probe refuses
// EVERYTHING on Windows and no case could tell a wrong-platform shim from a
// missing shell.
const shimShell = { shell: SHIM_NEEDS_SHELL } as const;

// A name no real binary on any developer machine or runner answers to, so a
// resolution MISS in this suite can only ever fail — never reach a live tool.
// That matters more here than anywhere else: this file exists to drive the miss
// case on purpose.
const COMMAND = 'aka-shim-fixture-cmd';

// The shim body every case writes: records that it ran, then prints a word the
// caller can match. Written behind the helper's prologue, so the probe answer
// sits ahead of the sentinel write.
const bodyWritingSentinel = (sentinelPath: string): string =>
  `require('node:fs').writeFileSync(${JSON.stringify(sentinelPath)}, '');
process.stdout.write('SHIM-BODY-RAN');
`;

// A third-party binary that happens to answer to the same name — what the real
// installed CLI is to a judge stub. Deliberately NOT written through
// writeCommandShim: the whole point is that it runs cleanly and answers the
// probe with something other than this suite's marker.
const writeForeignBinary = (dir: string, command: string): void => {
  const js = "process.stdout.write('FOREIGN-TOOL 1.2.3');\n";
  if (process.platform === 'win32') {
    const foreignScript = join(dir, `${command}-foreign.js`);
    writeFileSync(foreignScript, js);
    // Absolute, for the reason writeCommandShim spells out: %~dp0 expands
    // against the cwd for a batch file cmd.exe resolved from PATH by name.
    writeFileSync(
      join(dir, `${command}.cmd`),
      `@echo off\r\n"${process.execPath}" "${foreignScript}" %*\r\n`,
    );
    return;
  }
  const binPath = join(dir, command);
  writeFileSync(binPath, `#!/usr/bin/env node\n${js}`);
  chmodSync(binPath, 0o755);
};

const dirs: string[] = [];
const tempDir = (): string => {
  const dir = mkdtempSync(join(tmpdir(), 'aka-path-shim-test-'));
  dirs.push(dir);
  return dir;
};

// node's own dir, so a POSIX shim's `#!/usr/bin/env node` line resolves without
// dragging the whole host PATH (and its real binaries) into these cases.
const NODE_DIR = dirname(process.execPath);

// The env a probe is run with: node's own dir for a POSIX shim's shebang, plus
// (win32 only) the system dirs cmd.exe itself is found through.
const shimEnv = (binDir?: string): NodeJS.ProcessEnv => ({
  ...WINDOWS_SYSTEM_ENV,
  PATH: shimmedPath(binDir ?? '', [NODE_DIR, ...WINDOWS_SYSTEM_DIRS].join(delimiter)),
});

afterEach(() => {
  while (dirs.length > 0) rmSync(dirs.pop() ?? '', { recursive: true, force: true });
});

const errorFrom = (fn: () => unknown): Error | undefined => {
  try {
    fn();
    return undefined;
  } catch (e) {
    return e as Error;
  }
};

// The weaker check this helper replaced: "the spawn worked". Kept as the paired
// control — a case is only evidence that identity is being checked if the
// spawn-succeeded form would have passed on the same input.
const spawnSucceeded = (command: string, env: NodeJS.ProcessEnv): boolean => {
  try {
    execFileSync(command, ['--version'], {
      env,
      encoding: 'utf8',
      timeout: 20_000,
      stdio: ['ignore', 'pipe', 'pipe'],
      ...shimShell,
    });
    return true;
  } catch {
    return false;
  }
};

describe('shimmedPath', () => {
  it('prepends the shim dir as a real first entry under the platform delimiter', () => {
    const base = ['/first/base', '/second/base'].join(delimiter);
    const entries = shimmedPath('/shim/dir', base).split(delimiter);
    expect(entries[0]).toBe('/shim/dir');
    expect(entries.slice(1)).toEqual(['/first/base', '/second/base']);
  });

  it('yields the shim dir ALONE when there is no base PATH, leaving no empty entry', () => {
    // Asserting entry [0] would pass on a trailing delimiter too, which is the
    // bug: an empty PATH element is read as the CURRENT DIRECTORY by execvp and
    // by libuv's own search, so `${binDir}${delimiter}` quietly adds the cwd to
    // a search path whose whole purpose is that only the shim is on it.
    expect(shimmedPath('/shim/dir', undefined)).toBe('/shim/dir');
    expect(shimmedPath('/shim/dir', '')).toBe('/shim/dir');
    expect(shimmedPath('/shim/dir', undefined).split(delimiter)).toEqual(['/shim/dir']);
  });
});

describe('writeCommandShim + assertShimResolves', () => {
  it('resolves the shim written for the running platform', () => {
    const binDir = tempDir();
    writeCommandShim(binDir, COMMAND, bodyWritingSentinel(join(binDir, 'ran')));
    const env = shimEnv(binDir);

    expect(
      errorFrom(() => {
        assertShimResolves(COMMAND, env, shimShell);
      }),
    ).toBeUndefined();
  });

  it('answers the probe WITHOUT recording an invocation, and records one when really run', () => {
    const binDir = tempDir();
    const sentinel = join(binDir, 'ran');
    writeCommandShim(binDir, COMMAND, bodyWritingSentinel(sentinel));
    const env = shimEnv(binDir);

    assertShimResolves(COMMAND, env, shimShell);
    // The property a `judgeWasInvoked()`-style sentinel depends on: probing is
    // not invoking. Lose the ordering in the prologue and every "the egress
    // never happened" assertion starts failing for a reason that is not the
    // one under test.
    expect(existsSync(sentinel)).toBe(false);

    // Positive control: the sentinel IS written when the shim runs for real, so
    // the absence above is the ordering rather than a shim that never runs.
    const out = execFileSync(COMMAND, [], {
      env,
      encoding: 'utf8',
      timeout: 20_000,
      ...shimShell,
    });
    expect(out).toContain('SHIM-BODY-RAN');
    expect(existsSync(sentinel)).toBe(true);
  });

  it('performs the probe under the cwd it is given, not this process s', () => {
    const binDir = tempDir();
    writeCommandShim(binDir, COMMAND, bodyWritingSentinel(join(binDir, 'ran')));
    const env = shimEnv(binDir);

    // A real cwd changes nothing on POSIX (only Windows searches it), so the
    // decisive check is a cwd that cannot be entered: the spawn itself fails,
    // which can only happen if the option reached the spawn. Drop the cwd from
    // assertShimResolves and this resolves cleanly and the case goes red —
    // asserting a successful resolution under a valid cwd would not, since
    // ignoring the option produces exactly the same pass.
    const err = errorFrom(() => {
      assertShimResolves(COMMAND, env, { ...shimShell, cwd: join(binDir, 'no-such-dir') });
    });
    expect(err?.message).toContain(`PATH shim for "${COMMAND}" did not resolve`);
    expect(err?.message).toContain('the spawn failed');

    // Positive control on the same shim: with no cwd override it resolves, so
    // the refusal above is the cwd and not a shim that never worked.
    expect(
      errorFrom(() => {
        assertShimResolves(COMMAND, env, shimShell);
      }),
    ).toBeUndefined();
  });

  it('refuses when the shim dir is not on PATH at all', () => {
    const binDir = tempDir();
    writeCommandShim(binDir, COMMAND, bodyWritingSentinel(join(binDir, 'ran')));
    const env = shimEnv();

    const err = errorFrom(() => {
      assertShimResolves(COMMAND, env, shimShell);
    });
    expect(err?.message).toContain(`PATH shim for "${COMMAND}" did not resolve`);
  });

  it('refuses when another executable of the same name answers first', () => {
    // The fail-open shape itself: something DOES resolve and DOES run, it is
    // just not the stub. A judge stub that missed this way would be the real
    // CLI, and the call would reach a live model.
    const decoyDir = tempDir();
    writeForeignBinary(decoyDir, COMMAND);
    const shimDir = tempDir();
    writeCommandShim(shimDir, COMMAND, bodyWritingSentinel(join(shimDir, 'ran')));
    const env = { ...shimEnv(shimDir), PATH: shimmedPath(decoyDir, shimEnv(shimDir).PATH) };

    const err = errorFrom(() => {
      assertShimResolves(COMMAND, env, shimShell);
    });
    expect(err?.message).toContain('did not resolve to the test stub');
    // Paired control: the weaker "did the spawn work?" check passes here. The
    // decoy answers the probe cleanly — it just is not ours — so only an
    // identity check can tell this case from the passing one above.
    expect(spawnSucceeded(COMMAND, env)).toBe(true);
  });

  it('passes its shell option through to the spawn', () => {
    // Proven by the DIFFERENCE a shell makes to the SAME missing command, so it
    // holds on either platform and needs no shim to exist. Shell-free, the spawn
    // never starts and libuv reports ENOENT; shelled, the interpreter DOES start,
    // fails to find the name itself, and reports its own exit status. An option
    // the probe ignored would make the two messages identical — and on Windows
    // that difference is the whole reason these cases can run at all.
    const env = shimEnv();

    const shellFree = errorFrom(() => {
      assertShimResolves(COMMAND, env, { shell: false });
    });
    const shelled = errorFrom(() => {
      assertShimResolves(COMMAND, env, { shell: true });
    });

    expect(shellFree?.message).toContain('code=ENOENT');
    expect(shelled?.message).not.toContain('code=ENOENT');
    expect(shelled?.message).toMatch(/status=\d+/);
  });

  it('names the live-call consequence and the Windows cause in its refusal', () => {
    const err = errorFrom(() => {
      assertShimResolves(COMMAND, shimEnv(), shimShell);
    });
    // A setup failure is only useful if it says why continuing is unsafe.
    expect(err?.message).toContain('does NOT fail closed');
    expect(err?.message).toContain('PATHEXT');
  });
});

describe('the platform branch, driven from either host', () => {
  // The win32 shim is a `.cmd` launcher, which POSIX cannot execute; the POSIX
  // shim is an extensionless file, which Windows will not resolve for a bare
  // name. So writing the OTHER platform's form is a resolution failure on this
  // one — which is exactly what makes it a live check of the refusal path
  // rather than an assertion about a string.
  const otherPlatform = process.platform === 'win32' ? 'linux' : 'win32';

  it(`refuses a shim written for ${otherPlatform} while running on ${process.platform}`, () => {
    const binDir = tempDir();
    const written = writeCommandShim(
      binDir,
      COMMAND,
      bodyWritingSentinel(join(binDir, 'ran')),
      otherPlatform,
    );

    // Pin the ARTIFACT, not just the refusal. A branch that wrote nothing at all
    // would also refuse, and would look identical here — so a POSIX runner
    // checking only the throw proves nothing about what win32 gets.
    if (otherPlatform === 'win32') {
      expect(written.endsWith(`${COMMAND}.cmd`)).toBe(true);
      expect(existsSync(written)).toBe(true);
      expect(existsSync(join(binDir, `${COMMAND}-shim.js`))).toBe(true);
    } else {
      expect(written).toBe(join(binDir, COMMAND));
      expect(existsSync(written)).toBe(true);
    }

    const env = shimEnv(binDir);
    const err = errorFrom(() => {
      assertShimResolves(COMMAND, env, shimShell);
    });
    expect(err?.message).toContain('did not resolve to the test stub');
  });

  // The launcher names its script by absolute path, and this is a real defect
  // that shipped: %~dp0 reads as "the directory this batch file is in" and is
  // not that. %0 holds the name AS TYPED, so for a batch cmd.exe resolved from
  // PATH under a bare name, %~dp0 expands against the CURRENT DIRECTORY. Every
  // shim-driven suite in this package went red on Windows the moment the spawn
  // under test grew a cwd anchor, with node reporting `Cannot find module` for
  // a path in the anchored directory that nothing had written.
  //
  // Driven with an explicit platform so it runs on every host: the bug is in
  // the bytes written, and a POSIX runner can read those.
  it('names the shim script by absolute path, never through %~dp0', () => {
    const binDir = tempDir();
    const written = writeCommandShim(
      binDir,
      COMMAND,
      bodyWritingSentinel(join(binDir, 'ran')),
      'win32',
    );

    const launcher = readFileSync(written, 'utf8');
    expect(launcher).toContain(join(binDir, `${COMMAND}-shim.js`));
    expect(launcher).not.toContain('%~dp0');
  });

  it('writes the running platform form under an explicit platform argument too', () => {
    // Guards the parameter itself: a `platform` argument the writer ignores
    // would leave the case above passing for the wrong reason — every shim
    // would be the running platform's, and a `.cmd` would never be written.
    const binDir = tempDir();
    const written = writeCommandShim(
      binDir,
      COMMAND,
      bodyWritingSentinel(join(binDir, 'ran')),
      process.platform,
    );
    expect(written.endsWith('.cmd')).toBe(process.platform === 'win32');
    expect(
      errorFrom(() => {
        assertShimResolves(COMMAND, shimEnv(binDir), shimShell);
      }),
    ).toBeUndefined();
  });
});

describe('SHIM_NEEDS_SHELL and the Windows system bits', () => {
  // These carry over from the deleted `shim-unsupported.ts`, whose own suite made
  // the same argument: a constant every caller spends through `skipIf` or a spawn
  // option is the one shape a green run cannot vouch for, because getting it
  // wrong changes what runs rather than what asserts. The coverage is
  // platform-split and no single leg catches every way it can be wrong —
  // `= true` fails off win32, `= false` fails on it — which is why it matters on
  // a workspace that runs ubuntu, macOS and Windows.
  it('is exactly the win32 predicate, not a hardcoded constant', () => {
    expect(SHIM_NEEDS_SHELL).toBe(process.platform === 'win32');
    expect(typeof SHIM_NEEDS_SHELL).toBe('boolean');
  });

  it('contributes nothing to a POSIX child env', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('win32 is the platform these exist for');
      return;
    }
    // A non-empty value here would put host state into envs whose narrowness is
    // the point — the journey harnesses build theirs from scratch precisely so a
    // real CLI is unreachable.
    expect(WINDOWS_SYSTEM_DIRS).toEqual([]);
    expect(WINDOWS_SYSTEM_ENV).toEqual({});
  });

  it('names the system dir a shelled spawn is found through, on the platform that needs it', (ctx) => {
    if (process.platform !== 'win32') {
      ctx.skip('there is no System32 to name off win32');
      return;
    }
    expect(WINDOWS_SYSTEM_DIRS.length).toBeGreaterThan(0);
    expect(WINDOWS_SYSTEM_ENV.COMSPEC).toBeTruthy();
  });
});

describe('shimMarker', () => {
  it('is per command, so one command s shim cannot satisfy another s probe', () => {
    expect(shimMarker('alpha')).not.toBe(shimMarker('beta'));
  });
});
