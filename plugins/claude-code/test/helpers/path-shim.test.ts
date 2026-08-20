import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import {
  assertCommandNotOnPath,
  assertShimResolves,
  NODE_BIN,
  nodeOnlyDir,
  nodeOnlyPathEntries,
  SHIM_NEEDS_NODE_ON_PATH,
  SHIM_NEEDS_SHELL,
  shimMarker,
  shimmedPath,
  shimNeedsNodeOnPath,
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

// The env a probe is run with: a dir holding node ALONE for a POSIX shim's
// shebang — never node's own bin dir, which under a shared install prefix
// carries `npm i -g`'s shims beside the interpreter — plus (win32 only) the
// system dirs cmd.exe itself is found through.
//
// Through `nodeOnlyPathEntries` rather than `nodeOnlyDir`, for the reason that
// wrapper exists: on win32 the shim is a `.cmd` naming `process.execPath`
// outright, so nothing reads the interpreter off PATH, and materialising one
// there costs a copy of the whole binary wherever the platform refuses the link
// — which is the ordinary un-elevated Windows account. Called once per case,
// this is the same shape `launcherEnv` uses in the e2e suites.
const shimEnv = (binDir?: string): NodeJS.ProcessEnv => ({
  ...WINDOWS_SYSTEM_ENV,
  PATH: shimmedPath(
    binDir ?? '',
    [...nodeOnlyPathEntries(tempDir()), ...WINDOWS_SYSTEM_DIRS].join(delimiter),
  ),
});

// `node --version` through `PATH` alone, the way a POSIX shim's `#!/usr/bin/env
// node` line reaches the interpreter. Shell-free on every platform: libuv's own
// search tries `.exe`, so a bare `node` finds `node.exe` without one.
const nodeVersionVia = (dir: string): string =>
  execFileSync('node', ['--version'], {
    env: { ...WINDOWS_SYSTEM_ENV, PATH: dir },
    encoding: 'utf8',
    timeout: 20_000,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();

afterEach(() => {
  while (dirs.length > 0) removeTree(dirs.pop() ?? '');
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

describe('nodeOnlyDir', () => {
  it('holds node and NOTHING else, in a fresh dir under the parent it was given', () => {
    // The whole property. `dirname(process.execPath)` fails it under nvm — or any
    // prefix node shares with its global installs — because `npm i -g` writes
    // its bin shims beside the binary, so a PATH built from node's own dir
    // carries the real `aka` too. An exact listing is what pins "nothing else":
    // a `toContain` would pass with a sibling in the dir, which is the defect.
    const parent = tempDir();
    const dir = nodeOnlyDir(parent);

    expect(dirname(dir)).toBe(parent);
    expect(readdirSync(dir)).toEqual([NODE_BIN]);
  });

  it('is fresh per call, so two callers never share a dir', () => {
    const parent = tempDir();
    expect(nodeOnlyDir(parent)).not.toBe(nodeOnlyDir(parent));
  });

  it('reaches THIS process s node by bare name, from a PATH holding only that dir', () => {
    // What a shebang needs, asked the way a shebang asks: bare name, PATH alone.
    // The version pins that the interpreter reached is this one and not some
    // other node the search happened upon.
    const dir = nodeOnlyDir(tempDir());
    expect(nodeVersionVia(dir)).toBe(process.version);
  });

  it('links rather than copies where the platform grants a link', () => {
    const dir = nodeOnlyDir(tempDir());
    const target = join(dir, NODE_BIN);

    // Followed: whatever was written, it is a regular file when read through.
    expect(statSync(target).isFile()).toBe(true);
    // Not followed: the cheap branch is the one taken where it can be. A file
    // symlink on Windows needs a privilege an ordinary account may lack, so the
    // branch is not pinned there — the copy case below is what covers that leg.
    if (process.platform !== 'win32') {
      expect(lstatSync(target).isSymbolicLink()).toBe(true);
      expect(readlinkSync(target)).toBe(process.execPath);
    }
  });

  it('routes the link through the seam it was given', () => {
    // Guards the parameter itself: a `symlink` option the helper ignored would
    // leave the fallback case below passing for the wrong reason on a Windows
    // account without the privilege — every dir would be a copy, and no case
    // could tell an ignored seam from a refused link.
    const calls: [string, string][] = [];
    const dir = nodeOnlyDir(tempDir(), {
      symlink: (target, path) => {
        calls.push([target, path]);
        symlinkSync(target, path);
      },
    });
    expect(calls).toEqual([[process.execPath, join(dir, NODE_BIN)]]);
  });

  it('falls back to a copy when the link is refused, and the copy still runs', () => {
    // Driven through the seam so the branch is reachable from a host that grants
    // symlinks; the real refusal (a Windows account without the privilege) is a
    // leg no runner here takes.
    const dir = nodeOnlyDir(tempDir(), {
      symlink: () => {
        throw new Error('EPERM: symlink privilege not held (injected)');
      },
    });
    const target = join(dir, NODE_BIN);

    // Still node and nothing else — the refused link left no stray behind.
    expect(readdirSync(dir)).toEqual([NODE_BIN]);
    // A real file with the binary's own bytes, not a link and not a stub.
    expect(lstatSync(target).isSymbolicLink()).toBe(false);
    expect(lstatSync(target).isFile()).toBe(true);
    expect(statSync(target).size).toBe(statSync(process.execPath).size);
    // And it runs, which is what the shebang will ask of it.
    expect(nodeVersionVia(dir)).toBe(process.version);
  });
});

describe('nodeOnlyPathEntries', () => {
  it('yields NOTHING for the platform whose shim reads no shebang', () => {
    // The decision that matters, driven for win32 from whatever host runs this.
    // Read off the running platform instead and the case asserts nothing on a
    // POSIX runner: `true === true` however the gate is spelled, so dropping it
    // entirely stays green on every leg the suite is actually run on.
    //
    // The cost is why it is worth a case at all. Materialising the interpreter
    // is a link where the platform grants one and a copy of the whole binary —
    // tens of megabytes — where it does not, and Windows is both the platform
    // that may refuse the link and the one that can least afford the write.
    const parent = tempDir();
    expect(nodeOnlyPathEntries(parent, { platform: 'win32' })).toEqual([]);
    // Absent ENTRY means absent DIR: an empty list beside a dir built anyway
    // would read identically at every caller and cost exactly the same.
    expect(readdirSync(parent)).toEqual([]);
  });

  it('yields one dir holding node alone for a platform whose shim does', () => {
    const parent = tempDir();
    const [dir] = nodeOnlyPathEntries(parent, { platform: 'linux' });

    expect(dirname(dir ?? '')).toBe(parent);
    expect(readdirSync(dir ?? '')).toEqual([NODE_BIN]);
  });

  it('decides on the RUNNING platform by default', () => {
    // The default is what every caller uses, so it needs its own case: a
    // parameter honoured only when passed would leave the shipped call site
    // unguarded while both cases above stayed green.
    const parent = tempDir();
    expect(nodeOnlyPathEntries(parent)).toHaveLength(SHIM_NEEDS_NODE_ON_PATH ? 1 : 0);
    expect(SHIM_NEEDS_NODE_ON_PATH).toBe(shimNeedsNodeOnPath(process.platform));
  });

  it('states the platform rule the same way for both branches', () => {
    // The rule itself, independent of the host: win32 alone needs no entry.
    expect(shimNeedsNodeOnPath('win32')).toBe(false);
    for (const platform of ['linux', 'darwin', 'freebsd'] as const) {
      expect(shimNeedsNodeOnPath(platform)).toBe(true);
    }
  });

  it('reaches THIS process s node through the dir it yields', (ctx) => {
    if (!SHIM_NEEDS_NODE_ON_PATH) ctx.skip('this platform needs no node on PATH');
    const [dir] = nodeOnlyPathEntries(tempDir());
    expect(nodeVersionVia(dir ?? '')).toBe(process.version);
  });

  it('forwards the link seam, so the fallback is reachable through it', () => {
    // Without this the option could be dropped on the way through and the
    // wrapper would look identical from every caller.
    const calls: string[] = [];
    nodeOnlyPathEntries(tempDir(), {
      platform: 'linux',
      symlink: (target, path) => {
        calls.push(path);
        symlinkSync(target, path);
      },
    });
    expect(calls).toHaveLength(1);
  });
});

describe('assertCommandNotOnPath', () => {
  const REAL = 'aka';

  // Every name a bare `aka` could resolve to: the POSIX file, the `.cmd` shim
  // an npm global install writes on Windows, a `.exe`, and the EXTENSIONLESS
  // Bourne launcher npm writes beside the shim. Each is planted on its own, so
  // a match narrowed to one form fails on the others rather than on a mixture.
  const RESOLVABLE = ['aka', 'aka.cmd', 'aka.exe', 'aka.bat', 'AKA.CMD'];

  const pathOf = (...dirs: string[]): NodeJS.ProcessEnv => ({ PATH: dirs.join(delimiter) });

  it('passes on a PATH holding nothing that resolves', () => {
    // The positive control. Without it every refusal case below could be
    // satisfied by a check that throws unconditionally.
    const dir = tempDir();
    writeFileSync(join(dir, 'akashic-unrelated'), '');
    writeFileSync(join(dir, 'claude'), '');
    expect(
      errorFrom(() => {
        assertCommandNotOnPath(pathOf(dir), REAL);
      }),
    ).toBeUndefined();
  });

  it.each(RESOLVABLE)('refuses a planted %s', (name) => {
    const dir = tempDir();
    writeFileSync(join(dir, name), '');

    const err = errorFrom(() => {
      assertCommandNotOnPath(pathOf(dir), REAL);
    });
    // Named, so the refusal sends the reader at the file rather than at PATH.
    expect(err?.message).toContain(join(dir, name));
    expect(err?.message).toContain('SETUP');
  });

  it('scans every dir on PATH, not just the first', () => {
    // A loop that returned after the first clean dir would pass the control
    // case above and miss every real one, since the shim dir is always first.
    const clean = tempDir();
    const dirty = tempDir();
    writeFileSync(join(dirty, REAL), '');

    expect(
      errorFrom(() => {
        assertCommandNotOnPath(pathOf(clean, dirty), REAL);
      })?.message,
    ).toContain(join(dirty, REAL));
  });

  it('decides by LISTING, so it never runs what it finds', () => {
    // The check stands in front of a launcher that would start a detached
    // server, so it must not be able to start one itself. Pinned by planting a
    // shim that records having run: a probe-by-spawn would trip it.
    const dir = tempDir();
    const sentinel = join(tempDir(), 'ran');
    writeCommandShim(dir, REAL, bodyWritingSentinel(sentinel));

    expect(
      errorFrom(() => {
        assertCommandNotOnPath(pathOf(dir), REAL);
      }),
    ).toBeDefined();
    expect(existsSync(sentinel)).toBe(false);
  });

  it('tolerates a PATH entry that does not exist', () => {
    // Nothing resolves through a dir that is not there, so refusing on one
    // would report a resolution this PATH cannot perform — and an unguarded
    // readdir would throw ENOENT, naming the wrong problem entirely.
    const missing = join(tempDir(), 'never-created');
    expect(
      errorFrom(() => {
        assertCommandNotOnPath(pathOf(missing), REAL);
      }),
    ).toBeUndefined();
  });

  it('tolerates a PATH entry that is a file rather than a directory', () => {
    // The second entry nothing resolves THROUGH. `execvp` tries `<file>/aka`,
    // gets ENOTDIR and walks on to the next entry, so a stale file on PATH is
    // the "nothing can be here" case exactly as a missing dir is — and refusing
    // would report a read problem where there was nothing to read. A generic
    // NodeJS.ProcessEnv is what this takes, so a caller passing `process.env` on
    // a host whose PATH carries one gets a hard setup failure for a directory
    // that could never have resolved anything.
    const notADir = join(tempDir(), 'file-on-path');
    writeFileSync(notADir, '');

    expect(
      errorFrom(() => {
        assertCommandNotOnPath(pathOf(notADir), REAL);
      }),
    ).toBeUndefined();
  });

  it('rethrows a read failure that leaves the premise unestablished', (ctx) => {
    // The other half, and the one a blanket `catch { continue }` loses. Absence
    // and ENOTDIR mean nothing is there to find; a read that fails for any other
    // reason leaves the premise UNESTABLISHED, and this check reporting "nothing
    // resolves" without having looked is the exact failure it exists to prevent.
    //
    // Driven as the live case rather than a stand-in: a POSIX dir with search
    // but not read permission (`--x`). `execvp` executes a known name inside it
    // while `readdir` refuses with EACCES, so a swallowed error hides a binary
    // that really is reachable. ENOTDIR was the earlier stand-in and is no
    // longer one — it is now a skip, which is what the case above pins.
    const dir = tempDir();
    writeFileSync(join(dir, REAL), '');
    chmodSync(dir, 0o111);
    // chmod is a no-op on Windows and again as root, and there the read
    // succeeds — so there is no unreadable directory to assert about. Skipped
    // rather than returned: a pass here would be a claim this run never checked.
    let denied = false;
    try {
      readdirSync(dir);
    } catch {
      denied = true;
    }
    if (!denied) {
      chmodSync(dir, 0o755);
      ctx.skip('this platform/account ignores a --x directory, so readdir still succeeds');
    }

    const err = errorFrom(() => {
      assertCommandNotOnPath(pathOf(dir), REAL);
    });
    // Restored before the assertions, so a failure does not also break teardown.
    chmodSync(dir, 0o755);
    expect(err).toBeDefined();
    expect((err as NodeJS.ErrnoException).code).toBe('EACCES');
  });

  it('refuses a command in the cwd on win32, which resolves before PATH', () => {
    // The axis PATH alone cannot see. Windows searches the working directory
    // first, so a real `aka` there is resolved with a spotless PATH — and the
    // launcher's win32 plan anchors its spawn at homedir(), a directory this
    // check has no other way to know about.
    const cwd = tempDir();
    const clean = tempDir();
    for (const name of RESOLVABLE) {
      rmSync(join(cwd, name), { force: true });
      writeFileSync(join(cwd, name), '');

      const err = errorFrom(() => {
        assertCommandNotOnPath(pathOf(clean), REAL, { cwd, platform: 'win32' });
      });
      expect(err, `a "${name}" in the cwd must refuse`).toBeDefined();
      // Named as the cwd rather than as a PATH entry: the two are fixed by
      // different edits, so a refusal that misreports which one wastes the hint.
      expect(err?.message).toContain('BEFORE PATH');
      rmSync(join(cwd, name), { force: true });
    }
  });

  it('ignores the cwd on POSIX, where resolution never consults it', () => {
    // Not symmetry for its own sake: POSIX PATH lookup does not read the cwd, so
    // refusing there would block a case over a binary that could never be
    // reached — and the call site passes `plan.options.cwd` unconditionally.
    const cwd = tempDir();
    writeFileSync(join(cwd, REAL), '');

    expect(
      errorFrom(() => {
        assertCommandNotOnPath(pathOf(tempDir()), REAL, { cwd, platform: 'linux' });
      }),
    ).toBeUndefined();
  });

  it('still walks PATH when a cwd is given, and tolerates a missing one', () => {
    // The cwd is an ADDITIONAL entry, not a replacement: a check that returned
    // after reading it would pass every PATH case in this file.
    const onPath = tempDir();
    writeFileSync(join(onPath, REAL), '');
    expect(
      errorFrom(() => {
        assertCommandNotOnPath(pathOf(onPath), REAL, { cwd: tempDir(), platform: 'win32' });
      }),
    ).toBeDefined();

    // A cwd that does not exist is the ENOENT skip, reached through the new arm.
    expect(
      errorFrom(() => {
        assertCommandNotOnPath(pathOf(tempDir()), REAL, {
          cwd: join(tempDir(), 'never-created'),
          platform: 'win32',
        });
      }),
    ).toBeUndefined();
  });

  it('ignores empty PATH segments rather than reading the cwd', () => {
    // An empty segment means the CURRENT DIRECTORY to execvp — reading it here
    // would refuse on whatever the repo happens to hold.
    expect(
      errorFrom(() => {
        assertCommandNotOnPath({ PATH: '' }, REAL);
      }),
    ).toBeUndefined();
    expect(
      errorFrom(() => {
        assertCommandNotOnPath({}, REAL);
      }),
    ).toBeUndefined();
  });

  it('matches the command it was given, not a name baked in', () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'codex'), '');

    expect(
      errorFrom(() => {
        assertCommandNotOnPath(pathOf(dir), 'codex');
      }),
    ).toBeDefined();
    expect(
      errorFrom(() => {
        assertCommandNotOnPath(pathOf(dir), REAL);
      }),
    ).toBeUndefined();
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
