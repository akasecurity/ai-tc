// Guards the env handed to a PowerShell child.
//
// This exists because the defect it covers is invisible everywhere except the
// one platform that runs it. `Get-FileHash` lives in Microsoft.PowerShell
// .Utility, autoloaded off `PSModulePath` — and pwsh 7 and Windows PowerShell
// 5.1 need DIFFERENT values for it. GitHub Actions runs Windows `run:` steps
// under pwsh by default, so a spawn that inherits the step's environment hands
// 5.1 a pwsh-7 module path, 5.1 cannot autoload its own standard library, and
// install.ps1 dies at the hashing step with CommandNotFoundException — a failure
// that names a cmdlet and mentions neither the module path nor the edition.
//
// The stripping runs on every host, so its regression is catchable on every
// host; only its CONSEQUENCE is Windows-only. Hence a unit test rather than
// trusting the Windows leg to notice.
import { chmodSync, existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import {
  assertHostArchitecture,
  describeRun,
  type InstallerRun,
  powershellEnv,
  privateCacheHome,
  probePowershell,
  runInstallPs1,
  runScript,
  type ScriptRunner,
} from './run-installer.ts';

describe('powershellEnv', () => {
  // `extra` is merged before the strip runs, so a key supplied here goes through
  // exactly the loop a host-supplied one does — which is what makes this a real
  // test of the stripping rather than of the merge. Injecting via `extra` also
  // keeps the case off `process.env`, which it must not mutate for its
  // neighbours.
  it.each(['PSModulePath', 'PSMODULEPATH', 'psmodulepath', 'PsModulePath'])(
    'strips %s, whatever its casing',
    (spelling) => {
      const env = powershellEnv({ [spelling]: 'C:\\Program Files\\PowerShell\\7\\Modules' });

      const survivors = Object.keys(env).filter((k) => k.toLowerCase() === 'psmodulepath');
      expect(survivors).toEqual([]);
    },
  );

  it('keeps everything else, so the child still resolves its own tools', () => {
    const env = powershellEnv({
      AKA_DOWNLOAD_BASE: 'http://127.0.0.1:1/',
      PSModulePath: 'drop me',
    });

    // Positive control on the same object the absence check reads: an env that
    // came back empty would satisfy the strip assertion above vacuously.
    expect(env.AKA_DOWNLOAD_BASE).toBe('http://127.0.0.1:1/');
    expect(Object.keys(env).length).toBeGreaterThan(1);
  });

  it('lets a caller override a host value', () => {
    // The overrides are how a fixture base reaches the script at all; a strip
    // that rebuilt the object from HOST_ENV alone would silently drop them.
    expect(powershellEnv({ AKA_VERSION: '9.9.9' }).AKA_VERSION).toBe('9.9.9');
  });
});

// Both branches are driven with an injected platform rather than gated on the
// real one, so the win32 half is covered from every runner. A platform guard
// here would leave the case that matters unexercised on the two legs that run
// most of the suite.
describe('assertHostArchitecture', () => {
  const ARCH = 'PROCESSOR_ARCHITECTURE';

  it.each([
    ['unset', {}, 'unset'],
    ['empty', { [ARCH]: '' }, 'empty'],
  ])('refuses a win32 host whose architecture is %s', (_label, env, word) => {
    const error = errorFrom(() => {
      assertHostArchitecture(env, 'win32');
    });

    // What it SAYS before what it omits: a never-thrown error arrives as
    // undefined, and every `toContain` below would then read as vacuous.
    expect(error).toBeDefined();
    expect(error?.message).toContain(ARCH);
    expect(error?.message).toContain(word);
    // The refusal has to point at the cause, or it is one more message that
    // names the script and leaves the reader where they started.
    expect(error?.message).toContain('passThroughEnv');
    expect(error?.message).toContain('setup failure');
  });

  it('accepts a win32 host that reports an architecture', () => {
    expect(() => {
      assertHostArchitecture({ [ARCH]: 'AMD64' }, 'win32');
    }).not.toThrow();
  });

  // Asserted non-empty rather than equal to AMD64 on purpose: an arm64 runner
  // must reach install.ps1's own unsupported-architecture refusal, which is a
  // property of the script this harness is not entitled to pre-empt.
  it('accepts an unsupported architecture, leaving the refusal to the script', () => {
    expect(() => {
      assertHostArchitecture({ [ARCH]: 'ARM64' }, 'win32');
    }).not.toThrow();
  });

  it.each<NodeJS.Platform>(['darwin', 'linux'])(
    'says nothing on %s, where the variable does not exist',
    (platform) => {
      expect(() => {
        assertHostArchitecture({}, platform);
      }).not.toThrow();
    },
  );
});

/**
 * The retry inside `runScript`, driven through its injected spawner.
 *
 * It exists for a crash that cannot be provoked on demand — pwsh dying inside
 * .NET's own assembly-name parser before the script it was handed begins — so
 * against a real PowerShell the retry branch is dead code on every leg that
 * runs this suite. The failure is injected instead.
 *
 * `compressArchive` already retries the same corruption where it BUILDS the
 * fixture archive, and this is the other call site it reaches. The two see it
 * differently, which is why one check does not cover both: the archive build
 * gets a child killed outright (`status: null, signal: 'SIGABRT'`), while pwsh
 * running a `-File` script gets far enough to print an unhandled-exception
 * trace and exit non-zero. So this one discriminates on the TEXT.
 */

// The shape the corrupted run really produces. Only the two markers matter, so
// the assembly-name tail is left out rather than transcribed: a real one is a
// version and a public-key token, and a literal of that shape in a public
// repository reads as a credential to this product's own scanner.
const CLR_ABORT_STDERR =
  'Unhandled exception. System.IO.FileLoadException: The given assembly name was invalid.\n' +
  "File name: 'System.Private.Uri, <truncated mid-token by the crash>'";

/**
 * An `InstallerRun` for a case that cares about two of its fields.
 *
 * A builder rather than five object literals: `signal` and `elapsedMs` say
 * nothing about the retry, and spelling them at every site makes the field the
 * case IS about harder to see — while a sixth field added later would be five
 * more edits, each of which reads as a decision and is not one.
 */
function runOf(over: Partial<InstallerRun>): InstallerRun {
  return { status: 0, signal: null, elapsedMs: 1, stdout: '', stderr: '', ...over };
}

function aborts(times: number, then: InstallerRun): { run: ScriptRunner; calls: () => number } {
  let calls = 0;
  const run: ScriptRunner = () => {
    calls += 1;
    if (calls <= times) {
      return Promise.resolve(runOf({ status: 134, stderr: CLR_ABORT_STDERR }));
    }
    return Promise.resolve(then);
  };
  return { run, calls: () => calls };
}

const REFUSAL: InstallerRun = runOf({ status: 1, stderr: 'checksum mismatch' });
const SUCCESS: InstallerRun = runOf({ stdout: 'ok' });

describe('runScript retries a CLR startup abort', () => {
  it('re-runs past an abort and returns the run that happened', async () => {
    const { run, calls } = aborts(1, REFUSAL);
    const result = await runScript('pwsh', [], {}, run);
    // The script's own refusal, not the crash — which is the whole point: the
    // assertion the caller makes is about what install.ps1 said.
    expect(result).toEqual(REFUSAL);
    expect(calls()).toBe(2);
  });

  it('gives up rather than looping, and hands back the last abort', async () => {
    const { run, calls } = aborts(Infinity, SUCCESS);
    const result = await runScript('pwsh', [], {}, run);
    // Bounded: a host where this fails three times running is not flaking, and
    // the caller sees the crash rather than a hang.
    expect(calls()).toBe(3);
    expect(result.stderr).toBe(CLR_ABORT_STDERR);
  });

  it('does NOT retry a script that ran and failed', async () => {
    // The refusals this suite exists to assert all exit non-zero. Retrying one
    // would re-run it for no reason, and a budget spent here is a budget not
    // available for the crash.
    const { run, calls } = aborts(0, REFUSAL);
    const result = await runScript('pwsh', [], {}, run);
    expect(result).toEqual(REFUSAL);
    expect(calls()).toBe(1);
  });

  it('does NOT retry a crash the script itself caused', async () => {
    // An unhandled .NET exception from a `Compress-Archive` the SCRIPT ran is a
    // real failure. Only the assembly-name parser marks the startup corruption,
    // so both markers are required and this one carries the first alone.
    const selfInflicted: InstallerRun = runOf({
      status: 1,
      stderr: 'Unhandled exception. System.IO.IOException: There is not enough space on the disk.',
    });
    const { run, calls } = aborts(0, selfInflicted);
    const result = await runScript('pwsh', [], {}, run);
    expect(result).toEqual(selfInflicted);
    expect(calls()).toBe(1);
  });

  it('does NOT retry a zero exit, whatever it wrote', async () => {
    // A run that happened is a run that happened. Without this a script that
    // printed the marker and succeeded would be re-run, and the second run's
    // side effects would land on top of the first's.
    const noisySuccess: InstallerRun = runOf({ stderr: CLR_ABORT_STDERR });
    const { run, calls } = aborts(0, noisySuccess);
    const result = await runScript('pwsh', [], {}, run);
    expect(result).toEqual(noisySuccess);
    expect(calls()).toBe(1);
  });
});

/**
 * The probe and every install.ps1 attempt get a cache home of their own off
 * Windows.
 *
 * pwsh keeps a startup profile in its cache home that every start reads and
 * then rewrites on the way out. Shared between concurrent starts, it can be left
 * holding a damaged assembly name inside records that still parse, and a start
 * that reads it dies in .NET's assembly-name parser before its command runs —
 * the crash `runScript` retries. The retry cannot get past it on its own: the
 * crashed start writes nothing back, so the next attempt reads the same file.
 *
 * Provoking that needs a real pwsh and a damaged profile, and whether a given
 * damage crashes is a race inside .NET, so it is not driven here. What is pinned
 * is the property that takes the shared file off the path: each child sees an
 * empty home no other process has written to, and none is left behind.
 */

/** What a child found in its cache home at the moment it was spawned. */
interface HomeAtSpawn {
  dir: string | undefined;
  /** undefined when the directory did not exist. */
  entries: string[] | undefined;
}

function homeAtSpawn(env: NodeJS.ProcessEnv): HomeAtSpawn {
  const dir = env.XDG_CACHE_HOME;
  return { dir, entries: dir !== undefined && existsSync(dir) ? readdirSync(dir) : undefined };
}

// Under the OS temp dir, not merely a string: `''` is a string, and
// `join('', 'powershell')` is a path in the working directory.
const TEMP_PREFIX = new RegExp(`^${tmpdir().replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')}`, 'u');

const EMPTY_HOME: HomeAtSpawn = { dir: expect.stringMatching(TEMP_PREFIX) as string, entries: [] };

/**
 * Refuse a home this suite may not write into: anything but a directory under
 * the OS temp dir. A regression hands a case the HOST's cache home, or `''` —
 * which `join` resolves against the checkout — and planting a fake profile in
 * either is the one thing this suite must never do to the machine running it.
 * Refused, the case still fails.
 */
function assertPrivateHome(dir: string | undefined): asserts dir is string {
  if (dir === undefined || !TEMP_PREFIX.test(dir)) {
    throw new Error(`not a private cache home: ${String(dir)}`);
  }
}

/**
 * That a disposed home is gone, wherever that can be asserted. `removeTree`
 * tolerates a tree Windows still holds and leaves it to the temp sweeper — its
 * stated contract — so on a win32 host this pins only that the home was a
 * private one and that dispose returned.
 */
function expectRemoved(dir: string | undefined): void {
  assertPrivateHome(dir);
  if (process.platform !== 'win32') expect(existsSync(dir)).toBe(false);
}

/** Make `dir` refuse the recursive removal dispose performs; the thunk undoes it and cleans up. */
function lockHome(dir: string): () => void {
  mkdirSync(join(dir, 'powershell'));
  writeFileSync(join(dir, 'powershell', 'StartupProfileData-NonInteractive'), 'profile');
  chmodSync(dir, 0o500);
  return () => {
    chmodSync(dir, 0o700);
    removeTree(dir);
  };
}

// Driven with an injected platform for the reason assertHostArchitecture is:
// both branches have to be reachable from every runner.
describe('privateCacheHome', () => {
  it('gives a POSIX child an empty home that no other process has written to', () => {
    const home = privateCacheHome('linux');
    try {
      expect(homeAtSpawn(home.env)).toEqual(EMPTY_HOME);
    } finally {
      home.dispose();
    }
  });

  it('never hands two children the same home', () => {
    const first = privateCacheHome('linux');
    try {
      const second = privateCacheHome('linux');
      try {
        assertPrivateHome(first.env.XDG_CACHE_HOME);
        expect(second.env.XDG_CACHE_HOME).not.toBe(first.env.XDG_CACHE_HOME);
      } finally {
        second.dispose();
      }
    } finally {
      first.dispose();
    }
  });

  it('removes the home on dispose, with whatever the child wrote into it', () => {
    const home = privateCacheHome('linux');
    const dir = home.env.XDG_CACHE_HOME;
    let disposing = false;
    try {
      assertPrivateHome(dir);
      // What pwsh leaves behind, so the removal has to be recursive. The write
      // succeeding is also the control that the home existed before dispose.
      const profileDir = join(dir, 'powershell');
      mkdirSync(profileDir);
      writeFileSync(join(profileDir, 'StartupProfileData-NonInteractive'), 'profile');
      disposing = true;
      home.dispose();
    } finally {
      // A throw before the dispose above must not leak the home.
      if (!disposing) home.dispose();
    }

    expectRemoved(dir);
  });

  it('sets nothing on win32, where PowerShell does not read XDG_CACHE_HOME', () => {
    const home = privateCacheHome('win32');

    expect(home.env).toEqual({});
    expect(() => {
      home.dispose();
    }).not.toThrow();
  });
});

describe('probePowershell', () => {
  // The probe matters as much as the run it gates. A probe that read a damaged
  // profile would crash, report no PowerShell, and turn every install.ps1 case
  // into a skip — unrun rather than red.
  it('probes under a private home and leaves none behind', () => {
    const seen: HomeAtSpawn[] = [];

    const exe = probePowershell('linux', (_command, _args, env) => {
      seen.push(homeAtSpawn(env));
      return true;
    });

    expect(exe).toBe('pwsh');
    expect(seen).toEqual([EMPTY_HOME]);
    expectRemoved(seen[0]?.dir);
  });

  it('leaves no home behind when nothing starts', () => {
    const seen: HomeAtSpawn[] = [];

    const exe = probePowershell('linux', (_command, _args, env) => {
      seen.push(homeAtSpawn(env));
      return false;
    });

    expect(exe).toBeUndefined();
    expect(seen).toEqual([EMPTY_HOME]);
    expectRemoved(seen[0]?.dir);
  });

  it('tries Windows PowerShell before pwsh on win32', () => {
    const tried: string[] = [];

    const exe = probePowershell('win32', (command) => {
      tried.push(command);
      return command === 'pwsh';
    });

    expect(tried).toEqual(['powershell', 'pwsh']);
    expect(exe).toBe('pwsh');
  });
});

// Driven with an injected platform, as its neighbours are, so both branches run
// from every host — including the env-merge control, which is not platform code.
describe('runInstallPs1 isolates the cache home', () => {
  const OVERRIDES = { base: 'http://localhost:1/', version: '9.9.9', installDir: 'unused' };

  it('hands the run an empty home and removes it afterwards', async () => {
    const seen: HomeAtSpawn[] = [];
    const versions: (string | undefined)[] = [];

    const result = await runInstallPs1(
      'pwsh',
      OVERRIDES,
      (_command, _args, env) => {
        seen.push(homeAtSpawn(env));
        versions.push(env.AKA_VERSION);
        return Promise.resolve(REFUSAL);
      },
      'linux',
    );

    expect(result).toEqual(REFUSAL);
    // The overrides still arrive: a home that REPLACED the env rather than
    // joining it would satisfy every other line here.
    expect(versions).toEqual(['9.9.9']);
    expect(seen).toEqual([EMPTY_HOME]);
    expectRemoved(seen[0]?.dir);
  });

  it('starts a retry from a fresh home, not the one the abort died in', async () => {
    const seen: HomeAtSpawn[] = [];

    const result = await runInstallPs1(
      'pwsh',
      OVERRIDES,
      (_command, _args, env) => {
        const home = homeAtSpawn(env);
        seen.push(home);
        if (seen.length > 1) return Promise.resolve(REFUSAL);
        // The first attempt leaves a profile behind and aborts. A home shared
        // across attempts would hand the retry this exact file.
        assertPrivateHome(home.dir);
        if (home.entries?.length !== 0) throw new Error(`cache home was not empty: ${home.dir}`);
        const profileDir = join(home.dir, 'powershell');
        mkdirSync(profileDir);
        writeFileSync(join(profileDir, 'StartupProfileData-NonInteractive'), 'damaged');
        return Promise.resolve(runOf({ status: 134, stderr: CLR_ABORT_STDERR }));
      },
      'linux',
    );

    expect(result).toEqual(REFUSAL);
    expect(seen).toEqual([EMPTY_HOME, EMPTY_HOME]);
    expect(seen[1]?.dir).not.toBe(seen[0]?.dir);
    for (const { dir } of seen) {
      expectRemoved(dir);
    }
  });

  it('removes the home when the spawn itself fails', async () => {
    const seen: HomeAtSpawn[] = [];

    const error = await runInstallPs1(
      'pwsh',
      OVERRIDES,
      (_command, _args, env) => {
        seen.push(homeAtSpawn(env));
        return Promise.reject(new Error('could not spawn pwsh: ENOENT'));
      },
      'linux',
    ).then(
      () => undefined,
      (err: unknown) => err as Error,
    );

    expect(error?.message).toContain('ENOENT');
    expect(seen).toEqual([EMPTY_HOME]);
    expectRemoved(seen[0]?.dir);
  });

  it('merges no home into the env on win32, where there is none to give', async () => {
    const seen: NodeJS.ProcessEnv[] = [];

    const result = await runInstallPs1(
      'powershell',
      OVERRIDES,
      (_command, _args, env) => {
        seen.push(env);
        return Promise.resolve(REFUSAL);
      },
      'win32',
    );

    expect(result).toEqual(REFUSAL);
    expect(seen.map((env) => env.AKA_VERSION)).toEqual(['9.9.9']);
    // The host's own value, whatever it is: powershellEnv() is that same host
    // env with nothing merged in.
    expect(seen[0]?.XDG_CACHE_HOME).toBe(powershellEnv().XDG_CACHE_HOME);
  });
});

// What a removal that fails does to the outcome it follows. Only POSIX can show
// it: removeTree tolerates a held tree on win32, so no removal failure exists
// there to mask anything, and root ignores the mode that forces one here.
describe('when a cache home cannot be removed', () => {
  const OVERRIDES = { base: 'http://localhost:1/', version: '9.9.9', installDir: 'unused' };
  const WIN32_REASON = 'removeTree tolerates a held tree on win32, so no removal failure exists';
  const ROOT_REASON = 'the mode did not stop the removal on this host (running as root?)';

  it("keeps the spawn's own failure rather than the removal's", async (ctx) => {
    if (process.platform === 'win32') ctx.skip(WIN32_REASON);
    const box: { dir: string | undefined; unlock: (() => void) | undefined } = {
      dir: undefined,
      unlock: undefined,
    };

    const error = await runInstallPs1(
      'pwsh',
      OVERRIDES,
      (_command, _args, env) => {
        box.dir = env.XDG_CACHE_HOME;
        assertPrivateHome(box.dir);
        box.unlock = lockHome(box.dir);
        return Promise.reject(new Error('could not spawn pwsh: ENOENT'));
      },
      'linux',
    ).then(
      () => undefined,
      (err: unknown) => err as Error,
    );

    try {
      // The precondition, or this proves nothing: the removal really failed.
      if (box.dir === undefined || !existsSync(box.dir)) ctx.skip(ROOT_REASON);
      expect(error?.message).toContain('ENOENT');
    } finally {
      box.unlock?.();
    }
  });

  it("keeps the probe runner's own failure rather than the removal's", (ctx) => {
    if (process.platform === 'win32') ctx.skip(WIN32_REASON);
    const box: { dir: string | undefined; unlock: (() => void) | undefined } = {
      dir: undefined,
      unlock: undefined,
    };

    const error = errorFrom(() => {
      probePowershell('linux', (_command, _args, env) => {
        box.dir = env.XDG_CACHE_HOME;
        assertPrivateHome(box.dir);
        box.unlock = lockHome(box.dir);
        throw new Error('the probe runner failed');
      });
    });

    try {
      if (box.dir === undefined || !existsSync(box.dir)) ctx.skip(ROOT_REASON);
      expect(error?.message).toBe('the probe runner failed');
    } finally {
      box.unlock?.();
    }
  });

  it('still reports the failed removal when the run itself succeeded', async (ctx) => {
    if (process.platform === 'win32') ctx.skip(WIN32_REASON);
    const box: { dir: string | undefined; unlock: (() => void) | undefined } = {
      dir: undefined,
      unlock: undefined,
    };

    const outcome = await runInstallPs1(
      'pwsh',
      OVERRIDES,
      (_command, _args, env) => {
        box.dir = env.XDG_CACHE_HOME;
        assertPrivateHome(box.dir);
        box.unlock = lockHome(box.dir);
        return Promise.resolve(REFUSAL);
      },
      'linux',
    ).then(
      (run) => ({ run, error: undefined }),
      (err: unknown) => ({ run: undefined, error: err as NodeJS.ErrnoException }),
    );

    try {
      if (box.dir === undefined || !existsSync(box.dir)) ctx.skip(ROOT_REASON);
      // A leaked home stays loud: off win32 removeTree treats it as a defect.
      // Which errno says so varies by platform — macOS reports ENOTEMPTY rather
      // than the EACCES the mode suggests — so what is pinned is that the run
      // was not returned and a filesystem error was.
      expect(outcome.run).toBeUndefined();
      expect(outcome.error?.code).toMatch(/^E[A-Z]+$/u);
    } finally {
      box.unlock?.();
    }
  });
});

/** The error a thunk threw, captured OUTSIDE its own catch. */
function errorFrom(fn: () => void): Error | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    return err as Error;
  }
}

/**
 * What a failing assertion about a run is allowed to say about it.
 *
 * These read like formatting tests and are not. The assertions that fail
 * intermittently on CI are `expect(status).not.toBe(0)`, which vitest renders
 * as `expected +0 not to be +0` — a message that names neither the script nor
 * anything it did. Three occurrences of one signature produced no evidence
 * between them and two investigations dead-ended for the lack of it, so what
 * this carries is the difference between the next occurrence being an answer
 * and being another investigation.
 */
describe('a real spawn fills the record', () => {
  // Every case above injects a runner, so all of them would pass with
  // `elapsedMs` hardcoded to zero and the signal never read — and the reading
  // this whole record exists for is the one taken from a real child. Driven
  // through the default runner for that reason, against this very Node rather
  // than a PowerShell: the fields are filled by `spawnScript`, which does not
  // care what it started, and requiring an interpreter here would leave the
  // measurement unpinned on exactly the hosts that have none.
  it('reports the status, the streams and a non-zero elapsed', async () => {
    const result = await runScript(
      process.execPath,
      ['-e', 'process.stdout.write("ran"); process.stderr.write("noted")'],
      {},
    );

    expect(result.status).toBe(0);
    expect(result.signal).toBeNull();
    expect(result.stdout).toBe('ran');
    expect(result.stderr).toBe('noted');
    // Not a timing assertion — no budget, no ceiling. Starting a process and
    // reading its output cannot take zero, so a zero here means the clock is
    // not wired rather than that the machine is fast.
    expect(result.elapsedMs).toBeGreaterThan(0);
  });
});

describe('describeRun', () => {
  it('names the three readings that separate a run from a non-run', () => {
    const line = describeRun(runOf({ status: 0, signal: null, elapsedMs: 107 }));

    expect(line).toContain('status=0');
    expect(line).toContain('signal=null');
    expect(line).toContain('elapsed=107ms');
  });

  it('carries both streams', () => {
    const line = describeRun(runOf({ stdout: 'downloading', stderr: 'checksum mismatch' }));

    expect(line).toContain('downloading');
    expect(line).toContain('checksum mismatch');
  });

  it('says an empty stream is empty rather than rendering nothing', () => {
    // "the script printed nothing" and "the message was lost on the way here"
    // look identical when an empty stream renders as an empty string, and they
    // point at opposite causes.
    const line = describeRun(runOf({ stdout: '', stderr: '' }));

    expect(line).toContain('stdout: (empty)');
    expect(line).toContain('stderr: (empty)');
  });

  it('excerpts a long stream and says how long it really was', () => {
    // A 46 MB archive download can print a great deal, and a message that
    // scrolls the failure off the top of a CI log is one nobody reads.
    const long = 'z'.repeat(5_000);

    const line = describeRun(runOf({ stderr: long }));

    expect(line.length).toBeLessThan(2_000);
    expect(line).toContain('(5000 chars)');
  });

  it('reaches the failure message vitest actually renders', () => {
    // The assumption the whole change rests on, and it is not self-evident:
    // `expect(actual, message)` is vitest's second parameter, so a runner
    // upgrade that stopped honouring it would leave every call site above
    // compiling, passing, and carrying nothing. Driven through the real
    // assertion rather than asserted about it.
    const run = runOf({ status: 0, elapsedMs: 107, stderr: 'nothing was downloaded' });

    const error = errorFrom(() => {
      expect(run.status, describeRun(run)).not.toBe(0);
    });

    expect(error).toBeDefined();
    expect(error?.message).toContain('elapsed=107ms');
    expect(error?.message).toContain('nothing was downloaded');
  });

  it('keeps a stream that fits, whole', () => {
    // The control on the case above, and it has to say BOTH things. An excerpt
    // that truncated everything would satisfy the length bound for ever — and
    // so would one that took the truncation branch on EVERY stream, because
    // `slice(0, EXCERPT_CHARS)` of a 75-character string still contains the
    // whole string. It just arrives annotated as an excerpt of itself, and a
    // `toContain` alone cannot tell the two apart: forcing that branch left all
    // of this file's cases green.
    //
    // One bound call, so the presence check and the absence check describe the
    // same bytes rather than two independent reads.
    const whole = 'aka: checksum mismatch for aka-1.2.3-win32-x64.zip -- refusing to install.';
    const line = describeRun(runOf({ stderr: whole }));

    expect(line).toContain(whole);
    expect(line).not.toContain('chars)');
  });
});
