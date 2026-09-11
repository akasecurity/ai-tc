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
import { describe, expect, it } from 'vitest';

import {
  assertHostArchitecture,
  type InstallerRun,
  powershellEnv,
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

function aborts(times: number, then: InstallerRun): { run: ScriptRunner; calls: () => number } {
  let calls = 0;
  const run: ScriptRunner = () => {
    calls += 1;
    if (calls <= times) {
      return Promise.resolve({ status: 134, stdout: '', stderr: CLR_ABORT_STDERR });
    }
    return Promise.resolve(then);
  };
  return { run, calls: () => calls };
}

const REFUSAL: InstallerRun = { status: 1, stdout: '', stderr: 'checksum mismatch' };
const SUCCESS: InstallerRun = { status: 0, stdout: 'ok', stderr: '' };

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
    const selfInflicted: InstallerRun = {
      status: 1,
      stdout: '',
      stderr: 'Unhandled exception. System.IO.IOException: There is not enough space on the disk.',
    };
    const { run, calls } = aborts(0, selfInflicted);
    const result = await runScript('pwsh', [], {}, run);
    expect(result).toEqual(selfInflicted);
    expect(calls()).toBe(1);
  });

  it('does NOT retry a zero exit, whatever it wrote', async () => {
    // A run that happened is a run that happened. Without this a script that
    // printed the marker and succeeded would be re-run, and the second run's
    // side effects would land on top of the first's.
    const noisySuccess: InstallerRun = { status: 0, stdout: '', stderr: CLR_ABORT_STDERR };
    const { run, calls } = aborts(0, noisySuccess);
    const result = await runScript('pwsh', [], {}, run);
    expect(result).toEqual(noisySuccess);
    expect(calls()).toBe(1);
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
