import { describe, expect, it } from 'vitest';

import { type InstallerRun, runScript, type ScriptRunner } from './run-installer.ts';

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
