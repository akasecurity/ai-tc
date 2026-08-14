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

import { assertHostArchitecture, powershellEnv } from './run-installer.ts';

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

/** The error a thunk threw, captured OUTSIDE its own catch. */
function errorFrom(fn: () => void): Error | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    return err as Error;
  }
}
