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

import { powershellEnv } from './run-installer.ts';

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
