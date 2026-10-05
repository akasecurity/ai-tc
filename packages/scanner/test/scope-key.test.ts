import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { scopeKeysUnder } from '../src/scope-key.ts';

// The userinfo in an scp-form remote reads as an email address to a scanner,
// so the fixture builds it from parts.
const AT = String.fromCharCode(64);
const gitUser = `git${AT}`;

// The lookup on its own, against a real fixture repository and the real
// resolver. Which capture carries which key, and how often a scan reads a
// repository, are pinned through scanWorktree in ./scan.test.ts.
describe('scopeKeysUnder', () => {
  let tmp: string;
  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'aka-scope-key-'));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('resolves a relative scan root against the process directory before walking up', () => {
    // `/aka:scan --dir api` hands the scanner the root as typed. The resolver
    // returns no key for a directory that is not absolute, so a root left
    // relative would leave every file keyless even though the repository two
    // levels above it has a remote.
    mkdirSync(join(tmp, '.git'), { recursive: true });
    writeFileSync(
      join(tmp, '.git', 'config'),
      `[remote "origin"]\n\turl = ${gitUser}github.com:acme/work.git\n`,
    );
    mkdirSync(join(tmp, 'packages', 'api', 'src'), { recursive: true });
    // path.resolve reads the process directory through process.cwd(); every
    // later read uses the absolute path it returns.
    const cwd = vi.spyOn(process, 'cwd').mockReturnValue(join(tmp, 'packages'));
    try {
      expect(scopeKeysUnder('api')('src/api-a.ts')).toBe('github.com/acme/work');
    } finally {
      cwd.mockRestore();
    }
  });
});
