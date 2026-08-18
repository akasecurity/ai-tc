import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { quoteForDisplay, quoteForShell } from '../src/exec.ts';

// Node does not quote argv when `shell: true`: it joins the command and its
// arguments with single spaces and hands the string to the shell, which then
// re-parses every one of them. exec.ts takes that path on Windows (the global
// `npm`/`claude` binaries are `.cmd` shims that cannot be spawned without a
// shell), and the CLI self-update is the first caller to pass an argument that
// is a PATH rather than a constant flag or package name.
//
// These run everywhere rather than only on win32: `quoteForShell` is pure, and
// the property it has to hold — one argument in, one token out — is what the
// Windows leg would otherwise be the only place to discover.

describe('quoteForShell', () => {
  it('leaves an argument that needs no quoting byte-identical', () => {
    // Every argument the update surface sent before the install prefix existed.
    for (const arg of [
      'install',
      '-g',
      '--prefix',
      '@akasecurity/cli@latest',
      'plugin',
      'update',
    ]) {
      expect(quoteForShell(arg)).toBe(arg);
    }
  });

  it('quotes a Windows prefix containing a space', () => {
    // The common case, not an exotic one: a user account with a space in it.
    expect(quoteForShell(String.raw`C:\Users\First Last\AppData\Roaming\npm`)).toBe(
      String.raw`"C:\Users\First Last\AppData\Roaming\npm"`,
    );
  });

  it('quotes the cmd metacharacters that would otherwise end the command', () => {
    for (const meta of ['&', '|', '^', '<', '>', '(', ')']) {
      const arg = `C:\\opt\\a${meta}b`;
      expect(quoteForShell(arg), meta).toBe(`"${arg}"`);
    }
  });

  it('doubles an embedded quote rather than closing the token early', () => {
    expect(quoteForShell('a"b')).toBe('"a""b"');
  });
});

describe('quoteForDisplay', () => {
  // The same argument for a HUMAN to paste, which is a different shell from the
  // one exec.ts spawns through. On Windows it is the same problem and delegates;
  // on POSIX it is not, because a double-quoted run still expands.
  it('leaves every argument of the ordinary command byte-identical', () => {
    for (const arg of ['install', '-g', '--prefix', '@akasecurity/cli@latest', '/opt/node']) {
      expect(quoteForDisplay(arg, 'darwin'), arg).toBe(arg);
      expect(quoteForDisplay(arg, 'win32'), arg).toBe(arg);
    }
  });

  it('single-quotes a POSIX path that needs it', () => {
    expect(quoteForDisplay('/opt/My Node/prefix', 'darwin')).toBe(
      String.raw`'/opt/My Node/prefix'`,
    );
  });

  it('delegates to the cmd form on Windows', () => {
    const prefix = String.raw`C:\Program Files\nodejs`;
    expect(quoteForDisplay(prefix, 'win32')).toBe(quoteForShell(prefix));
    expect(quoteForDisplay(prefix, 'win32')).toBe(`"${prefix}"`);
  });

  it('closes and reopens the quotes around an embedded single quote', () => {
    expect(quoteForDisplay("/opt/o'brien/prefix", 'darwin')).toBe(
      String.raw`'/opt/o'\''brien/prefix'`,
    );
  });

  it('quotes anything outside the safe set, including a character nobody listed', () => {
    for (const arg of ['/opt/a;b', '/opt/a*b', '/opt/a`b', '/opt/a$b', '/opt/a\\b']) {
      expect(quoteForDisplay(arg, 'darwin'), arg).toBe(`'${arg}'`);
    }
  });
});

describe.skipIf(process.platform === 'win32')('the property the quoting exists to preserve', () => {
  // A POSIX shell and cmd.exe disagree about almost everything, but they agree
  // that an unquoted space separates two arguments. So driving the quoted form
  // through /bin/sh proves the token survives as ONE argument on the host that
  // can actually be tested here, and pins the failure the bug produced. (The
  // win32 leg is skipped because the reporter below is a POSIX script — the
  // unit cases above are the ones that run everywhere.)
  const withSpace = '/opt/My Node/prefix';

  // Reports each argument it received on its own line, so a split shows up as
  // an extra line rather than as differently-spaced text.
  const dir = mkdtempSync(join(tmpdir(), 'aka-exec-quote-'));
  const reporter = join(dir, 'argv.sh');
  writeFileSync(reporter, '#!/bin/sh\nfor a in "$@"; do echo "[$a]"; done\n', { mode: 0o700 });
  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function argvUnderShell(args: string[]): string[] {
    const out = execFileSync(reporter, args, { encoding: 'utf8', shell: true });
    return out.trim().split('\n');
  }

  it('a quoted path arrives as a single argument', () => {
    expect(argvUnderShell([quoteForShell(withSpace), 'pkg@latest'])).toStrictEqual([
      `[${withSpace}]`,
      '[pkg@latest]',
    ]);
  });

  it('the unquoted form is split — the defect this guards', () => {
    // The positive control: without quoting the same input yields THREE tokens,
    // so the assertion above is testing the quoting and not the harness.
    expect(argvUnderShell([withSpace, 'pkg@latest'])).toStrictEqual([
      '[/opt/My]',
      '[Node/prefix]',
      '[pkg@latest]',
    ]);
  });

  // A `display` string is pasted into the reader's own shell, and a POSIX one
  // keeps expanding INSIDE double quotes — so the spawn-side form is not
  // sufficient here even though it fixes the space. The variable below is
  // deliberately one nothing sets: it expands to empty, which is a silent
  // rewrite of the path rather than an error.
  const withVar = '/opt/My $AKA_NOT_A_REAL_VAR Node';

  it('a single-quoted path reaches the shell verbatim', () => {
    expect(argvUnderShell([quoteForDisplay(withVar, 'darwin')])).toStrictEqual([`[${withVar}]`]);
  });

  it('the double-quoted form is rewritten — why display quoting is its own function', () => {
    const [got] = argvUnderShell([quoteForShell(withVar)]);
    expect(got).not.toBe(`[${withVar}]`);
    expect(got).not.toContain('$AKA_NOT_A_REAL_VAR');
  });
});
