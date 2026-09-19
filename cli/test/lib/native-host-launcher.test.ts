import { describe, expect, it } from 'vitest';

import { launcherScript, parseLauncher } from '../../src/lib/native-host-launcher.ts';

// Every character either interpreter still acts on inside its quoting, plus a
// space, which ends a word. Each one is its own case on both platforms so a
// round trip that loses one names it.
const AWKWARD = [
  '/opt/homebrew/opt/aka/libexec/aka',
  '/Users/x/My Tools/aka',
  "/Users/x/it's/aka",
  '/Users/x/we$IRD/aka',
  '/Users/x/`dir`/aka',
  'C:\\Users\\x\\100%\\aka.exe',
  'C:\\Users\\x\\%PATH%\\aka.exe',
  "/a/''/b",
];

describe('launcherScript / parseLauncher', () => {
  it.each(AWKWARD)('reads back %j from a POSIX launcher', (path) => {
    const argv = [path, '__native-host'];
    expect(parseLauncher(launcherScript(argv, 'darwin'))).toEqual(argv);
  });

  it.each(AWKWARD)('reads back %j from a cmd launcher', (path) => {
    const argv = [path, '__native-host'];
    expect(parseLauncher(launcherScript(argv, 'win32'))).toEqual(argv);
  });

  it('reads back a two-path launcher (a Node runtime over a host script)', () => {
    const argv = ['/usr/local/bin/node', '/usr/local/lib/node_modules/x/native-host/host.js'];
    expect(parseLauncher(launcherScript(argv, 'linux'))).toEqual(argv);
    expect(parseLauncher(launcherScript(argv, 'win32'))).toEqual(argv);
  });

  it('writes the forms Chrome runs: sh with "$@", cmd with %*', () => {
    expect(launcherScript(['/a/aka', '__native-host'], 'darwin')).toBe(
      "#!/bin/sh\nexec '/a/aka' '__native-host' \"$@\"\n",
    );
    expect(launcherScript(['C:\\a\\aka.exe', '__native-host'], 'win32')).toBe(
      '@echo off\r\n"C:\\a\\aka.exe" "__native-host" %*\r\n',
    );
  });

  it.each([
    ['a script with no recognised header', 'echo hi\n'],
    ['a POSIX launcher that drops the forwarded arguments', "#!/bin/sh\nexec '/a/aka'\n"],
    ['a POSIX launcher with an unquoted word', '#!/bin/sh\nexec /a/aka "$@"\n'],
    ['a POSIX launcher with an unclosed quote', '#!/bin/sh\nexec \'/a/aka "$@"\n'],
    ['a POSIX launcher with a second command', '#!/bin/sh\nexec \'/a/aka\' "$@"\necho second\n'],
    ['a cmd launcher that drops the forwarded arguments', '@echo off\r\n"C:\\a\\aka.exe"\r\n'],
    ['a cmd launcher with an unquoted word', '@echo off\r\nC:\\a\\aka.exe %*\r\n'],
  ])('refuses %s', (_label, script) => {
    expect(parseLauncher(script)).toBeNull();
  });
});
