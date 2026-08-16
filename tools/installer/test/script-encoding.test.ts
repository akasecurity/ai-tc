// The shipped installer scripts must be pure ASCII, and this is the guard that
// keeps them that way.
//
// It exists because a non-ASCII byte in install.ps1 is not a cosmetic issue: it
// stopped the Windows installer from PARSING, and did so while every review of
// the file read fine.
//
//   Windows PowerShell 5.1 — still the default interpreter on every Windows
//   box — decodes a BOM-less .ps1 with the system ANSI codepage rather than as
//   UTF-8. Under CP1252 an em dash's three UTF-8 bytes (e2 80 94) decode to
//   'â' + '€' + U+201D, and U+201D is a character PowerShell's lexer accepts as
//   a closing double quote. So an em dash inside a double-quoted string ends
//   that string early, the trailing real quote opens one that never closes, and
//   the file dies with `TerminatorExpectedAtEndOfString` before a single line of
//   it runs. The security control that hashes the archive and refuses a mismatch
//   simply does not execute.
//
// Three properties made it survive: it is invisible in review (an em dash and a
// hyphen look alike), it breaks on one platform only, and the error names
// neither the character nor the encoding — it names a quote several lines away.
//
// A UTF-8 BOM would also fix the parse, but ASCII is the stronger invariant: it
// decodes identically under EVERY codepage, so it holds for a user on CP1251 or
// CP932 too, and it survives every consumption path — piped to `iex`, saved and
// run with -File, opened in an editor that guesses wrong.
//
// Scoped to these two files rather than added to tools/portability-gate: that
// gate scans the tracked test and bench trees (its `isRelevantPath` is spec
// files, test/bench directories and vitest configs), so it does not reach a
// shipped .ps1 at a package root, and its rules are a JS/TS tokenizer that a
// raw byte scan does not fit. The guard belongs where the scripts are.
import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { INSTALL_PS1, INSTALL_SH } from './helpers/run-installer.ts';

// Named rather than passed as bare paths, so a case title is `install.ps1 …`
// rather than the absolute path of whoever's machine ran it.
const SCRIPTS = [
  { name: 'install.sh', path: INSTALL_SH },
  { name: 'install.ps1', path: INSTALL_PS1 },
];

/** Every non-ASCII byte in `raw`, located by 1-based line and column. */
function nonAsciiRuns(raw: Buffer): { line: number; column: number; bytes: string }[] {
  const found: { line: number; column: number; bytes: string }[] = [];
  let line = 1;
  let column = 1;
  for (const byte of raw) {
    if (byte === 0x0a) {
      line += 1;
      column = 1;
      continue;
    }
    if (byte > 0x7f) found.push({ line, column, bytes: `0x${byte.toString(16)}` });
    column += 1;
  }
  return found;
}

describe('shipped installer scripts', () => {
  it.each(SCRIPTS)('$name is pure ASCII', ({ name, path }) => {
    const raw = readFileSync(path);
    const offenders = nonAsciiRuns(raw);

    // Positive control: the file was actually read. An empty buffer has no
    // non-ASCII bytes either, so the assertion below would hold vacuously on a
    // path that resolved to nothing.
    expect(raw.byteLength).toBeGreaterThan(0);

    expect(
      offenders.map((o) => `${name}:${String(o.line)}:${String(o.column)} ${o.bytes}`),
      `${name} must be pure ASCII: a non-ASCII byte here can mis-decode into a ` +
        `quote character under a legacy codepage and stop the script parsing`,
    ).toEqual([]);
  });

  it.each(SCRIPTS)('$name decodes identically under every legacy codepage', ({ name, path }) => {
    const raw = readFileSync(path);
    const utf8 = new TextDecoder('utf-8', { fatal: true }).decode(raw);

    // This is the property the ASCII rule buys, asserted directly rather than
    // inferred: what the file MEANS cannot depend on the reader's codepage.
    // windows-1252 is the one that broke it; the others are the same trap for a
    // user whose system locale is not Western European.
    for (const encoding of ['windows-1252', 'windows-1251', 'shift_jis', 'ibm866']) {
      expect(new TextDecoder(encoding).decode(raw), `${name} under ${encoding}`).toBe(utf8);
    }
  });

  it.each(SCRIPTS)('$name has no byte-order mark', ({ path }) => {
    // Implied by the ASCII rule (a BOM is ef bb bf), asserted separately because
    // a BOM is the other way someone might "fix" a future mis-decode, and it is
    // the weaker fix: `sh` would then execute the BOM as part of the shebang
    // line. Failing here says which repair was chosen.
    expect([...readFileSync(path).subarray(0, 3)]).not.toEqual([0xef, 0xbb, 0xbf]);
  });
});
