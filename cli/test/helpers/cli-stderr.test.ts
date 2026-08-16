import { spawnSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { cliStderr } from './cli-stderr.ts';

// The helper an absence assertion leans on gets its own suite, or it can be
// weakened back with nothing going red. Broadening this one does not merely
// leave its callers green, it makes them MORE green: they assert
// `cliStderr(stderr)` is empty, so a filter that ate the CLI's own words would
// satisfy them while proving nothing. No caller can be what catches that.
//
// So the cases below are two-sided on purpose — what must be REMOVED, and what
// must SURVIVE — and the removal half is driven by really spawning Node rather
// than by pasting its output into a literal, so the fixture cannot drift from
// what the runtime actually prints.

/** Node's stderr from a one-line script, as a real child process. */
function stderrOf(script: string): string {
  const result = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8' });
  return result.stderr;
}

describe('cliStderr', () => {
  describe('removes Node’s own diagnostics', () => {
    // Both spellings of the hint line are reachable without any flag — which one
    // a process gets depends only on the kind of the FIRST warning it emits. A
    // filter covering one covers the other by accident, which is why they are
    // separate cases.
    it.each([
      ['a plain warning', "process.emitWarning('probe message')", '--trace-warnings'],
      [
        'a deprecation notice',
        "process.emitWarning('probe message', 'DeprecationWarning')",
        '--trace-deprecation',
      ],
    ])('reduces %s and its hint line to nothing', (_label, script, hintFlag) => {
      const raw = stderrOf(script);

      // The positive control, and it is not decoration: `cliStderr('')` is `''`,
      // so without pinning that the warning really fired AND that the hint line
      // really followed it, the assertion below passes on a Node that emitted
      // nothing at all — which is exactly the state this helper exists for.
      expect(raw).toContain('probe message');
      expect(raw).toContain(hintFlag);
      // The line the two original patterns missed: it carries no `(node:N)`
      // prefix and is not a stack frame.
      expect(raw).toMatch(/^\(Use `node --trace-/mu);

      expect(cliStderr(raw)).toBe('');
    });

    it('still removes the `(node:N)` prefix and stack frames it always removed', () => {
      // Pins what the helper did before it moved into this file, so the move
      // itself is verified rather than assumed.
      const raw = [
        '(node:12345) ExperimentalWarning: Type Stripping is experimental',
        '    at loadESM (node:internal/process/esm_loader:34:7)',
        'Warning: a bare continuation line',
        '(tsx:12345) SomeWarning: from the loader',
      ].join('\n');

      expect(cliStderr(raw)).toBe('');
    });

    it('removes the hint line even with CRLF endings', () => {
      // Splitting CRLF output on `\n` leaves a `\r` on each line, which a bare
      // `$` anchor would not match — so this is the Windows leg of the pattern
      // above, not a restatement of it.
      const raw =
        '(node:1) Warning: x\r\n(Use `node --trace-warnings ...` to show where the warning was created)\r\n';

      expect(cliStderr(raw)).toBe('');
    });
  });

  describe('keeps what the CLI itself wrote', () => {
    // The half that stops the filter going quietly over-broad. Each of these
    // would be reported as "the CLI said nothing" if a pattern grew to match it.
    it('keeps a real CLI error', () => {
      // The exact line a corrupt-store case asserts as its positive control.
      expect(cliStderr('aka: file is not a database')).toBe('aka: file is not a database');
    });

    it('keeps a line that merely CONTAINS the hint text, not starts with it', () => {
      // The `^` anchor is the only thing standing between this line and the
      // filter, so the fixture has to carry the matched prefix VERBATIM and
      // merely displaced. A fixture that only paraphrases the hint (`run
      // \`node --trace-warnings ...\``, with no `(Use `) never reaches the
      // anchor at all: dropping `^` leaves it green, and the case then reports
      // an over-breadth guard it does not have.
      const line =
        'aka: the runtime said (Use `node --trace-warnings ...` to show where the warning was created) — ignoring it';
      expect(line).toContain('(Use `node --trace-'); // the prefix is really present
      expect(cliStderr(line)).toBe(line);
    });

    it('keeps a CLI hint that opens with `(Use `', () => {
      // `--trace-` is the discriminator, not the `(Use ` opener.
      const line = '(Use the --home flag to point somewhere else)';
      expect(cliStderr(line)).toBe(line);
    });

    it('keeps CLI output sitting beside a real Node warning', () => {
      // The mixed case the spawn cases cannot produce: the runtime's noise and
      // the CLI's own words on one stream. Dropping the wrong one here is the
      // failure that reads as a passing test.
      const raw = [
        '(node:12345) ExperimentalWarning: Type Stripping is experimental',
        '(Use `node --trace-warnings ...` to show where the warning was created)',
        'aka: file is not a database',
      ].join('\n');

      expect(cliStderr(raw)).toBe('aka: file is not a database');
    });
  });
});
