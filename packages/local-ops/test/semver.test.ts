// TWIN: packages/persistence/test/semver.test.ts covers the boundary-forced copy
// of this comparator (`compareBinaryVersions`). The two comparators must stay
// semantically identical — if you change the ordering rules or the parse grammar
// in semver.ts, mirror it in the persistence copy and update both suites. The
// duplication is intentional (OSS/CLI boundary); see the note atop semver.ts.
import { describe, expect, it } from 'vitest';

import { compareSemver, isExactSemver, isNewer, isSemver } from '../src/semver.ts';

describe('compareSemver', () => {
  it('orders by major/minor/patch', () => {
    expect(compareSemver('1.0.0', '2.0.0')).toBe(-1);
    expect(compareSemver('1.2.0', '1.1.9')).toBe(1);
    expect(compareSemver('1.0.10', '1.0.9')).toBe(1);
    expect(compareSemver('3.4.5', '3.4.5')).toBe(0);
  });

  it('ranks a prerelease below its release', () => {
    expect(compareSemver('0.0.2-alpha.0', '0.0.2')).toBe(-1);
    expect(compareSemver('0.0.2', '0.0.2-alpha.0')).toBe(1);
  });

  it('orders prerelease identifiers (numeric < alnum, per-identifier)', () => {
    expect(compareSemver('1.0.0-alpha.1', '1.0.0-alpha.2')).toBe(-1);
    expect(compareSemver('1.0.0-alpha.9', '1.0.0-alpha.10')).toBe(-1);
    expect(compareSemver('1.0.0-alpha', '1.0.0-alpha.1')).toBe(-1);
    expect(compareSemver('1.0.0-1', '1.0.0-alpha')).toBe(-1);
  });

  it('treats unparseable versions as equal (never nags)', () => {
    expect(compareSemver('latest', '1.0.0')).toBe(0);
    expect(compareSemver('1.0.0', 'not-a-version')).toBe(0);
  });
});

describe('isNewer', () => {
  it('is true only when latest strictly exceeds installed', () => {
    expect(isNewer('0.0.3', '0.0.2')).toBe(true);
    expect(isNewer('0.0.2', '0.0.2')).toBe(false);
    expect(isNewer('0.0.2-alpha.0', '0.0.2-alpha.1')).toBe(false);
    expect(isNewer('0.0.2', '0.0.2-alpha.1')).toBe(true);
    expect(isNewer('unknown', '0.0.2')).toBe(false);
  });
});

/**
 * The predicate a registry-supplied version must pass before it can become a
 * command-line argument.
 *
 * `isSemver` trims first, which is harmless for a comparison and not harmless
 * here: `local-ops`' shelled spawn routes through cmd.exe on Windows and Node
 * concatenates argv there without escaping it, so a space splits an npm spec
 * into two arguments and a line break ends the command line.
 */
describe('isExactSemver', () => {
  it('accepts the forms a registry really serves', () => {
    for (const version of [
      '0.11.0',
      '1.0.0',
      '0.11.0-beta.4',
      '0.9.13-nightly.20260918.gabc1234',
      '0.11.0-rc.1',
      '10.20.30',
    ]) {
      expect(isExactSemver(version), version).toBe(true);
    }
  });

  it('refuses the surrounding whitespace isSemver tolerates', () => {
    // Stated as a DIFFERENCE from `isSemver`, because a predicate that merely
    // agreed with it everywhere would be the hole this one exists to close.
    for (const version of [' 0.11.0', '0.11.0 ', ' 0.11.0 ', '0.11.0\n', '0.11.0\t', '\r0.11.0']) {
      expect(isSemver(version), `isSemver ${JSON.stringify(version)}`).toBe(true);
      expect(isExactSemver(version), JSON.stringify(version)).toBe(false);
    }
  });

  it('refuses every shell metacharacter, and a leading dash', () => {
    for (const version of [
      '0.11.0; id',
      '0.11.0 && id',
      '0.11.0 | id',
      '0.11.0`id`',
      '0.11.0$(id)',
      '0.11.0%PATH%',
      '0.11.0"x"',
      "0.11.0'x'",
      '0.11.0&0.11.1',
      '0.11.0 --prefix=/tmp',
      '-0.11.0',
      '--prefix=/tmp',
      '0.11.0/../x',
      '0.11.0\\x',
      '',
      'latest',
      '__proto__',
      '0.11.0+build.1',
    ]) {
      expect(isExactSemver(version), JSON.stringify(version)).toBe(false);
    }
  });

  it('is never true where the comparator cannot order the value', () => {
    // The spec has to be a version the report could also have compared: a
    // string this accepts and `isSemver` rejects would be offered by nobody and
    // installed anyway.
    for (const version of ['0.11.0', ' 0.11.0 ', 'latest', '0.11.0; id', '1.2', 'v1.2.3']) {
      if (isExactSemver(version)) expect(isSemver(version), version).toBe(true);
    }
  });
});
