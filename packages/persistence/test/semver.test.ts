// TWIN: packages/local-ops/test/semver.test.ts covers the boundary-forced copy
// of this comparator (`compareSemver`). Keep the two semantically in lockstep —
// if you change the ordering rules or the parse grammar in semver.ts, mirror it
// in the local-ops copy and update both suites. The duplication is intentional
// (local-ops depends on persistence); see the note atop semver.ts.
import { describe, expect, it } from 'vitest';

import { compareBinaryVersions, isParseableBinaryVersion } from '../src/semver.ts';

describe('compareBinaryVersions', () => {
  it('orders release cores numerically', () => {
    expect(compareBinaryVersions('0.0.2', '0.0.1')).toBe(1);
    expect(compareBinaryVersions('0.0.2', '0.0.10')).toBe(-1);
    expect(compareBinaryVersions('1.0.0', '1.0.0')).toBe(0);
  });

  it('orders the alpha prerelease line correctly (the release convention)', () => {
    // Load-bearing: the shipping line is 0.0.2-alpha.N — a triplet-only
    // comparison would call every alpha equal and the notice would never fire.
    expect(compareBinaryVersions('0.0.2-alpha.6', '0.0.2-alpha.5')).toBe(1);
    expect(compareBinaryVersions('0.0.2-alpha.5', '0.0.2-alpha.6')).toBe(-1);
    expect(compareBinaryVersions('0.0.2-alpha.10', '0.0.2-alpha.9')).toBe(1);
    // A release outranks any prerelease of the same core (semver §11).
    expect(compareBinaryVersions('0.0.2', '0.0.2-alpha.9')).toBe(1);
  });

  it('treats unparseable versions as equal (the notice never fires on garbage)', () => {
    expect(compareBinaryVersions('not-a-version', '0.0.2')).toBe(0);
    expect(compareBinaryVersions('0.0.2', '')).toBe(0);
  });
});

describe('isParseableBinaryVersion', () => {
  it('accepts exactly what the comparator can order', () => {
    expect(isParseableBinaryVersion('0.0.2')).toBe(true);
    expect(isParseableBinaryVersion('0.0.2-alpha.6')).toBe(true);
    expect(isParseableBinaryVersion(' 1.2.3 ')).toBe(true); // parse() trims
  });

  it('rejects anything the comparator would fold to "equal"', () => {
    // These would each compare 0 against everything — a max-by-comparator scan
    // must drop them, not let one stick as the running maximum.
    expect(isParseableBinaryVersion('garbage')).toBe(false);
    expect(isParseableBinaryVersion('2.0')).toBe(false);
    expect(isParseableBinaryVersion('v2.0.0')).toBe(false);
    expect(isParseableBinaryVersion('')).toBe(false);
  });
});
