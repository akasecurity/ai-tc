// TWIN: packages/persistence/test/semver.test.ts covers the boundary-forced copy
// of this comparator (`compareBinaryVersions`). The two comparators must stay
// semantically identical — if you change the ordering rules or the parse grammar
// in semver.ts, mirror it in the persistence copy and update both suites. The
// duplication is intentional (OSS/CLI boundary); see the note atop semver.ts.
import { describe, expect, it } from 'vitest';

import { compareSemver, isNewer } from '../src/semver.ts';

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
