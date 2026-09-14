// The token scan behind `hostCliVersion`, which is the only version parser on
// the install gate's path.
//
// It had no test at all: every CLI case injects `deps.hostVersion`, correctly —
// this repo's PATH shims fail OPEN, so an unstubbed probe would reach the
// developer's real installed CLI — but the consequence was that the real parse
// ran nowhere, and each defect it fixes was asserted only by its own comment.
// Each is a silent miss on a security gate: a version it cannot read leaves the
// gate quiet, and one it reads too high clears a floor the host does not.
import { describe, expect, it } from 'vitest';

import { versionTokenFrom } from '../src/cli-plugin-manager.ts';

describe('versionTokenFrom', () => {
  it('reads the shape Claude Code actually prints', () => {
    expect(versionTokenFrom('2.1.258 (Claude Code)')).toBe('2.1.258');
  });

  it('tolerates the punctuation a version is commonly wrapped in', () => {
    // A `v` prefix was unmatchable under the regex this replaced — there is no
    // word boundary between `v` and a digit — and a parenthesised version is
    // the same class of miss.
    expect(versionTokenFrom('v2.1.258')).toBe('2.1.258');
    expect(versionTokenFrom('(2.1.258)')).toBe('2.1.258');
    expect(versionTokenFrom('Claude Code v2.1.258 (build 9)')).toBe('2.1.258');
    expect(versionTokenFrom('2.1.258,')).toBe('2.1.258');
  });

  it('KEEPS the prerelease, so a build below a floor cannot clear it', () => {
    // The sharpest of the three: dropping `-rc.1` makes this compare EQUAL to
    // the 2.1.251 floor, so a build that genuinely predates the events behind
    // that floor installs with no warning.
    expect(versionTokenFrom('2.1.251-rc.1 (Claude Code)')).toBe('2.1.251-rc.1');
    expect(versionTokenFrom('2.1.251-alpha.1')).toBe('2.1.251-alpha.1');
  });

  it('prefers the first line, so a later notice cannot outrank the version', () => {
    expect(versionTokenFrom('2.1.258 (Claude Code)\nnpm notice 2.2.0 available')).toBe('2.1.258');
  });

  it('refuses a package spec, a URL path, or any other unwrapped prefix', () => {
    // The strips are an enumerated set of WRAPPING punctuation, not "everything
    // up to the first digit". The open-ended form accepted all of these, and the
    // first row is the one that bit: an npm notice naming a package@version on
    // the first line then outranked the real version below it — a MISSED warning
    // on a security gate, which is the direction this function must not fail in.
    // These also pin the BOUND, which is what keeps the strips linear.
    for (const token of [
      '@anthropic-ai/claude-code@2.2.0',
      'https://example.com/rel/2.9.0',
      'build-2.9.0',
      'foo-2.1.258',
      'x-2.1.258',
    ]) {
      expect(versionTokenFrom(token)).toBeUndefined();
    }
  });

  it('strips a BOUNDED run of trailing wrappers, not an open-ended one', () => {
    // Pins the quadratic half behaviourally, with no wall clock. An unbounded
    // `[^\w.-]+$` accepts every row below — and is polynomial on a token the
    // host CLI controls (measured 281/1089/4276 ms at 25k/50k/100k commas).
    // A timing assertion would be the wrong instrument here; this repo does not
    // gate on wall clock, and these rows fail for the same reason the timing
    // would: the strip is no longer open-ended.
    expect(versionTokenFrom('2.1.258,,,,,')).toBeUndefined(); // 5 > the bound
    expect(versionTokenFrom('2.1.258)))))')).toBeUndefined();
    expect(versionTokenFrom('2.1.258!!!')).toBeUndefined(); // outside the class

    // The positive half: what the bound is FOR still resolves.
    expect(versionTokenFrom('2.1.258,')).toBe('2.1.258');
    expect(versionTokenFrom('2.1.258))')).toBe('2.1.258');
  });

  it('lets the real version win over a package spec on the FIRST line', () => {
    // The paired positive control for the case above, and the regression that
    // prompted it: with an open-ended leading strip this returned '3.0.0'.
    expect(
      versionTokenFrom(
        'npm notice New major version available: @anthropic-ai/claude-code@3.0.0\n' +
          '2.1.258 (Claude Code)',
      ),
    ).toBe('2.1.258');
  });

  it('still loses to a version-shaped token on the FIRST line', () => {
    // Pinned as the KNOWN LIMIT rather than left to be discovered. It fails
    // toward silence — a spurious higher version clears every floor — so it
    // costs a missed warning, never a wrong one. Assert it so a future change
    // that narrows or widens it is a deliberate edit.
    expect(versionTokenFrom('npm notice 2.2.0 available\n2.1.258 (Claude Code)')).toBe('2.2.0');
  });

  it('answers undefined when nothing parses, rather than guessing', () => {
    for (const out of ['', 'garbage', 'Claude Code', '2.1', '2026-09-10']) {
      expect(versionTokenFrom(out)).toBeUndefined();
    }
  });
});
