// A tiny semver comparator — just enough to answer "is `latest` newer than what's
// installed?" for the update check. The schema's `SemVer` (packages/schema) is a
// validation regex only; it has no comparator, so we add this CLI-local one. Handles
// `X.Y.Z` with an optional `-prerelease` (a version WITH a prerelease sorts BELOW the
// same version without one, per semver §11). Unparseable input compares as equal so
// the update check never nags on a garbage version string.
//
// TWIN: packages/persistence/src/semver.ts holds a boundary-forced copy of this
// comparator (this package depends on persistence, so persistence cannot import
// it back). The two must stay semantically identical — mirror any change to the
// ordering rules or the parse grammar in both files, and in both test suites
// (this one and packages/persistence/test/semver.test.ts).
//
// A READER over the existing grammar is not such a change and is NOT owed a
// mirror: `prereleaseIdentifiers` below projects what `parse` already produces,
// so copying it into the twin would leave that package exporting something no
// caller in it needs. Only the ordering rules and the grammar are twinned.

interface Parsed {
  core: [number, number, number];
  pre: string[]; // prerelease identifiers, empty for a release
}

function parse(version: string): Parsed | null {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-.]+))?$/.exec(version.trim());
  if (!match) return null;
  return {
    core: [Number(match[1]), Number(match[2]), Number(match[3])],
    pre: match[4] ? match[4].split('.') : [],
  };
}

// Does `version` parse as a semver this module can order? Callers that pick a
// winner out of a set need this: compareSemver returns 0 for anything it cannot
// parse, so an unparseable candidate is indistinguishable from an equal one and
// can survive a reduce it should never have entered.
export function isSemver(version: string): boolean {
  return parse(version) !== null;
}

// Is `version` EXACTLY a version this grammar accepts, with nothing around it?
//
// `isSemver` trims first, so ` 1.0.0 ` and `1.0.0\n` pass it. That is harmless
// for a comparison and not harmless for a string that becomes a child process's
// argv: `local-ops`' shelled spawn routes through cmd.exe on Windows and Node
// concatenates argv there without escaping it, so a space splits the spec into
// two arguments and a line break ends the command line. This is the predicate
// to reach for before a registry-supplied version goes anywhere near a spawn.
//
// What survives it is digits, dots and the prerelease alphabet `[0-9A-Za-z-.]`,
// which holds no shell metacharacter, no whitespace and no leading dash npm
// would read as a flag.
//
// Derived from the same `parse` rather than written as a second regex: a
// private copy is free to accept a form the comparator rejects, and a spec
// built from one would reach npm as a version nothing publishes.
export function isExactSemver(version: string): boolean {
  return version === version.trim() && isSemver(version);
}

// The prerelease identifiers of `version`, or `[]` for a release AND for
// anything unparseable. Collapsing those two is deliberate: both answer "not on
// a prerelease channel", which is the conservative direction for a reader
// deciding which release channel a machine follows — it falls back to stable,
// the behaviour that shipped before channels existed.
export function prereleaseIdentifiers(version: string): readonly string[] {
  return parse(version)?.pre ?? [];
}

function comparePre(a: string[], b: string[]): -1 | 0 | 1 {
  // A release (no prerelease) outranks a prerelease of the same core.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    // i < len ≤ both lengths, so these are always present; `?? ''` only satisfies
    // noUncheckedIndexedAccess.
    const ai = a[i] ?? '';
    const bi = b[i] ?? '';
    if (ai === bi) continue;
    const an = /^\d+$/.test(ai);
    const bn = /^\d+$/.test(bi);
    // Numeric identifiers rank below alphanumeric ones.
    if (an && !bn) return -1;
    if (!an && bn) return 1;
    if (an && bn) return Number(ai) < Number(bi) ? -1 : 1;
    return ai < bi ? -1 : 1;
  }
  // All shared identifiers equal — the longer set wins.
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

// -1 if a < b, 0 if equal, 1 if a > b. Unparseable versions compare as equal.
export function compareSemver(a: string, b: string): -1 | 0 | 1 {
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return 0;
  for (let i = 0; i < 3; i++) {
    const av = pa.core[i] ?? 0;
    const bv = pb.core[i] ?? 0;
    if (av !== bv) return av < bv ? -1 : 1;
  }
  return comparePre(pa.pre, pb.pre);
}

// Is `latest` strictly newer than `installed`? Both must parse; anything else
// (unknown/garbage version) is treated as "no update" so the check stays quiet.
export function isNewer(latest: string, installed: string): boolean {
  return compareSemver(latest, installed) > 0;
}
