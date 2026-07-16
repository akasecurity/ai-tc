// A tiny semver comparator for `recorded_by` binary versions — enough to
// answer "is that recorded binary newer than the one running this session?"
// for the stale-session notice. Handles `X.Y.Z` with an optional
// `-prerelease` (a version WITH a prerelease sorts BELOW the same version
// without one, per semver §11) — prerelease awareness is load-bearing here:
// the release line is `0.0.2-alpha.N`, so a triplet-only comparison would
// call every alpha equal. Unparseable input compares as equal so the notice
// never fires on a garbage version string.
//
// INTENTIONAL boundary-forced copy of the comparator in
// `packages/local-ops/src/semver.ts` (same semantics, same tests): the packages
// that could host a shared copy either depend on persistence (local-ops, so
// importing it here would cycle) or must stay I/O-free (detections). Mirror any
// semantic change in both places.

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

/** -1 if a < b, 0 if equal, 1 if a > b. Unparseable versions compare as equal. */
export function compareBinaryVersions(a: string, b: string): -1 | 0 | 1 {
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

/**
 * Whether a version string parses under the same grammar the comparator uses.
 * Callers that pick a maximum via `compareBinaryVersions` use this to drop
 * unparseable versions first: those compare *equal* (0) to everything, so an
 * unparseable value that landed as the running max would never be displaced by
 * a genuinely-newer parseable one (0 is not `> 0`).
 */
export function isParseableBinaryVersion(version: string): boolean {
  return parse(version) !== null;
}
