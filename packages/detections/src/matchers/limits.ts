// The absolute per-rule match ceiling shared by every matcher. It bounds how
// many spans a single rule can produce — and therefore allocate — regardless of
// input size. Two failure modes hit this cap: a matcher loop that never
// advances (a zero-width regex match, or a future engine edge case), and a
// well-formed but pathologically broad match (a 1-character keyword, or a regex
// like "." over a very large input) that would otherwise emit one span per byte.
export const MAX_MATCHES_PER_RULE = 10_000;

// Hard ceiling on how much text a single regex rule is ever run against. A
// backtracking engine's worst-case cost for a pathological pattern (nested
// quantifiers like "(a+)+", overlapping alternation, etc.) grows with input
// size — for some patterns exponentially — so bounding the text a caller-
// supplied pattern is evaluated over bounds the worst case it can trigger,
// independent of whether the pattern itself is ever inspected for complexity.
// This package is synchronous and has no timeout/worker available to it, so
// this input-size cap (plus the pattern-length cap in the schema package) is
// the only defense it can offer on its own; a caller that runs untrusted,
// externally-authored patterns (e.g. a rule-testing API) still needs its own
// time-bounded isolation around the call. Generous enough that no real source
// file, log line, or prompt is ever truncated in practice.
export const MAX_REGEX_INPUT_LENGTH = 200_000;
