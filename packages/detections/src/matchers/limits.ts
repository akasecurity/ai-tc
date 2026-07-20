// The absolute per-rule match ceiling shared by every matcher. It bounds how
// many spans a single rule can produce — and therefore allocate — regardless of
// input size. Two failure modes hit this cap: a matcher loop that never
// advances (a zero-width regex match, or a future engine edge case), and a
// well-formed but pathologically broad match (a 1-character keyword, or a regex
// like "." over a very large input) that would otherwise emit one span per byte.
export const MAX_MATCHES_PER_RULE = 10_000;
