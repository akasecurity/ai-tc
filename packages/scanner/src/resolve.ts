// Pure set-difference helper for finding resolution:
// returns keys present in prior but not in current, deduplicated.
export function computeResolutions(prior: string[], current: string[]): string[] {
  const cur = new Set(current);
  return [...new Set(prior)].filter((k) => !cur.has(k));
}
