/**
 * Binds a row's id to its handler at render time, so the click body is a
 * plain, directly-callable closure rather than an arrow function inline in
 * JSX — this package's tests server-render views to a markup string (no DOM),
 * so a handler can only be exercised by calling it directly, not by
 * simulating a click.
 */
export function bindId(fn: (id: string) => void, id: string): () => void {
  return () => {
    fn(id);
  };
}

/** Same as bindId, for a handler keyed by two ids (e.g. destination + endpoint). */
export function bindTwoIds(
  fn: (id: string, secondId: string) => void,
  id: string,
  secondId: string,
): () => void {
  return () => {
    fn(id, secondId);
  };
}
