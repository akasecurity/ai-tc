// Stand-in for `next/headers` under vitest.
//
// The real `headers()` reads the incoming request out of Next's request scope
// and throws when called outside one, which is every page test here: they call
// a route's Server Component as a plain async function. A route reads one header
// today — `Accept-Language`, through app/lib/render-locale.ts — so this answers
// with a request that carries none unless a test sets one, and the route
// resolves the en-US default exactly as it would for a request without the
// header. See vitest.config.ts.
//
// The headers are per test FILE (vitest isolates modules per file); a test that
// sets them puts them back with `setRequestHeaders({})` in its own teardown.
let current = new Headers();

/** The headers the next `headers()` call answers with. */
export function setRequestHeaders(init: Record<string, string>): void {
  current = new Headers(init);
}

export function headers(): Promise<Headers> {
  return Promise.resolve(current);
}
