// The one locale a route formats its numbers and times in.
//
// The sibling of rendered-at.ts, for the other half of a label: a server render
// and the hydration that follows it must agree on the INSTANT and on the
// LOCALE, or React discards the server's markup for that subtree. Reading the
// locale off the runtime gets neither renderer the reader's convention — the
// server's is the Node process's, the browser's is whatever the browser says —
// and the two need not match. So a route reads it off the request instead, once,
// and passes it down as a prop; the shared formatters require it (see
// @akasecurity/dashboard-ui's lib/locale.ts).
import { resolveLocale } from '@akasecurity/dashboard-ui';
import { headers } from 'next/headers';

/**
 * The reader's locale for this request, from its `Accept-Language` header, or
 * en-US when it names none this runtime can format.
 *
 * Call once per request, in a Server Component, and pass the result down.
 */
export async function renderLocale(): Promise<string> {
  return resolveLocale((await headers()).get('accept-language'));
}
