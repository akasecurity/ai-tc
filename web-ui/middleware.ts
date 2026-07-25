import { type NextRequest, NextResponse } from 'next/server';

// The dashboard binds to loopback, but a loopback bind alone does not stop DNS
// rebinding: a hostile page can re-resolve its own domain to 127.0.0.1 and
// script same-origin requests into this server, reaching the local-store read
// surface (project-file browsing) and the Server Action write surface. The
// browser still stamps those requests with the attacker's domain in the Host
// header — and Next's built-in Server Action CSRF check compares Origin to
// Host, which AGREE under rebinding — so the gate that actually closes the
// hole is this one: reject any request not addressed to a loopback literal.
//
// The whole gate is one anchored pattern: a bare `host[:port]` whose host is
// exactly `localhost`, `127.0.0.1`, or `[::1]` (case-insensitive), any port
// (`aka dashboard --port N`). The anchors reject everything else in a single
// step — alternate IPv4/IPv6 encodings that resolve to loopback (`127.1`,
// `2130706433`, `0x7f000001`, `127.000.000.001`, `[::ffff:127.0.0.1]`) and any
// userinfo, path, query, or fragment smuggled past the authority
// (`localhost:4319@evil.com`, `localhost:4319/evil`). Testing the literal the
// client sent — not a parsed or normalised host — is what keeps the allow-set to
// exactly these spellings; and a literal test has no URL-parser behaviour that
// could differ between Node and the Edge runtime this middleware ships on. The
// port is not part of the security decision — the host is always a loopback
// literal when this matches — so `\d{1,5}` bounds only the port's length, and
// out-of-range or zero-padded ports on loopback are admitted (harmless; no
// browser can open a port above 65535).
const BARE_LOOPBACK = /^(?:localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?$/i;

function isLoopbackHost(hostHeader: string | null): boolean {
  return hostHeader !== null && BARE_LOOPBACK.test(hostHeader);
}

// No `config.matcher` export on purpose: the gate runs on every request that
// reaches middleware, including RSC data requests and Server Action posts.
// (Next answers trailing-slash / double-slash / case normalisation with a 308
// before middleware runs; that redirect carries no body and its target path is
// itself gated, so nothing reachable with a body escapes this check.)
export function middleware(request: NextRequest): NextResponse {
  // `x-forwarded-host`, when present, participates in Next's Server Action
  // origin comparison, so hold it to the same bar (no supported deployment
  // puts a proxy in front of the dashboard).
  const forwardedHost = request.headers.get('x-forwarded-host');
  if (
    !isLoopbackHost(request.headers.get('host')) ||
    (forwardedHost !== null && !isLoopbackHost(forwardedHost))
  ) {
    return new NextResponse('This dashboard only answers requests addressed to localhost.', {
      status: 403,
    });
  }
  return NextResponse.next();
}
