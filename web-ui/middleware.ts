import { type NextRequest, NextResponse } from 'next/server';

// The dashboard binds to loopback, but a loopback bind alone does not stop DNS
// rebinding: a hostile page can re-resolve its own domain to 127.0.0.1 and
// script same-origin requests into this server, reaching the local-store read
// surface (project-file browsing) and the Server Action write surface. The
// browser still stamps those requests with the attacker's domain in the Host
// header — and Next's built-in Server Action CSRF check compares Origin to
// Host, which AGREE under rebinding — so the gate that actually closes the
// hole is this one: reject any request not addressed to a loopback literal.
// Any port is fine (`aka dashboard --port N`); the name must be loopback.
const LOOPBACK_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]']);

// Split the hostname off a `host[:port]` header WITHOUT normalising it. An IPv6
// literal is bracketed (`[::1]`) and carries its own colons, so its port is
// whatever follows the closing `]`; every other form splits at the first colon.
function hostnameLiteral(hostHeader: string): string {
  if (hostHeader.startsWith('[')) {
    const end = hostHeader.indexOf(']');
    return end === -1 ? hostHeader : hostHeader.slice(0, end + 1);
  }
  const colon = hostHeader.indexOf(':');
  return colon === -1 ? hostHeader : hostHeader.slice(0, colon);
}

function isLoopbackHost(hostHeader: string | null): boolean {
  if (hostHeader === null || hostHeader === '') return false;
  let parsed: URL;
  try {
    parsed = new URL(`http://${hostHeader}`);
  } catch {
    // Unparseable Host header — fail closed.
    return false;
  }
  // The header must be a bare `host[:port]`: reject anything that smuggles
  // userinfo, a path, a query, or a fragment past the authority (e.g.
  // `localhost:4319/evil`, `localhost:4319@evil.com`).
  if (
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.pathname !== '/' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    return false;
  }
  // Match the LITERAL spelling the client sent, not URL's normalised
  // `hostname`. The WHATWG parser rewrites every alternate IPv4 encoding —
  // `127.1`, `2130706433`, `0x7f000001`, `127.000.000.001` — all to
  // `127.0.0.1`, which would silently widen this allow-set to spellings it
  // never admitted. Host names are case-insensitive, so fold case first.
  return LOOPBACK_HOSTNAMES.has(hostnameLiteral(hostHeader).toLowerCase());
}

// No `config.matcher` export on purpose: the gate covers every path, including
// RSC data requests and Server Action posts.
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
