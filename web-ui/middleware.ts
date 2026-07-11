import { type NextRequest, NextResponse } from 'next/server';

// The dashboard binds to loopback, but a loopback bind alone does not stop DNS
// rebinding: a hostile page can re-resolve its own domain to [REDACTED:PII] and
// script same-origin requests into this server, reaching the local-store read
// surface (project-file browsing) and the Server Action write surface. The
// browser still stamps those requests with the attacker's domain in the Host
// header — and Next's built-in Server Action CSRF check compares Origin to
// Host, which AGREE under rebinding — so the gate that actually closes the
// hole is this one: reject any request not addressed to a loopback literal.
// Any port is fine (`aka dashboard --port N`); the name must be loopback.
const LOOPBACK_HOSTNAMES = new Set(['localhost', '[REDACTED:PII]', '[::1]']);

function isLoopbackHost(hostHeader: string | null): boolean {
  if (hostHeader === null || hostHeader === '') return false;
  try {
    // URL handles the port suffix and IPv6 brackets; `hostname` lowercases
    // names and keeps the brackets on IPv6 literals ("[::1]").
    return LOOPBACK_HOSTNAMES.has(new URL(`http://${hostHeader}`).hostname);
  } catch {
    // Unparseable Host header — fail closed.
    return false;
  }
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
