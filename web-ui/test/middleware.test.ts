import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';

import * as middlewareModule from '../middleware.ts';
import { middleware } from '../middleware.ts';
import nextConfig from '../next.config.ts';

// `middleware.ts` is the sole DNS-rebinding gate in front of the dashboard's
// unauthenticated, store-mutating Server Actions. Under rebinding the browser
// stamps the attacker's own domain into `Host` while `Origin` agrees with it,
// so Next's built-in CSRF check passes — only this Host-literal check closes
// the hole. It is untestable as a live network attack, so it is tested as what
// it is: a pure function over the `Host` / `x-forwarded-host` headers. Each row
// below pins the exact 200-vs-403 decision that keeps the gate honest.

// Drive the real middleware with a real NextRequest. Only the request headers
// matter to the gate; the URL host is irrelevant (the gate reads the `Host`
// header, not the URL), so a fixed loopback URL is used and the header under
// test is set explicitly. Pass `host: undefined` to omit the header entirely.
function runMiddleware(
  host: string | undefined,
  init: { xForwardedHost?: string; path?: string; method?: string } = {},
) {
  const headers = new Headers();
  if (host !== undefined) headers.set('host', host);
  if (init.xForwardedHost !== undefined) headers.set('x-forwarded-host', init.xForwardedHost);
  const request = new NextRequest(`http://localhost:4319${init.path ?? '/'}`, {
    method: init.method ?? 'GET',
    headers,
  });
  return middleware(request);
}

function statusFor(
  host: string | undefined,
  init: { xForwardedHost?: string; path?: string; method?: string } = {},
): number {
  return runMiddleware(host, init).status;
}

describe('middleware — allowed loopback literals (any port)', () => {
  // The three accepted spellings, each with the default port, a non-default
  // port, and no port at all — "any port is fine; the name must be loopback".
  // These are also the exact hosts the CLI uses: cli/src/commands/dashboard.ts
  // opens `http://localhost:${port}` (line 90) and binds `127.0.0.1` (lines
  // 39/127/171). Literal-only matching makes those load-bearing — if the gate
  // stops admitting them the dashboard 403s every page on launch — so this block
  // doubles as the pin keeping the gate and the CLI's host choices in agreement.
  it.each([
    'localhost:4319',
    'localhost:9999',
    'localhost',
    '127.0.0.1:4319',
    '127.0.0.1:9999',
    '127.0.0.1',
    '[::1]:4319',
    '[::1]:9999',
    '[::1]',
    'LOCALHOST:4319', // Host names are case-insensitive.
  ])('200 (real pass-through) for %s', (host) => {
    const response = runMiddleware(host);
    expect(response.status).toBe(200);
    // Assert the mechanism, not just the status: a genuine hand-off carries
    // NextResponse.next()'s `x-middleware-next` sentinel, so a 200 reached any
    // other way on an allowed host would still fail here. That header is a Next
    // internal under the `next: ^15.2.0` range — if a future Next renames or
    // drops it this fails with "expected '1', got null"; read that as an upgrade
    // signal, not a middleware regression, and keep the check (it is the only
    // thing separating a real pass-through from an incidental 200).
    expect(response.headers.get('x-middleware-next')).toBe('1');
  });
});

describe('middleware — non-loopback hosts are rejected (rebinding vectors)', () => {
  it.each(['evil.com', 'localhost.evil.com', '127.0.0.1.nip.io', 'attacker.example:4319'])(
    '403 for %s',
    (host) => {
      expect(statusFor(host)).toBe(403);
    },
  );
});

describe('middleware — alternate IPv4 encodings the pre-fix gate ALLOWED (regression guards)', () => {
  // The previous gate matched `new URL(...).hostname`, and the WHATWG parser
  // normalises each of these to the literal `127.0.0.1` — so on shipped code
  // they returned 200 and were a live DNS-rebinding bypass, not a hypothetical.
  // The fix matches the client's literal token instead, so they must now 403.
  // Every row here fails on the pre-fix middleware, which is what makes it a
  // real regression guard rather than a forward-only pin.
  it.each([
    '127.1', // shorthand IPv4
    '2130706433', // decimal IPv4
    '0x7f000001', // hex IPv4
    '127.000.000.001', // zero-padded dotted IPv4
    '127.1:4319', // ...with a port, too
  ])('403 for %s', (host) => {
    expect(statusFor(host)).toBe(403);
  });
});

describe('middleware — encodings already denied, pinned against a future normalisation', () => {
  // Unlike the block above, these were never in the allow-set: they 403 on both
  // the pre- and post-fix gate. They still route to loopback on many stacks, so
  // they are pinned so a future "helpful" normalisation cannot silently admit
  // them.
  it.each([
    '0.0.0.0', // all-zeros wildcard, not loopback
    '[::ffff:127.0.0.1]', // IPv4-mapped IPv6
  ])('403 for %s', (host) => {
    expect(statusFor(host)).toBe(403);
  });
});

describe('middleware — genuine-but-unadmitted loopback spellings stay out (intentional, fail-closed)', () => {
  // These do resolve to loopback, but they are deliberately NOT in the allow-set.
  // The dashboard only ever opens http://localhost:PORT or http://127.0.0.1:PORT,
  // so a browser never sends them, and holding the set to three exact spellings
  // is what keeps the literal match tight. Rejecting them is a conscious,
  // fail-closed choice — pinned so it stays deliberate. Admitting any of them
  // (e.g. *.localhost per RFC 6761) would be a separate, opt-in widening.
  it.each([
    'localhost.', // trailing-dot FQDN
    'app.localhost', // RFC 6761 *.localhost subdomain
    '127.0.0.2', // the rest of 127/8
    '127.0.0.2:4319',
    '[0:0:0:0:0:0:0:1]', // uncompressed IPv6 loopback
    '[::0.0.0.1]', // IPv6 with an embedded IPv4 loopback
  ])('403 for %s', (host) => {
    expect(statusFor(host)).toBe(403);
  });
});

describe('middleware — missing, empty, or malformed Host fails closed', () => {
  it('403 when the Host header is absent', () => {
    expect(statusFor(undefined)).toBe(403);
  });

  it('403 when the Host header is empty', () => {
    expect(statusFor('')).toBe(403);
  });

  it.each([
    '[bad', // unclosed IPv6 bracket
    '::1', // unbracketed IPv6 is invalid
    'http://localhost:4319', // a URL, not a host
    'localhost:4319/evil', // path smuggled past the authority
    'localhost:4319?x=1', // query smuggled past the authority
    'localhost:4319#frag', // fragment smuggled past the authority
    'localhost:4319@evil.com', // userinfo smuggle — the real host is evil.com
    'user:pass@localhost', // userinfo smuggle — reject rather than trust
    'localhost:99999999', // out-of-range port
  ])('403 for malformed host %s', (host) => {
    expect(statusFor(host)).toBe(403);
  });

  it('403 fast for an oversized / many-colon Host (constant-time, no hang)', () => {
    // The gate is a single anchored regex with no backtracking, so hostile-sized
    // input is simply rejected rather than causing a silent stall. Node caps real
    // request headers well below this, so it is defence-in-depth.
    expect(statusFor('a'.repeat(10_000))).toBe(403);
    expect(statusFor(`localhost${':1'.repeat(5_000)}`)).toBe(403);
  });
});

describe('middleware — x-forwarded-host is held to the same loopback bar', () => {
  it('200 when both Host and x-forwarded-host are loopback', () => {
    expect(statusFor('localhost:4319', { xForwardedHost: '127.0.0.1:4319' })).toBe(200);
  });

  it.each([
    'evil.com',
    '127.1',
    '[::ffff:127.0.0.1]',
    '',
    'localhost, evil.com', // comma-joined (duplicate-header collapse) — the leading token must not be trusted
    'localhost,evil.com',
  ])('403 when Host is loopback but x-forwarded-host is %s', (xForwardedHost) => {
    expect(statusFor('localhost:4319', { xForwardedHost })).toBe(403);
  });

  it('403 when duplicate x-forwarded-host headers join to a non-loopback value', () => {
    // The runtime collapses repeated headers into one comma-joined value, so a
    // smuggled second `x-forwarded-host` arrives as "localhost, evil.com". That
    // fails to parse as a bare authority and is rejected — pinned so a future
    // parser change cannot start trusting the leading token.
    const headers = new Headers();
    headers.set('host', 'localhost:4319');
    headers.append('x-forwarded-host', 'localhost');
    headers.append('x-forwarded-host', 'evil.com');
    const request = new NextRequest('http://localhost:4319/', { headers });
    expect(middleware(request).status).toBe(403);
  });

  it('403 when x-forwarded-host is loopback but Host is not', () => {
    // A good forwarded header does not excuse a non-loopback Host.
    expect(statusFor('evil.com', { xForwardedHost: 'localhost:4319' })).toBe(403);
  });
});

describe('middleware — the gate covers every route and method', () => {
  // There is no `config.matcher`, so the gate runs on every request: page GETs,
  // RSC data fetches, and Server Action POSTs alike. A rebinding attack targets
  // the mutating POST path, so the rejection must not depend on route or method.
  const routes = ['/', '/security', '/scan', '/exceptions/new', '/_next/data/x.json'];

  it.each(routes)('403s a non-loopback GET to %s', (path) => {
    expect(statusFor('evil.com', { path })).toBe(403);
  });

  it.each(routes)('403s a non-loopback Server Action POST to %s', (path) => {
    expect(statusFor('evil.com', { path, method: 'POST' })).toBe(403);
  });

  it('200s a loopback Server Action POST', () => {
    expect(statusFor('127.0.0.1:4319', { path: '/exceptions', method: 'POST' })).toBe(200);
  });

  it('exports no config.matcher — narrowing the gate would uncover Server Actions', () => {
    // Assert exactly the invariant the name states: no `matcher`. A matcher-free
    // `config` (e.g. `export const config = { runtime: 'nodejs' }`, the supported
    // way to move middleware onto the Node runtime) narrows nothing and must not
    // trip this — only a `matcher`, however spelled, uncovers Server Actions.
    const exported = middlewareModule as { config?: { matcher?: unknown } };
    expect(exported.config?.matcher).toBeUndefined();
  });
});

describe('middleware — the Server Action allowedOrigins list stays within the gate', () => {
  // next.config.ts's `serverActions.allowedOrigins` is a SECOND hard-coded list
  // of loopback spellings guarding the same write surface. It only ever WIDENS
  // Next's built-in Origin==Host check (which is consulted when the two differ),
  // so same-origin requests on any port are already allowed without it — but the
  // real risk is drift: a later edit that adds a non-loopback origin would leave
  // this middleware as the only thing rejecting it. Pin that every entry is a
  // host the gate itself admits, so the two lists cannot silently disagree.
  const allowedOrigins = nextConfig.experimental?.serverActions?.allowedOrigins ?? [];

  it('is non-empty (so the assertion below is not vacuously true)', () => {
    expect(allowedOrigins.length).toBeGreaterThan(0);
  });

  it.each(allowedOrigins)('the gate admits allowedOrigins entry %s', (origin) => {
    expect(statusFor(origin)).toBe(200);
  });
});

describe('middleware — the rejection is a real 403, the pass a real hand-off', () => {
  it('rejects with a 403 and an explanatory body', async () => {
    const response = runMiddleware('evil.com');
    expect(response.status).toBe(403);
    await expect(response.text()).resolves.toContain('localhost');
  });

  it('passes a loopback request through to the app', () => {
    // `NextResponse.next()` hands the request to the app; its sentinel header
    // distinguishes a genuine pass-through from an incidental 200 body.
    const response = runMiddleware('127.0.0.1:4319');
    expect(response.status).toBe(200);
    expect(response.headers.get('x-middleware-next')).toBe('1');
  });
});
