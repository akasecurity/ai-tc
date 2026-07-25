import { NextRequest } from 'next/server';
import { describe, expect, it } from 'vitest';

import * as middlewareModule from '../middleware.ts';
import { middleware } from '../middleware.ts';

// `middleware.ts` is the sole DNS-rebinding gate in front of the dashboard's
// unauthenticated, store-mutating Server Actions. Under rebinding the browser
// stamps the attacker's own domain into `Host` while `Origin` agrees with it,
// so Next's built-in CSRF check passes — only this Host-literal check closes
// the hole. It is untestable as a live network attack, so it is tested as what
// it is: a pure function over the `Host` / `x-forwarded-host` headers. Each row
// below pins the exact 200-vs-403 decision that keeps the gate honest.

interface MiddlewareInit {
  xForwardedHost?: string;
  path?: string;
  method?: string;
}

// Drive the real middleware with a real NextRequest. Only the request headers
// matter to the gate; the URL host is irrelevant (the gate reads the `Host`
// header, not the URL), so a fixed loopback URL is used and the header under
// test is set explicitly. Pass `host: undefined` to omit the header entirely.
function runMiddleware(host: string | undefined, init: MiddlewareInit = {}) {
  const headers = new Headers();
  if (host !== undefined) headers.set('host', host);
  if (init.xForwardedHost !== undefined) headers.set('x-forwarded-host', init.xForwardedHost);
  const request = new NextRequest(`http://localhost:4319${init.path ?? '/'}`, {
    method: init.method ?? 'GET',
    headers,
  });
  return middleware(request);
}

function statusFor(host: string | undefined, init: MiddlewareInit = {}): number {
  return runMiddleware(host, init).status;
}

describe('middleware — allowed loopback literals (any port)', () => {
  // The three accepted spellings, each with the default port, a non-default
  // port, and no port at all — "any port is fine; the name must be loopback".
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
  ])('200 for %s', (host) => {
    expect(statusFor(host)).toBe(200);
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

describe('middleware — alternate loopback encodings stay out of the allow-set', () => {
  // These all route to 127.0.0.1 on many stacks, and `new URL()` normalises
  // every one of them to the literal `127.0.0.1`. They are NOT in the allow-set
  // and must 403 — pinned here so a future "helpful" normalisation (or a
  // parser that folds them before the check) cannot silently open the gate.
  it.each([
    '127.1', // shorthand IPv4
    '0.0.0.0', // all-zeros, not loopback
    '[::ffff:127.0.0.1]', // IPv4-mapped IPv6
    '2130706433', // decimal IPv4
    '0x7f000001', // hex IPv4
    '127.000.000.001', // zero-padded dotted IPv4
    '127.1:4319', // ...with a port, too
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
});

describe('middleware — x-forwarded-host is held to the same loopback bar', () => {
  it('200 when both Host and x-forwarded-host are loopback', () => {
    expect(statusFor('localhost:4319', { xForwardedHost: '127.0.0.1:4319' })).toBe(200);
  });

  it.each(['evil.com', '127.1', '[::ffff:127.0.0.1]', ''])(
    '403 when Host is loopback but x-forwarded-host is %s',
    (xForwardedHost) => {
      expect(statusFor('localhost:4319', { xForwardedHost })).toBe(403);
    },
  );

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
    const exported = middlewareModule as Record<string, unknown>;
    expect(exported.config).toBeUndefined();
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
