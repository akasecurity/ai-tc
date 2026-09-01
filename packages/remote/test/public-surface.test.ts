/**
 * What `@akasecurity/remote` lets the rest of the workspace do.
 *
 * This package is the only one permitted to open a socket, so its export list
 * is a security surface rather than an API convenience. `http.ts` holds four
 * guarantees by construction — no redirects, a deadline on every request, a
 * body cap, a protocol upgrade refused — and one by precondition: that plain
 * `http:` only ever names a loopback host, established by `isSafeEndpoint`
 * before an endpoint reaches disk. `send` cannot re-check that itself (the
 * predicate lives in @akasecurity/persistence, which this package must not
 * depend on), so while `send` was exported it was the one guarantee a caller
 * could step around — build a URL from a less-trusted source and the credential
 * goes out in cleartext.
 *
 * Pinned as an EXACT set rather than as "does not export send", because the
 * property is that the surface stays seven routes against one endpoint. A floor
 * would let the next raw-URL entry point in.
 */
import { describe, expect, it } from 'vitest';

import * as remote from '../src/index.ts';

const EXPECTED = [
  'DEFAULT_TIMEOUT_MS',
  'MAX_RESPONSE_BYTES',
  'RemoteRequestError',
  'RemoteRequestInvalid',
  'RemoteResponseInvalid',
  'RemoteTransportError',
  'createRemoteClient',
] as const;

describe('the package export surface', () => {
  it('is exactly the client, its error vocabulary and its two bounds', () => {
    expect(Object.keys(remote).sort()).toEqual([...EXPECTED].sort());
  });

  it('offers no way to hand the transport an arbitrary URL', () => {
    // The specific thing the exact set above exists to prevent, named so a
    // failure says WHY rather than just showing a diff of two lists.
    expect(
      Object.keys(remote),
      '`send` takes a caller-supplied URL, and this package cannot check that a ' +
        'plain-http one is loopback. Route new work through createRemoteClient.',
    ).not.toContain('send');
  });
});
