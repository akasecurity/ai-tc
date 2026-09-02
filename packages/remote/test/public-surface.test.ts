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
 * property is that the surface stays a fixed list of named routes against one
 * endpoint. A floor would let the next raw-URL entry point in.
 *
 * A second factory now sits beside the first: `createAttachClient`, which
 * speaks two routes and holds no credential. That is a widening of this surface
 * and it is deliberate — those two routes are how a credential comes into
 * existence — but it widens by ROUTE, not by capability. Neither client can be
 * handed a URL, and the credential-less one cannot express any route but its
 * two, so the guarantee this file exists to hold is unchanged.
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
  // The credential-LESS client, and the one addition to this surface allowed to
  // talk to a deployment without a key.
  //
  // It earns that by being a SEPARATE factory rather than a flag on the one
  // above. Its two routes are how a machine obtains a credential in the first
  // place, so it necessarily has none while calling them — and because it is a
  // distinct object, a caller cannot reach any other route through it: it does
  // not know how to build one. An optional `apiKey` on `createRemoteClient`
  // would have been the cheaper change and the worse one, turning a forgotten
  // credential into a silent unauthenticated call on every route in the client.
  'createAttachClient',
] as const;

describe('the package export surface', () => {
  it('is exactly the client, its error vocabulary and its two bounds', () => {
    expect(Object.keys(remote).sort()).toEqual([...EXPECTED].sort());
  });

  // The widening above must not become a general escape hatch: the
  // credential-less client is admissible BECAUSE it can only reach the two
  // routes that precede having a credential.
  it('keeps the credential-less client to the two routes that precede a credential', () => {
    const client = remote.createAttachClient({ endpoint: 'https://aka.example.test' });
    expect(Object.keys(client).sort()).toEqual(['notOfferedStatus', 'poll', 'startGrant']);
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
