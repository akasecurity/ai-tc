import { describe, expect, it } from 'vitest';

import { createAttachClient, createRemoteClient } from '../src/client.ts';
import { classifyRemoteFailure } from '../src/failure-kind.ts';
import { RemoteEndpointRefused } from '../src/http.ts';
import { useLoopbackServer } from './helpers/loopback.ts';

// `createRemoteClient` and `createAttachClient` refuse an endpoint
// `isSafeEndpoint` (@akasecurity/schema) rejects, at construction — before
// either factory hands back a client at all. See client.ts's `resolveBaseUrl`,
// the one function both build their base URL through.

const API_KEY = 'not-a-real-key-1a2b3c4d5e6f';
const UNSAFE_ENDPOINT = 'http://aka.example-org.internal';

/** Capture the error a thunk threw, outside its own catch. */
function errorFrom(fn: () => unknown): Error | undefined {
  try {
    fn();
    return undefined;
  } catch (err) {
    return err as Error;
  }
}

describe('createRemoteClient refuses an unsafe endpoint', () => {
  const server = useLoopbackServer();

  it('refuses plain http to a real host, as a named, non-retryable error', () => {
    const err = errorFrom(() => createRemoteClient({ endpoint: UNSAFE_ENDPOINT, apiKey: API_KEY }));
    expect(err).toBeInstanceOf(RemoteEndpointRefused);
    expect(err?.name).toBe('RemoteEndpointRefused');
    // A local, construction-time refusal — never a verdict from the
    // deployment — so it classifies as `invalid-request`, not `unreachable`.
    expect(classifyRemoteFailure(err)).toBe('invalid-request');
  });

  it('names the origin alone in the message, never the full URL', () => {
    const withUserinfo = 'http://user:secret-token@aka.example-org.internal/path?token=abc';
    const err = errorFrom(() => createRemoteClient({ endpoint: withUserinfo, apiKey: API_KEY }));
    expect(err?.message).toContain('http://aka.example-org.internal');
    expect(err?.message).not.toContain('secret-token');
    expect(err?.message).not.toContain('/path');
    expect(err?.message).not.toContain('token=abc');
  });

  it('accepts http on loopback, and the client actually works', async () => {
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          tenantName: 'acme',
          userEmail: 'dev@acme.example',
          role: 'member',
          keyKind: 'device',
          serverTime: '2026-08-24T10:00:00.000Z',
        }),
      );
    });

    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    await expect(client.whoami()).resolves.toMatchObject({ tenantName: 'acme' });
  });

  it('accepts https anywhere, at construction', () => {
    const err = errorFrom(() =>
      createRemoteClient({ endpoint: 'https://aka.example-org.internal', apiKey: API_KEY }),
    );
    expect(err).toBeUndefined();
  });
});

describe('createAttachClient refuses an unsafe endpoint', () => {
  it('refuses plain http to a real host, as a named, non-retryable error', () => {
    const err = errorFrom(() => createAttachClient({ endpoint: UNSAFE_ENDPOINT }));
    expect(err).toBeInstanceOf(RemoteEndpointRefused);
    expect(err?.name).toBe('RemoteEndpointRefused');
    expect(classifyRemoteFailure(err)).toBe('invalid-request');
  });

  it('accepts http on loopback', () => {
    const err = errorFrom(() => createAttachClient({ endpoint: 'http://127.0.0.1:1' }));
    expect(err).toBeUndefined();
  });

  it('accepts https anywhere', () => {
    const err = errorFrom(() =>
      createAttachClient({ endpoint: 'https://aka.example-org.internal' }),
    );
    expect(err).toBeUndefined();
  });
});
