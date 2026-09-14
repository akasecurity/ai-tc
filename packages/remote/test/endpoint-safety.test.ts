import { describe, expect, it } from 'vitest';

import { createAttachClient, createRemoteClient } from '../src/client.ts';
import { useLoopbackServer } from './helpers/loopback.ts';

// `createRemoteClient` and `createAttachClient` refuse an endpoint
// `isSafeEndpoint` (@akasecurity/schema) rejects, at construction — before
// either factory hands back a client at all. See client.ts's `refuseUnsafeEndpoint`.

const API_KEY = 'not-a-real-key-1a2b3c4d5e6f';
const UNSAFE_ENDPOINT = 'http://aka.example-org.internal';

describe('createRemoteClient refuses an unsafe endpoint', () => {
  const server = useLoopbackServer();

  it('refuses plain http to a real host', () => {
    expect(() => createRemoteClient({ endpoint: UNSAFE_ENDPOINT, apiKey: API_KEY })).toThrow();
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
    expect(() =>
      createRemoteClient({ endpoint: 'https://aka.example-org.internal', apiKey: API_KEY }),
    ).not.toThrow();
  });
});

describe('createAttachClient refuses an unsafe endpoint', () => {
  it('refuses plain http to a real host', () => {
    expect(() => createAttachClient({ endpoint: UNSAFE_ENDPOINT })).toThrow();
  });

  it('accepts http on loopback', () => {
    expect(() => createAttachClient({ endpoint: 'http://127.0.0.1:1' })).not.toThrow();
  });

  it('accepts https anywhere', () => {
    expect(() =>
      createAttachClient({ endpoint: 'https://aka.example-org.internal' }),
    ).not.toThrow();
  });
});
