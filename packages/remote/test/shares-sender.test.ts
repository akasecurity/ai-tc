import type { EgressIngestRequest } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { createSharesSender, SHARES_FORWARD_TIMEOUT_MS } from '../src/shares-sender.ts';
import { useLoopbackServer } from './helpers/loopback.ts';

// A real socket for the adapter, because the one thing it adds over the client
// is the reading of a failure the socket produced — a refused port, an answer
// with a status — and a stub would only prove the adapter reads what the stub
// was told to say.

const CREDENTIAL = ['test', 'plugin', 'key'].join('-');

const request: EgressIngestRequest = {
  projectKey: 'a'.repeat(64),
  project: 'widgets',
  reconcile: { mode: 'walk', walkedPrefix: '' },
  hits: [],
};

describe('createSharesSender', () => {
  const server = useLoopbackServer();
  const connection = () => ({ endpoint: server.origin, apiKey: CREDENTIAL });

  it('reports ok for an accepted submission, presenting the credential', async () => {
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });

    const result = await createSharesSender()(connection(), request);

    expect(result).toEqual({ ok: true });
    expect(server.received.at(-1)?.url).toBe('/v1/shares');
    expect(server.received.at(-1)?.headers['x-api-key']).toBe(CREDENTIAL);
  });

  it('reads a refusal off the status the deployment answered with', async () => {
    server.reply((_req, res) => {
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end('{"error":{"code":"FORBIDDEN"}}');
    });

    const result = await createSharesSender()(connection(), request);

    expect(result).toEqual({ ok: false, kind: 'forbidden' });
  });

  it('names a deployment that predates the route', async () => {
    server.reply((_req, res) => {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end('{"error":{"code":"NOT_FOUND"}}');
    });

    const result = await createSharesSender()(connection(), request);

    expect(result).toEqual({ ok: false, kind: 'route-absent' });
  });

  it('reports unreachable for a port nothing is listening on, without throwing', async () => {
    // Same host as the loopback server, a port that refuses the connection.
    const closed = new URL(server.origin);
    closed.port = '1';

    const result = await createSharesSender()(
      { endpoint: closed.origin, apiKey: CREDENTIAL },
      request,
    );

    expect(result).toEqual({ ok: false, kind: 'unreachable' });
  });

  it('refuses a body its own contract rejects, before the wire', async () => {
    const before = server.received.length;

    const result = await createSharesSender()(connection(), {
      ...request,
      projectKey: 'not-a-digest',
    });

    expect(result).toEqual({ ok: false, kind: 'invalid-request' });
    expect(server.received).toHaveLength(before);
  });

  it('carries a deadline sized for a full register, not a hook', () => {
    expect(SHARES_FORWARD_TIMEOUT_MS).toBe(15_000);
  });
});
