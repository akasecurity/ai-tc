import type { StorePostureSnapshot } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { createRemoteClient } from '../src/client.ts';
import { MAX_RESPONSE_BYTES, RemoteRequestError, RemoteTransportError } from '../src/http.ts';
import { useLoopbackServer } from './helpers/loopback.ts';

const API_KEY = 'not-a-real-key-9d3f7b2c4e81';

const snapshot: StorePostureSnapshot = {
  deviceId: '6f2d64f0-b6a4-4bb1-9a3c-6a4c26f5c9d1',
  hostname: 'dev-laptop.local',
  capturedAt: 1_766_000_000_000,
  storePresent: true,
  schemaVersion: 12,
  findingsTotal: 3,
  findingsFirstAt: null,
  findingsLastAt: null,
  packs: [],
  policyCounts: {
    total: 0,
    disabled: 0,
    byAction: { warn: 0, redact: 0, block: 0, allow: 0, log: 0 },
  },
};

const bundle = {
  version: 'sha256-abc',
  policies: [],
  rules: [],
  customKeywords: [],
  fetchedAt: '2026-08-24T10:00:00.000Z',
};

const json = (payload: unknown) => JSON.stringify(payload);

describe('the credential on the wire', () => {
  const server = useLoopbackServer();

  it('sends the key on every route, and sends it exactly once', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ accepted: 1, duplicates: 0 }));
    });

    await client.ingestEvents({ events: [] as never });
    const seen = server.received.at(-1);

    expect(seen?.headers['x-api-key']).toBe(API_KEY);
    // One credential header, not two. A second copy is one more place an
    // intermediary can log it for no gain.
    expect(seen?.headers.authorization).toBeUndefined();
  });

  it('sends a byte-length content-length, so a multi-byte body is not truncated', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ ok: true }));
    });

    // The hostname is where a snapshot most plausibly carries non-ASCII.
    await client.reportStorePosture({ ...snapshot, hostname: 'naïve-café-höst' });
    const seen = server.received.at(-1);

    expect(seen?.headers['content-length']).toBe(String(Buffer.byteLength(seen?.body ?? '')));
    // The positive control: the body really did survive the trip intact.
    expect(seen?.body).toContain('naïve-café-höst');
  });
});

describe('a redirect is answered, never followed', () => {
  const server = useLoopbackServer();

  it('returns the 3xx as a status rather than replaying the key at Location', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      // A deployment that has been taken over, or merely misconfigured, points
      // somewhere else. Following it hands the credential to that host.
      res.writeHead(302, { location: 'https://attacker.example/collect' });
      res.end();
    });

    const error = await client.whoami().then(
      () => undefined,
      (e: unknown) => e as RemoteRequestError,
    );

    expect(error).toBeInstanceOf(RemoteRequestError);
    expect(error?.status).toBe(302);
    // One request in total: nothing followed the redirect.
    expect(server.received).toHaveLength(1);
  });
});

describe('failures carry a status and nothing the server wrote', () => {
  const server = useLoopbackServer();

  it('throws RemoteRequestError with the status alone', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    const secret = 'internal-stack-trace-and-a-connection-string';
    server.reply((_req, res) => {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(json({ error: { message: secret } }));
    });

    const error = await client.whoami().then(
      () => undefined,
      (e: unknown) => e as Error,
    );

    expect(error).toBeInstanceOf(RemoteRequestError);
    // Positive control first: the message says something specific, so the
    // absence check below cannot pass on an empty string.
    expect(error?.message).toContain('500');
    expect(error?.message).not.toContain(secret);
  });

  it('rejects a 2xx body that is not the shape the route promises', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ accepted: 'not a number' }));
    });

    await expect(client.ingestEvents({ events: [] as never })).rejects.toThrow(/cannot read/);
  });

  it('rejects a 2xx body that is not JSON at all', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      // A captive portal or a proxy error page is the realistic shape here.
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<html>sign in to the network</html>');
    });

    await expect(client.whoami()).rejects.toThrow(/not JSON/);
  });
});

describe('bounds', () => {
  const server = useLoopbackServer();

  it('gives up on a deployment that never answers', async () => {
    const client = createRemoteClient({
      endpoint: server.origin,
      apiKey: API_KEY,
      timeoutMs: 150,
    });
    server.reply(() => {
      // Never respond. A hook lives inside its host's own timeout, so an
      // unbounded request is a stalled session rather than a slow one.
    });

    const error = await client.whoami().then(
      () => undefined,
      (e: unknown) => e as Error,
    );

    expect(error).toBeInstanceOf(RemoteTransportError);
    expect(error?.message).toContain('150ms');
  });

  it('refuses a response larger than the cap instead of buffering it', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      // Stream past the cap rather than allocating it here: the property is
      // that the CLIENT stops, and it has to stop before the sender does.
      const chunk = 'x'.repeat(64 * 1024);
      const pump = (): void => {
        while (res.write(chunk)) {
          /* until the socket applies backpressure, then wait for drain */
        }
      };
      res.on('drain', pump);
      pump();
    });

    const error = await client.whoami().then(
      () => undefined,
      (e: unknown) => e as Error,
    );

    expect(error).toBeInstanceOf(RemoteTransportError);
    expect(error?.message).toContain(String(MAX_RESPONSE_BYTES));
  });

  it('reports a deployment that is not listening', async () => {
    // Port 1 on loopback: reachable by the guard, refused by the kernel.
    const client = createRemoteClient({ endpoint: 'http://127.0.0.1:1', apiKey: API_KEY });
    await expect(client.whoami()).rejects.toBeInstanceOf(RemoteTransportError);
  });
});

describe('the conditional policy-bundle fetch', () => {
  const server = useLoopbackServer();

  it('parses a 200 and reports the validator it came with', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', etag: 'W/"sha256-abc"' });
      res.end(json(bundle));
    });

    const result = await client.getPolicyBundle();
    expect(result.changed).toBe(true);
    expect(result.changed && result.bundle.version).toBe('sha256-abc');
    expect(result.etag).toBe('W/"sha256-abc"');
    expect(server.received.at(-1)?.headers['if-none-match']).toBeUndefined();
  });

  it('presents the cached validator and reports no change on a 304', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(304);
      res.end();
    });

    const result = await client.getPolicyBundle('W/"sha256-abc"');
    expect(result).toEqual({ changed: false, etag: 'W/"sha256-abc"' });
    expect(server.received.at(-1)?.headers['if-none-match']).toBe('W/"sha256-abc"');
  });

  it('carries the presented validator forward when a 304 omits one', async () => {
    // Dropping it would send the next poll unconditionally, and the deployment
    // would answer with a full bundle every time — a cheap poll turned into a
    // transfer on a schedule.
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(304);
      res.end();
    });

    const result = await client.getPolicyBundle('W/"carried"');
    expect(result.etag).toBe('W/"carried"');
  });
});

describe('the audit-event submission', () => {
  const server = useLoopbackServer();

  const auditEvent = {
    id: 'evt-1',
    eventType: 'session' as const,
    startedAt: '2026-08-24T10:00:00.000Z',
    inspections: [],
  };

  it('posts a well-formed submission', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ accepted: true }));
    });

    await client.recordAuditEvent(auditEvent);
    expect(server.received.at(-1)?.url).toBe('/v1/audit-events');
  });

  it('refuses a reserved capture ruleVersion before it reaches the network', async () => {
    // The one field a deployment refuses on. Catching it here names the defect
    // instead of turning it into a 400 that a fail-open forwarder swallows.
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    const before = server.received.length;

    await expect(
      client.recordAuditEvent({
        ...auditEvent,
        eventType: 'tool_call',
        inspections: [
          {
            ruleId: 'secrets/aws-access-key',
            ruleName: 'AWS access key',
            ruleVersion: 'capture/secret/high',
            category: 'secret',
            severity: 'high',
            span: { start: 0, end: 4 },
            maskedMatch: 'AKIA…',
            actionTaken: 'redact',
            confidence: 1,
          },
        ],
      }),
    ).rejects.toThrow();

    expect(server.received).toHaveLength(before);
  });
});

describe('routes', () => {
  const server = useLoopbackServer();

  it('addresses each of the six, and tolerates a trailing slash on the endpoint', async () => {
    const client = createRemoteClient({ endpoint: `${server.origin}/`, apiKey: API_KEY });
    server.reply((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        req.url === '/v1/inventory'
          ? json({ hostId: 'h', harnessId: 'x', sourceProjectId: 'p' })
          : req.url === '/v1/policy-bundle'
            ? json(bundle)
            : req.url === '/v1/plugin/whoami'
              ? json({
                  tenantName: 'Example Org',
                  userEmail: 'dev@example.com',
                  role: 'member',
                  keyKind: 'plugin',
                  serverTime: '2026-08-24T10:00:00.000Z',
                })
              : json({ accepted: 1, duplicates: 0, ok: true }),
      );
    });

    await client.ingestEvents({ events: [] as never });
    await client.ingestInventory({});
    await client.recordAuditEvent({
      id: 'e',
      eventType: 'session',
      startedAt: '2026-08-24T10:00:00.000Z',
      inspections: [],
    });
    await client.reportStorePosture(snapshot);
    await client.getPolicyBundle();
    await client.whoami();

    expect(server.received.map((r) => `${r.method ?? ''} ${r.url ?? ''}`)).toEqual([
      'POST /v1/events',
      'POST /v1/inventory',
      'POST /v1/audit-events',
      'POST /v1/store-posture',
      'GET /v1/policy-bundle',
      'GET /v1/plugin/whoami',
    ]);
  });
});
