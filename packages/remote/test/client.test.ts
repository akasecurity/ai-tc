import type { EgressIngestRequest, StorePostureSnapshot } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { createAttachClient, createRemoteClient } from '../src/client.ts';
import { MAX_RESPONSE_BYTES, RemoteRequestError, RemoteTransportError, send } from '../src/http.ts';
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

const egressRequest: EgressIngestRequest = {
  projectKey: 'a'.repeat(64),
  project: 'widgets',
  reconcile: { mode: 'walk', walkedPrefix: '' },
  hits: [
    {
      host: 'api.stripe.com',
      kind: 'provider',
      name: 'Stripe',
      category: 'payments',
      trust: 'recognized',
      network: null,
      method: 'POST',
      transport: 'https',
      url: 'https://api.stripe.com/v1/charges',
      template: false,
      dataClass: 'customer',
      site: { file: 'src/billing/charge.ts', line: 42, dynamic: false, vendored: false },
    },
  ],
};

const json = (payload: unknown) => JSON.stringify(payload);

/**
 * Fail rather than hang when a promise that should settle does not.
 *
 * A bare `await` on a never-settling promise is reported by vitest as a test
 * timeout, which reads as a slow runner rather than as the property that broke.
 */
async function withDeadline(promise: Promise<void>, ms: number, message: string): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new Error(message));
        }, ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

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

  it('does not let a caller override the credential or the computed length', async () => {
    // `SendOptions.headers` is a free-form record on an exported function, so
    // "no caller does that today" is not the guarantee. This is what makes the
    // spread ORDER in http.ts fail-red: inverting it leaves every other case
    // green while a caller can blank the credential or restate the length —
    // re-creating the truncation the byte-count exists to prevent.
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ ok: true }));
    });

    await send({
      method: 'POST',
      url: `${server.origin}/v1/store-posture`,
      apiKey: API_KEY,
      body: JSON.stringify({ hello: 'wörld' }),
      headers: { 'x-api-key': 'attacker-supplied', 'content-length': '1', accept: 'text/html' },
    });

    const seen = server.received.at(-1);
    expect(seen?.headers['x-api-key']).toBe(API_KEY);
    expect(seen?.headers['content-length']).toBe(String(Buffer.byteLength(seen?.body ?? '')));
    expect(seen?.headers.accept).toBe('application/json');
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

  it('gives up on a protocol upgrade, and drops the socket it detached', async () => {
    // A response that is not a RESPONSE. Node routes a 101 to 'upgrade', so the
    // response callback never runs — and the request then emits 'close', which
    // used to CLEAR the deadline. The deadline was the last thing that would
    // have rejected this promise, so the result was not a slow request but a
    // permanently pending one, inside a hook process the host will eventually
    // kill.
    //
    // Two mechanisms answer that now and they are NOT interchangeable, which is
    // why both halves are asserted below. The 'close' backstop settles the
    // promise and would do so here on its own — so a test reading only "it
    // rejected" passes with the upgrade handler deleted. What only the upgrade
    // handler does is name the cause and DESTROY the detached socket: once the
    // socket has left the request, nothing else owns it, and settling the
    // promise does not close it.
    const client = createRemoteClient({
      endpoint: server.origin,
      apiKey: API_KEY,
      timeoutMs: 30_000,
    });
    // Assigned synchronously by the executor below, before any handler runs.
    let socketClosed!: () => void;
    const serverSawClose = new Promise<void>((resolve) => {
      socketClosed = resolve;
    });
    server.reply((_req, res) => {
      res.socket?.on('close', socketClosed);
      // Written on the raw socket: `writeHead` cannot express the upgrade
      // semantics Node's client dispatches on.
      res.socket?.write(
        'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n',
      );
    });

    const started = process.hrtime.bigint();
    const error = await client.whoami().then(
      () => undefined,
      (e: unknown) => e as Error,
    );
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    expect(error).toBeInstanceOf(RemoteTransportError);
    // The CAUSE, not merely a rejection: this is what separates the upgrade
    // handler from the generic backstop, which would otherwise cover for its
    // deletion.
    expect(error?.message).toContain('upgrade');
    // Settled by refusing, NOT by waiting out the 30s deadline — the difference
    // between refusing and merely surviving. Three orders of magnitude apart,
    // so this reads the property rather than the runner's speed.
    expect(elapsedMs).toBeLessThan(5_000);

    // And the socket really is gone. Without the explicit destroy this hangs
    // until the suite's own teardown calls closeAllConnections, which is the
    // leak the handler exists to prevent.
    await withDeadline(serverSawClose, 5_000, 'the upgraded socket was never closed');
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

  it('keeps the status when it refuses an oversized NON-2xx body', async () => {
    // The existing oversized case answers 200, so it stays green under a fix
    // that drops the status entirely — which is exactly the defect. A verbose
    // 401 is the shape that matters: reported as a bare transport failure it
    // sends the reader to look at their network instead of their credential.
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(401, { 'content-type': 'application/json' });
      const chunk = 'x'.repeat(64 * 1024);
      const pump = (): void => {
        while (res.write(chunk)) {
          /* until backpressure, then wait for drain */
        }
      };
      res.on('drain', pump);
      pump();
    });

    const error = await client.whoami().then(
      () => undefined,
      (e: unknown) => e as RemoteTransportError,
    );

    expect(error).toBeInstanceOf(RemoteTransportError);
    // Positive control on the reason, so the status assertion cannot pass on
    // some other rejection that happens to carry one.
    expect(error?.message).toContain(String(MAX_RESPONSE_BYTES));
    expect(error?.status).toBe(401);
  });

  it('picks the TLS transport for an https endpoint, not the plain one', async () => {
    // Every other case in this file drives the loopback server over plain HTTP,
    // so `httpsRequest` — the branch EVERY production deployment takes, since
    // `isSafeEndpoint` restricts `http:` to loopback — was exercised by nothing.
    //
    // Pinned at the wire rather than by standing up a TLS server with a
    // self-signed certificate. The cap, the deadline and the upgrade refusal are
    // transport-agnostic (they live above the switch), so duplicating them over
    // TLS would be suite weight rather than coverage; what is NOT proven
    // elsewhere is the switch itself. A port nothing listens on tells us which
    // module dialled: node:https fails connecting or negotiating TLS, promptly,
    // rather than waiting out the deadline.
    const client = createRemoteClient({
      endpoint: 'https://127.0.0.1:1',
      apiKey: API_KEY,
      timeoutMs: 2_000,
    });

    const error = await client.whoami().then(
      () => undefined,
      (e: unknown) => e as RemoteTransportError,
    );

    expect(error).toBeInstanceOf(RemoteTransportError);
    // Not a timeout: the switch resolved and the socket was refused promptly.
    expect(error?.message).not.toContain('2000ms');
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

describe('the shares-ingest submission', () => {
  const server = useLoopbackServer();

  it('posts a well-formed submission', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ ok: true }));
    });

    await client.recordProjectEgress(egressRequest);
    expect(server.received.at(-1)?.url).toBe('/v1/shares');
  });

  it('refuses a malformed request before it reaches the network', async () => {
    // Validated on the way out, the same discipline as recordAuditEvent: a
    // deterministic local shape bug must not be indistinguishable from a
    // transport fault to a caller counting failures toward a circuit breaker.
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    const before = server.received.length;

    const [firstHit] = egressRequest.hits;
    if (firstHit === undefined) throw new Error('fixture must carry at least one hit');

    await expect(
      client.recordProjectEgress({
        ...egressRequest,
        hits: [{ ...firstHit, site: { ...firstHit.site, line: -1 } }] as never,
      }),
    ).rejects.toThrow();

    expect(server.received).toHaveLength(before);
  });

  it('rejects a malformed projectKey digest before it reaches the wire', async () => {
    // The digest is the one field on this request derived from the machine's own
    // filesystem: a non-git project keys on `path:<abs root>`, which embeds an OS
    // username. Hashing is what makes that safe to send, so a value that is not a
    // digest is the exact shape of a build that forgot to hash — and it must fail
    // HERE, on the machine that still holds the plaintext, not as a remote 400.
    //
    // Each case is a different way to miss: too short, uppercase hex, right
    // length but not hex, and something that never resembled a digest at all.
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    const before = server.received.length;

    for (const bad of ['a'.repeat(63), 'A'.repeat(64), 'zz'.repeat(32), 'AKIA-not-a-digest']) {
      await expect(
        client.recordProjectEgress({ ...egressRequest, projectKey: bad }),
      ).rejects.toThrow();
    }

    expect(server.received).toHaveLength(before);
  });
});

describe('routes', () => {
  const server = useLoopbackServer();

  it('addresses each of the ten, and tolerates trailing slashes on the endpoint', async () => {
    // SEVERAL slashes, not one. The normalization is a scan rather than a
    // `replace(/\/+$/, '')` — that regex is quadratic on an all-slash string,
    // since the engine retries from every position and each attempt walks to the
    // end — and a single-slash fixture cannot tell the two implementations
    // apart, so it would go green on a scan that stripped only the last one.
    const client = createRemoteClient({ endpoint: `${server.origin}///`, apiKey: API_KEY });
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
              : req.url === '/v1/shares'
                ? json({ ok: true })
                : req.url === '/v1/plugin/commands'
                  ? json({ command: null })
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
    await client.recordAuditEvents([
      {
        id: 'e2',
        eventType: 'session',
        startedAt: '2026-08-24T10:00:00.000Z',
        inspections: [],
      },
    ]);
    await client.reportStorePosture(snapshot);
    await client.getPolicyBundle();
    await client.whoami();
    await client.recordProjectEgress(egressRequest);
    await client.pollCommand();
    await client.ackCommand('cmd_1', { outcome: 'reported', projectsForwarded: 0 });

    expect(server.received.map((r) => `${r.method ?? ''} ${r.url ?? ''}`)).toEqual([
      'POST /v1/events',
      'POST /v1/inventory',
      'POST /v1/audit-events',
      'POST /v1/audit-events/batch',
      'POST /v1/store-posture',
      'GET /v1/policy-bundle',
      'GET /v1/plugin/whoami',
      'POST /v1/shares',
      'GET /v1/plugin/commands',
      'POST /v1/plugin/commands/cmd_1/ack',
    ]);
  });

  /**
   * The command id is echoed back from the wire, so it is the one path segment
   * this client does not author. Unencoded, a `../` in it walks the URL onto a
   * different route on the same host with this machine's credential attached —
   * `printable(128)` rejects control characters but not slashes or dots.
   */
  it('encodes a command id rather than pasting it into the path', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ ok: true }));
    });

    // The server records every request in this describe, so index from HERE
    // rather than from 0 — `received[0]` is the first case's POST /v1/events.
    const before = server.received.length;
    await client.ackCommand('../../v1/events', { outcome: 'reported', projectsForwarded: 0 });

    const url = server.received[before]?.url ?? '';
    expect(url).toBe('/v1/plugin/commands/..%2F..%2Fv1%2Fevents/ack');
    expect(url).not.toContain('../');
  });

  /**
   * A deployment older than this route answers 404, and that is not an outage:
   * it is a deployment saying it has no command channel. Treated as "nothing
   * pending" so a device and a deployment can be upgraded weeks apart — the
   * same tolerance the audit-events batch route already has.
   */
  it('reads a 404 on the poll as no command, not as a failure', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(json({ error: { code: 'NOT_FOUND' } }));
    });

    await expect(client.pollCommand()).resolves.toBeNull();
  });

  /**
   * The scope is the privilege. A deployment that sends a path gets a parse
   * failure HERE, at the transport, before anything downstream can read it —
   * the client-side half of the pin `DeviceCommand.strict()` holds.
   */
  it('refuses a command that tries to name a directory', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        json({
          command: {
            id: 'cmd_1',
            kind: 'shares_rescan',
            issuedAt: '2026-09-03T12:00:00.000Z',
            expiresAt: '2026-09-04T12:00:00.000Z',
            searchRoots: ['/'],
          },
        }),
      );
    });

    await expect(client.pollCommand()).rejects.toThrow();
  });

  /** A malformed ack names the local defect instead of becoming a 400. */
  it('refuses to send an ack this device assembled wrongly', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    const before = server.received.length;

    await expect(
      // A failed ack with no reason — the case the discriminated union exists
      // to stop, caught before it leaves the machine.
      client.ackCommand('cmd_1', { outcome: 'failed', projectsForwarded: 0 } as never),
    ).rejects.toThrow();

    expect(server.received).toHaveLength(before);
  });
});

describe('recordAuditEvents', () => {
  const server = useLoopbackServer();

  const event = (id: string) => ({
    id,
    eventType: 'session' as const,
    startedAt: '2026-08-24T10:00:00.000Z',
    inspections: [],
  });

  it('sends the whole batch in one request and reports what was accepted', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ accepted: 2 }));
    });
    const before = server.received.length;

    const ack = await client.recordAuditEvents([event('a'), event('b')]);

    expect(ack).toEqual({ accepted: 2 });
    // Two events, ONE round trip — the whole point of the route.
    expect(server.received).toHaveLength(before + 1);
  });

  // A deployment that predates this route answers 404. That is not an outage —
  // it is an older deployment saying it speaks only the single-event form — and
  // the device has to keep working against it, or a device and a deployment
  // could never be upgraded weeks apart.
  //
  // OPT-IN, because the remedy is 50 sequential round trips and only a caller
  // whose budget is charged per request can afford them. This is that caller's
  // shape; the default is pinned by the test below.
  it('falls back to one request per event when the caller asks for it', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((req, res) => {
      if (req.url === '/v1/audit-events/batch') {
        res.writeHead(404);
        res.end();
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ ok: true }));
    });

    const before = server.received.length;

    const ack = await client.recordAuditEvents([event('a'), event('b')], {
      fallbackToSingleEvents: true,
    });

    expect(ack).toEqual({ accepted: 2 });
    expect(server.received.slice(before).map((r) => r.url ?? '')).toEqual([
      '/v1/audit-events/batch',
      '/v1/audit-events',
      '/v1/audit-events',
    ]);
  });

  // The DEFAULT, and the reason it is the default. A caller that bounds the
  // whole call — the live forward bounds it at FORWARD_BUDGET_MS — cannot
  // survive the fallback: 50 sequential round trips inside one budget time out,
  // three chunks of that open the breaker, and a deployment answering every
  // request it understands gets reported as down while every row is dropped.
  // So an unasked-for fallback is not a kindness, and this raises instead.
  it('raises rather than silently falling back when the route is absent', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((req, res) => {
      if (req.url === '/v1/audit-events/batch') {
        res.writeHead(404);
        res.end();
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ ok: true }));
    });

    const before = server.received.length;

    await expect(client.recordAuditEvents([event('a'), event('b')])).rejects.toMatchObject({
      name: 'RemoteRouteAbsent',
    });

    // The batch attempt and NOTHING else: not one single-event request was made
    // on the caller's budget without it asking.
    expect(server.received.slice(before).map((r) => r.url ?? '')).toEqual([
      '/v1/audit-events/batch',
    ]);
  });

  // Refused before a socket is opened, and raised as the local-defect error
  // rather than a ZodError — a caller counting failures toward a breaker must
  // not read a shape bug on this machine as an outage.
  it('refuses to send a batch the route would reject', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ accepted: 1 }));
    });
    const before = server.received.length;

    await expect(
      client.recordAuditEvents([
        {
          ...event('a'),
          inspections: [
            {
              ruleId: 'r',
              ruleName: 'R',
              // The namespace the receiving side mints for itself.
              ruleVersion: 'capture/1',
              category: 'secret',
              severity: 'high',
              span: { start: 0, end: 1 },
              maskedMatch: '*',
              actionTaken: 'redact',
              confidence: 1,
            },
          ],
        },
      ]),
    ).rejects.toMatchObject({ name: 'RemoteRequestInvalid' });
    // Refused BEFORE a socket was opened.
    expect(server.received).toHaveLength(before);
  });

  it('refuses an empty batch rather than spending a round trip on nothing', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    const before = server.received.length;
    await expect(client.recordAuditEvents([])).rejects.toMatchObject({
      name: 'RemoteRequestInvalid',
    });
    expect(server.received).toHaveLength(before);
  });

  it('rejects a non-2xx that is not a 404', async () => {
    const client = createRemoteClient({ endpoint: server.origin, apiKey: API_KEY });
    server.reply((_req, res) => {
      res.writeHead(500);
      res.end();
    });

    await expect(client.recordAuditEvents([event('a')])).rejects.toMatchObject({ status: 500 });
  });
});

// The credential-less client — the one surface in this package that reaches a
// deployment with no key, because obtaining one is what these two routes are
// for.
//
// The export-shape assertion in public-surface.test.ts pins WHAT this object
// exposes; these pin what it DOES. The distinction matters here more than
// usual: the separate factory exists so a caller cannot present a credential on
// these routes or reach an authenticated one through this object, and neither
// of those is visible in a list of method names.
describe('the credential-less attach client', () => {
  const server = useLoopbackServer();

  const request = {
    deviceId: '6f2d64f0-b6a4-4bb1-9a3c-6a4c26f5c9d1',
    hostname: 'dev-laptop.local',
    os: 'darwin 25.5.0',
    cliVersion: '0.9.8',
  };

  const grant = {
    deviceCode: 'Xbi-3EJMYRNAtmqp2icmOZRlXovqVv0',
    userCode: 'BCDF-GHJK',
    verificationUri: 'https://aka.example.test/attach',
    expiresIn: 600,
    interval: 5,
  };

  it('posts the device request and parses the grant back', async () => {
    const client = createAttachClient({ endpoint: server.origin });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json(grant));
    });

    await expect(client.startGrant(request)).resolves.toMatchObject({
      userCode: 'BCDF-GHJK',
      interval: 5,
    });
    const seen = server.received.at(-1);
    expect(seen?.method).toBe('POST');
    expect(seen?.url).toBe('/v1/attach/device');
    expect(JSON.parse(seen?.body ?? '{}')).toMatchObject({ hostname: 'dev-laptop.local' });
  });

  // THE PROPERTY THE SEPARATE FACTORY EXISTS FOR, and the one a list of method
  // names cannot show. This object has no credential to send and no way to be
  // given one; asserting the header is absent is what makes that a fact about
  // the wire rather than about the constructor's signature.
  it('sends no credential header on either route', async () => {
    const client = createAttachClient({ endpoint: server.origin });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json(grant));
    });
    await client.startGrant(request);

    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ status: 'pending' }));
    });
    await client.poll(grant.deviceCode);

    for (const seen of server.received.slice(-2)) {
      expect(seen.headers['x-api-key']).toBeUndefined();
      expect(seen.headers.authorization).toBeUndefined();
    }
  });

  it('posts the device code when polling, and never the user code', async () => {
    const client = createAttachClient({ endpoint: server.origin });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ status: 'pending' }));
    });

    await expect(client.poll(grant.deviceCode)).resolves.toEqual({ status: 'pending' });
    const seen = server.received.at(-1);
    expect(seen?.url).toBe('/v1/attach/token');
    // The USER code is the short one a person reads aloud; it belongs to the
    // browser half of the flow and has no business on this route.
    expect(seen?.body).toContain(grant.deviceCode);
    expect(seen?.body).not.toContain(grant.userCode);
  });

  // The lenient union's whole point, exercised through the client rather than
  // against the parser: every state arrives as a 200 and must survive the round
  // trip intact, including one this build has never heard of.
  it.each([
    ['pending', { status: 'pending' }],
    ['slow_down', { status: 'slow_down', interval: 10 }],
    ['denied', { status: 'denied', message: 'Ask an owner or admin.' }],
    ['expired', { status: 'expired' }],
    ['a status this build has never heard of', { status: 'authorization_pending' }],
  ] as const)('parses %s from a 200', async (_name, payload) => {
    const client = createAttachClient({ endpoint: server.origin });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json(payload));
    });

    await expect(client.poll(grant.deviceCode)).resolves.toMatchObject(payload);
  });

  // THE FALLBACK CONTRACT. A 404 from `startGrant` is how a client learns the
  // deployment does not offer this flow — it predates it, or has it switched
  // off, and the two are deliberately indistinguishable. It has to arrive as a
  // rejection carrying the status, since that is what `notOfferedStatus` is
  // compared against.
  it('rejects a 404 with the status the caller falls back on', async () => {
    const client = createAttachClient({ endpoint: server.origin });
    server.reply((_req, res) => {
      res.writeHead(404);
      res.end();
    });

    await expect(client.startGrant(request)).rejects.toMatchObject({
      status: client.notOfferedStatus,
    });
    expect(client.notOfferedStatus).toBe(404);
  });

  it('rejects a non-2xx poll rather than reading a state out of it', async () => {
    const client = createAttachClient({ endpoint: server.origin });
    server.reply((_req, res) => {
      res.writeHead(500);
      res.end();
    });

    // Every state this flow defines arrives as a 200 with a body naming it, so
    // a non-2xx is a transport or deployment fault rather than an answer.
    await expect(client.poll(grant.deviceCode)).rejects.toMatchObject({ status: 500 });
  });

  it('refuses a grant body that is not the shape the contract names', async () => {
    const client = createAttachClient({ endpoint: server.origin });
    server.reply((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(json({ userCode: 'BCDF-GHJK' }));
    });

    await expect(client.startGrant(request)).rejects.toMatchObject({
      name: 'RemoteResponseInvalid',
    });
  });
});
