import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

// A real HTTP server on 127.0.0.1, for the CLI paths that put bytes on a socket.
//
// A stubbed transport proves what a command DECIDED; it cannot prove what it
// SENT. The forward a scan makes is a privacy boundary — a body with no source
// text, a digested project key, the credential in a header and nowhere else —
// and every one of those claims is about the request as it left the process.
// So the suite that makes them drives the real client against a real socket and
// reads the request off the wire.
//
// Loopback is what both the vitest no-network guard and the egress-blocked CI
// job permit, and binding on 127.0.0.1 rather than every interface is
// deliberate: a test server answering on a LAN address is a listener on
// somebody's machine.

/** One request as the server saw it. */
export interface LoopbackRequest {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingMessage['headers'];
  body: string;
}

export interface LoopbackServer {
  /** Base URL, e.g. `http://127.0.0.1:54321`. */
  readonly origin: string;
  /** Every request the server has seen, in order. */
  readonly received: LoopbackRequest[];
  /** Answer subsequent requests with this. */
  reply(handler: (req: LoopbackRequest, res: ServerResponse) => void): void;
  /** Stop listening. Always call it, from a `finally`. */
  close(): Promise<void>;
}

/**
 * Stand a server up and hand back its origin.
 *
 * Bound on port 0 so parallel suites cannot collide. Started and stopped
 * explicitly rather than through `beforeAll`/`afterAll` hooks, because a case
 * that needs its own answer to the same route needs its own server, and a
 * file-wide one would make the reply handler shared mutable state between
 * cases that vitest is free to interleave.
 */
export async function startLoopbackServer(): Promise<LoopbackServer> {
  const received: LoopbackRequest[] = [];
  let handler: (req: LoopbackRequest, res: ServerResponse) => void = (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  };

  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const handled: LoopbackRequest = {
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      };
      received.push(handled);
      handler(handled, res);
    });
  });

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no port bound');

  return {
    origin: `http://127.0.0.1:${String(address.port)}`,
    received,
    reply(next) {
      handler = next;
    },
    async close() {
      // `closeAllConnections` first: a keep-alive socket the client left open
      // holds `close` for ever, and a hung teardown reads as a hung suite.
      server.closeAllConnections();
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
    },
  };
}
