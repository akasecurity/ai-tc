import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import { afterAll, beforeAll } from 'vitest';

// A real HTTP server on 127.0.0.1, because the thing under test is a transport.
//
// Mocking `node:https` would leave every property this module actually claims
// unproven — that a deadline fires, that an oversized body is refused, that a
// 3xx is returned rather than followed. Those are socket behaviours, so the
// test needs a socket. Loopback is what both the vitest no-network guard and
// the egress-blocked CI job permit.

export interface Handled {
  method: string | undefined;
  url: string | undefined;
  headers: IncomingMessage['headers'];
  body: string;
}

export interface LoopbackServer {
  /** Base URL, e.g. `http://127.0.0.1:54321`. */
  readonly origin: string;
  /** Every request the server has seen, in order. */
  readonly received: Handled[];
  /** Answer the next request with this. */
  reply(handler: (req: Handled, res: ServerResponse) => void): void;
}

/**
 * Stand a server up for the file and tear it down after.
 *
 * Bound on port 0 so parallel suites cannot collide, and on 127.0.0.1
 * explicitly rather than on every interface — a test server that answers on a
 * LAN address is a listener on someone's machine.
 */
export function useLoopbackServer(): LoopbackServer {
  const received: Handled[] = [];
  let handler: (req: Handled, res: ServerResponse) => void = (_req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  };
  let server: Server;
  let origin = '';

  beforeAll(async () => {
    server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const handled: Handled = {
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
    origin = `http://127.0.0.1:${String(address.port)}`;
  });

  afterAll(async () => {
    // `closeAllConnections` first: a keep-alive socket the client left open
    // holds `close` forever, and a hung teardown reads as a hung suite.
    server.closeAllConnections();
    await new Promise<void>((resolve) => {
      server.close(() => { resolve(); });
    });
  });

  return {
    get origin() {
      return origin;
    },
    received,
    reply(next) {
      handler = next;
    },
  };
}
