// A local server that runs hooks inside one long-lived node process, so the
// per-call cost of starting node and loading the hook bundle is paid once. It
// listens on a unix socket in a directory only its owner can enter, never on a
// port, and answers one request per connection.
//
// Requests run one at a time: a hook reads a few process-wide things (the
// environment variables the account check names, the working directory), which
// the handler sets for the request and which concurrent requests would trample.
// A request the server cannot take — too large, a hook it does not serve, a
// full queue, a malformed frame — gets FALLBACK, and the client runs the node
// hook itself, so the server is only ever an accelerator.
//
// Fail-open, like every hook: whatever goes wrong, the client either gets what
// the node hook would have written or runs the node hook.
import { chmodSync, existsSync, mkdirSync, statSync, unlinkSync } from 'node:fs';
import { createConnection, createServer, type Server, type Socket } from 'node:net';
import { dirname } from 'node:path';

import type { HookRequest } from './wire.ts';
import { FALLBACK_RESPONSE, MAX_REQUEST_BYTES, okResponse, parseRequest } from './wire.ts';

/**
 * Runs one hook for one request and returns what it would have written to
 * stdout, or null to decline the request, which the client then runs itself.
 */
export type HookHandler = (request: HookRequest) => Promise<string | null>;

export interface HookServerOptions {
  readonly socketPath: string;
  readonly handlers: ReadonlyMap<string, HookHandler>;
  /** Exit after this long without a request. */
  readonly idleMs: number;
  /** Exit at the next idle moment after running this long. */
  readonly maxAgeMs: number;
  /** A request still running after this long is answered empty, and the server exits. */
  readonly handlerTimeoutMs: number;
  /** Requests waiting beyond the one running; the next gets FALLBACK. */
  readonly maxQueued: number;
  /** A client that sends nothing for this long is dropped. */
  readonly readTimeoutMs: number;
  /** True once the code this server runs has been replaced on disk. */
  readonly isStale: () => boolean;
  /** Directory mode for the socket's directory. */
  readonly dirMode: number;
  readonly onExit: (reason: string) => void;
  readonly log: (line: string) => void;
}

export interface RunningHookServer {
  stop(reason: string): Promise<void>;
}

/** Whether something is accepting connections on the socket. */
function isLive(path: string): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = createConnection(path);
    const done = (live: boolean): void => {
      probe.destroy();
      resolve(live);
    };
    probe.once('connect', () => {
      done(true);
    });
    probe.once('error', () => {
      done(false);
    });
  });
}

/** Creates the socket's directory owner-only, and refuses one someone else could enter. */
function prepareDirectory(dir: string, mode: number): void {
  mkdirSync(dir, { recursive: true, mode });
  const info = statSync(dir);
  const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  if (uid !== undefined && info.uid !== uid) throw new Error('the run directory is not ours');
  // Group and other bits matter only where the platform has them.
  if (process.platform !== 'win32' && (info.mode & 0o077) !== 0) {
    throw new Error('the run directory is accessible to other users');
  }
}

export async function startHookServer(options: HookServerOptions): Promise<RunningHookServer> {
  prepareDirectory(dirname(options.socketPath), options.dirMode);
  if (existsSync(options.socketPath)) {
    // A live server already owns it; a dead one left the file behind.
    if (await isLive(options.socketPath)) throw new Error('a hook server is already running');
    unlinkSync(options.socketPath);
  }

  const startedAt = Date.now();
  let queued = 0;
  let chain: Promise<void> = Promise.resolve();
  let idleTimer: NodeJS.Timeout | undefined;
  let stopping = false;

  const stop = (reason: string): Promise<void> => {
    if (stopping) return Promise.resolve();
    stopping = true;
    if (idleTimer !== undefined) clearTimeout(idleTimer);
    return new Promise((resolve) => {
      server.close(() => {
        try {
          unlinkSync(options.socketPath);
        } catch {
          // Already gone.
        }
        options.onExit(reason);
        resolve();
      });
      server.unref();
      // Connections still open would keep close() waiting; the clients treat a
      // dropped connection as FALLBACK.
      setTimeout(() => {
        resolve();
      }, 200).unref();
    });
  };

  const armIdle = (): void => {
    if (idleTimer !== undefined) clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      void stop('idle');
    }, options.idleMs);
    idleTimer.unref();
  };

  const TIMED_OUT = Symbol('timed out');
  const run = async (
    handler: HookHandler,
    request: HookRequest,
  ): Promise<string | null | typeof TIMED_OUT> => {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<typeof TIMED_OUT>((resolve) => {
      timer = setTimeout(() => {
        resolve(TIMED_OUT);
      }, options.handlerTimeoutMs);
    });
    try {
      return await Promise.race([handler(request), timeout]);
    } catch (error) {
      options.log(
        `hook ${request.hook} failed: ${error instanceof Error ? error.message : 'error'}`,
      );
      return '';
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  };

  const answer = (socket: Socket, response: string): void => {
    if (socket.destroyed) return;
    socket.end(response);
  };

  const onConnection = (socket: Socket): void => {
    armIdle();
    const chunks: Buffer[] = [];
    let size = 0;
    let handled = false;
    socket.setTimeout(options.readTimeoutMs, () => {
      socket.destroy();
    });
    socket.on('error', () => {
      socket.destroy();
    });
    // The client finished sending before a whole request arrived.
    socket.on('end', () => {
      if (handled) return;
      handled = true;
      answer(socket, FALLBACK_RESPONSE);
    });
    socket.on('data', (chunk: Buffer) => {
      if (handled) return;
      chunks.push(chunk);
      size += chunk.length;
      if (size > MAX_REQUEST_BYTES + 4096) {
        handled = true;
        answer(socket, FALLBACK_RESPONSE);
        return;
      }
      const parsed = parseRequest(Buffer.concat(chunks));
      if (parsed.kind === 'incomplete') return;
      handled = true;
      socket.setTimeout(0);
      if (parsed.kind === 'invalid') {
        answer(socket, FALLBACK_RESPONSE);
        return;
      }
      if (options.isStale() && !stopping) {
        answer(socket, FALLBACK_RESPONSE);
        void stop('replaced');
        return;
      }
      const handler = options.handlers.get(parsed.request.hook);
      if (handler === undefined || queued >= options.maxQueued || stopping) {
        answer(socket, FALLBACK_RESPONSE);
        return;
      }
      queued += 1;
      chain = chain.then(async () => {
        try {
          const stdout = await run(handler, parsed.request);
          if (stdout === TIMED_OUT) {
            // The handler is still running and cannot be interrupted: answer
            // as a hook that gave no opinion, and start over.
            answer(socket, okResponse(''));
            options.log(`hook ${parsed.request.hook} timed out; restarting`);
            void stop('handler-timeout');
          } else if (stdout === null) {
            answer(socket, FALLBACK_RESPONSE);
          } else {
            answer(socket, okResponse(stdout));
          }
        } finally {
          queued -= 1;
          if (!stopping && queued === 0 && Date.now() - startedAt > options.maxAgeMs) {
            void stop('max-age');
          }
        }
      });
    });
  };

  // A client may close its sending side once the request is sent and then wait
  // for the answer, so the server ends each connection itself.
  const server: Server = createServer({ allowHalfOpen: true }, onConnection);
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.socketPath, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  if (process.platform !== 'win32') chmodSync(options.socketPath, 0o600);
  server.on('error', (error) => {
    options.log(`server error: ${error.message}`);
    void stop('error');
  });
  armIdle();
  return { stop };
}
