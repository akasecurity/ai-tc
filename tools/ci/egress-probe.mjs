#!/usr/bin/env node
/**
 * The TCP half of the positive control for `tools/ci/no-network-test.sh`.
 *
 * WHY THIS IS NOT A `/dev/tcp` ONE-LINER. The obvious probe is bash's
 * `exec 3<>/dev/tcp/1.1.1.1/443`, and a failure there is read as "routing is
 * gone". But `/dev/tcp` is a bash COMPILE-TIME feature (`--enable-net-redirections`),
 * absent from some distribution and container builds and from every non-bash
 * shell. Where it is absent the redirection fails for a reason that has nothing
 * to do with the network, the caller concludes egress is blocked, and the suite
 * runs having proved nothing — the precise shape of vacuous pass the caller's
 * tool-presence check exists to prevent, reintroduced by the probe itself.
 *
 * So the probe proves its own mechanism before trusting it: it binds a listener
 * on loopback and connects to it. That round trip has to succeed, or the probe
 * reports itself broken rather than reporting the network blocked. It also
 * subsumes the loopback check the caller used to make by grepping `ip addr` —
 * an actual bind-and-connect is the property the suite depends on, where a
 * matching line of `ip` output was only a proxy for it.
 *
 * WHY THIS IMPORTS node:net. The specifier is on the workspace lint ban list.
 * Opening a socket is this file's entire purpose — it is the enforcement, not a
 * violation of it, the same opt-out `test/setup/no-network.ts` takes. It is
 * measured rather than assumed: `packages/eslint-config/test/no-network-runtime.test.js`
 * lints this file with the shared network guard and fails if it ever trips a
 * SECOND ban. This file ships nowhere — it is CI tooling, reachable from no
 * package's `files` array.
 *
 *   node tools/ci/egress-probe.mjs [host] [port]
 *
 * Exit codes are the interface; the caller branches on them:
 *   0 — the target is unreachable. Egress is blocked, which is the good case.
 *   1 — the target ANSWERED. Egress is not blocked.
 *   3 — the probe could not run: loopback is down, or the arguments are junk.
 *       Never conflate this with 0; an unreachable network and a broken probe
 *       look identical from the outside, which is the whole problem.
 */
import { createServer, Socket } from 'node:net';

/** Long enough for a real answer on a slow runner, short enough to fail a job fast. */
const CONNECT_TIMEOUT_MS = 10_000;

const EXIT_BLOCKED = 0;
const EXIT_REACHABLE = 1;
const EXIT_PROBE_BROKEN = 3;

const DEFAULT_HOST = '1.1.1.1';
const DEFAULT_PORT = 443;

/** @param {string} line */
function report(line) {
  process.stderr.write(`${line}\n`);
}

/**
 * One TCP connection attempt. Never rejects: an unreachable target is the
 * expected outcome here, not an error.
 * @param {string} host
 * @param {number} port
 * @returns {Promise<{ connected: boolean; detail: string }>}
 */
function tryConnect(host, port) {
  return new Promise((resolve) => {
    const socket = new Socket();
    /** @param {{ connected: boolean; detail: string }} outcome */
    const finish = (outcome) => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(outcome);
    };
    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.once('connect', () => {
      finish({ connected: true, detail: 'connected' });
    });
    socket.once('timeout', () => {
      finish({ connected: false, detail: `no answer within ${String(CONNECT_TIMEOUT_MS)} ms` });
    });
    socket.once('error', (error) => {
      const code = /** @type {NodeJS.ErrnoException} */ (error).code;
      finish({ connected: false, detail: code ?? error.message });
    });
    socket.connect(port, host);
  });
}

/**
 * The mechanism check: bind a listener on loopback and connect to it. Proves
 * both that this probe can open a socket at all and that loopback is up, which
 * the suite under the block genuinely depends on (the CLI's port probe, the
 * dashboard boot test).
 * @returns {Promise<{ ok: boolean; detail: string }>}
 */
function loopbackRoundTrip() {
  return new Promise((resolve) => {
    const server = createServer((connection) => {
      connection.destroy();
    });
    server.once('error', (error) => {
      resolve({ ok: false, detail: `could not listen on 127.0.0.1: ${error.message}` });
    });
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') {
        server.close(() => {
          resolve({ ok: false, detail: 'the loopback listener reported no port' });
        });
        return;
      }
      void tryConnect('127.0.0.1', address.port).then((outcome) => {
        server.close(() => {
          resolve(
            outcome.connected
              ? { ok: true, detail: `loopback round trip on port ${String(address.port)}` }
              : { ok: false, detail: `could not connect to my own listener: ${outcome.detail}` },
          );
        });
      });
    });
  });
}

const [rawHost, rawPort] = process.argv.slice(2);
const host = rawHost ?? DEFAULT_HOST;
const port = rawPort === undefined ? DEFAULT_PORT : Number(rawPort);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  report(`egress-probe: not a port: ${String(rawPort)}`);
  process.exit(EXIT_PROBE_BROKEN);
}

const control = await loopbackRoundTrip();
if (!control.ok) {
  report(`egress-probe: the probe itself does not work — ${control.detail}.`);
  report('egress-probe: reporting BROKEN rather than "blocked", which would be a');
  report('egress-probe: vacuous pass: a probe that cannot connect to anything');
  report('egress-probe: cannot tell you the network is gone.');
  process.exit(EXIT_PROBE_BROKEN);
}

const remote = await tryConnect(host, port);
if (remote.connected) {
  report(`egress-probe: ${host}:${String(port)} ANSWERED — egress is not blocked.`);
  process.exit(EXIT_REACHABLE);
}

report(`egress-probe: ${control.detail} works; ${host}:${String(port)} is unreachable`);
report(`egress-probe: (${remote.detail}). Egress is blocked.`);
process.exit(EXIT_BLOCKED);
