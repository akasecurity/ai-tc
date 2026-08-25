import { request as httpRequest } from 'node:http';
import { request as httpsRequest, type RequestOptions } from 'node:https';

// The only module in this workspace that sends anything over a network, and the
// only one whose ESLint config permits a transport import at all.
//
// Everything here is shaped by one fact: the caller is holding a bearer
// credential and is about to hand it to a host named in a settings file.
//
//   - NO REDIRECTS. Node's client does not follow them, and this module does
//     not implement them. A 3xx is returned as the status it is, so a
//     credential can never be replayed to whatever a `Location` header names.
//     That is the property `redirect: 'error'` buys a fetch-based client, held
//     here by construction instead of by a flag.
//   - NO RETRIES. A caller that wants one owns the decision; retrying a write
//     inside the transport turns one refused request into an unbounded amount
//     of traffic from a fail-open hook.
//   - A DEADLINE ON EVERY REQUEST, covering the connect and the body. A hook
//     lives inside a host's own timeout, so a request with no ceiling is a
//     stalled session rather than a slow one.
//   - THE ERROR CARRIES A STATUS AND NOTHING THE SERVER WROTE. A response body
//     is attacker-influenced input on a path whose whole job is refusing to
//     leak; a status code is all a caller needs to tell "the credential is
//     wrong" from "the deployment is unreachable".

/** How long a single request may take, connect and body together. */
export const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * The largest response this module will read.
 *
 * A deployment is not trusted to be well-behaved just because a user attached
 * to it: without a cap, a body that never ends is an unbounded allocation in a
 * hook process. Every response this client expects is a small JSON object; the
 * policy bundle is the largest and is far inside this.
 */
export const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

/**
 * A request that reached a deployment and came back non-2xx.
 *
 * Carries the status ALONE — deliberately not the body, not the headers, not a
 * server-authored message. Callers classify on `status` (401 and 403 mean the
 * credential is wrong or unprivileged, everything else means try later), and a
 * status code cannot smuggle anything into a log or a status line.
 */
export class RemoteRequestError extends Error {
  constructor(readonly status: number) {
    super(`control-plane request failed with status ${String(status)}`);
    this.name = 'RemoteRequestError';
  }
}

/**
 * A request this client refused to SEND, because the body it was handed does
 * not satisfy the contract the route publishes.
 *
 * Kept apart from the two errors above, and that separation is the whole point
 * of the class. Those describe what a control plane did; this describes a
 * defect on this machine, before anything reached a socket. A caller that
 * counts failures toward a circuit breaker must not count this one — a
 * deterministic local shape bug would otherwise open the breaker and suppress
 * every unrelated forward, while a status surface reported an outage that never
 * happened.
 */
export class RemoteRequestInvalid extends Error {
  constructor(
    route: string,
    override readonly cause: unknown,
  ) {
    super(`refusing to send a malformed body to ${route}`);
    this.name = 'RemoteRequestInvalid';
  }
}

/**
 * An answered request whose 2xx BODY is not what the route publishes.
 *
 * Its own class for the same reason `RemoteRequestInvalid` is: a caller has to
 * tell "the deployment is running a version this build cannot read" from "the
 * deployment could not be reached", and those point a user at completely
 * different things. Recovering that from an error's WORDING joins the two
 * packages by nothing but a string — the defect ./failure.ts's `statusOf`
 * comment describes for the status path, reintroduced on the body path.
 */
export class RemoteResponseInvalid extends Error {
  constructor(route: string, detail: string) {
    super(`control plane answered ${route} with ${detail}`);
    this.name = 'RemoteResponseInvalid';
  }
}

/** A request that never got an answer: DNS, connect, TLS, timeout, socket. */
export class RemoteTransportError extends Error {
  constructor(reason: string) {
    super(`control-plane request did not complete: ${reason}`);
    this.name = 'RemoteTransportError';
  }
}

export interface RemoteResponse {
  status: number;
  /** Lower-cased header names, as Node reports them. */
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

export interface SendOptions {
  method: 'GET' | 'POST';
  /** Absolute URL. The caller has already checked the endpoint is one it may send to. */
  url: string;
  apiKey: string;
  /** Serialized JSON, for POST. */
  body?: string | undefined;
  /** Extra request headers, e.g. `if-none-match`. */
  headers?: Record<string, string> | undefined;
  timeoutMs?: number | undefined;
}

/**
 * Send one request and read the whole response.
 *
 * Resolves for ANY answered status, including 4xx and 5xx — mapping a status to
 * an error is the caller's job, because 304 and 404 are ordinary answers on
 * some of these routes and failures on others. Rejects only when no answer
 * arrived at all (`RemoteTransportError`).
 */
export async function send(options: SendOptions): Promise<RemoteResponse> {
  const url = new URL(options.url);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  // http is reachable here only for a loopback endpoint; `isSafeEndpoint` in
  // @akasecurity/persistence is what establishes that, and this switch trusts
  // that check rather than repeating it — repeating it here in a weaker form is
  // how the two would drift.
  const send_ = url.protocol === 'http:' ? httpRequest : httpsRequest;

  const requestOptions: RequestOptions = {
    method: options.method,
    headers: {
      // CALLER HEADERS FIRST, so this module's own are not overridable. Spread
      // last they win, and two of the values below are ones no caller may
      // replace: `x-api-key` is the credential, and `content-length` is the
      // byte count that stops a multi-byte body being truncated by the
      // receiver. `SendOptions.headers` is a free-form record on an exported
      // function, so "no caller does that today" is not the guarantee to rely
      // on. The one header any caller actually passes — `if-none-match` on the
      // conditional GET — is untouched by this order.
      ...options.headers,
      // The credential. One header, matching what the deployment authenticates
      // on; a second copy in an `Authorization` header would be one more place
      // it can be logged by an intermediary for no gain.
      'x-api-key': options.apiKey,
      accept: 'application/json',
      ...(options.body === undefined
        ? {}
        : {
            'content-type': 'application/json',
            // Byte length, not string length: a multi-byte body sent with a
            // character count is truncated by the receiver.
            'content-length': String(Buffer.byteLength(options.body)),
          }),
    },
  };

  return new Promise<RemoteResponse>((resolve, reject) => {
    // A single settle guard for every path below. Node can deliver an 'error'
    // after a timeout has already fired (the abort surfaces as one), and a
    // second settle on a promise is a silent no-op that hides which cause won.
    let settled = false;
    const fail = (reason: string): void => {
      if (settled) return;
      settled = true;
      reject(new RemoteTransportError(reason));
    };

    const req = send_(url, requestOptions, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_RESPONSE_BYTES) {
          // SETTLE FIRST, then tear down. `destroy()` emits 'aborted' on this
          // same turn, and that handler also settles — so destroying first
          // reports "the response was aborted" and loses the only reason a
          // caller could act on. The `settled` guard makes the first call win,
          // which is why the order here is the whole fix.
          fail(`response exceeded ${String(MAX_RESPONSE_BYTES)} bytes`);
          // Destroy rather than merely stop reading: leaving the socket open
          // lets the sender keep pushing at a process that has already given up.
          res.destroy();
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      res.on('aborted', () => {
        fail('the response was aborted');
      });
      res.on('end', () => {
        if (settled) return;
        settled = true;
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
    });

    // Covers the connect AND the body: `setTimeout` on the request measures
    // socket inactivity, so a deployment that answers a byte at a time would
    // never trip it. This is a wall-clock ceiling on the whole exchange.
    const deadline = setTimeout(() => {
      // Settle before tearing down, for the reason the size cap gives above:
      // `destroy()` can surface as an 'error' that would otherwise settle first
      // with a socket message in place of the deadline that actually fired.
      fail(`no response within ${String(timeoutMs)}ms`);
      req.destroy();
    }, timeoutMs);
    // Do not hold the event loop open on account of the deadline — a hook
    // process that has finished its work should exit rather than wait out a
    // timer whose only job is to bound a request already being awaited.
    deadline.unref();

    // A response that is not a RESPONSE. Node routes a 101 to 'upgrade', so the
    // response callback above never runs — and an upgrade is not something this
    // client asked for or could read. Refused explicitly, and the detached
    // socket destroyed, because nothing else owns it once it has left the
    // request.
    //
    // There is deliberately no 'connect' sibling. Node dispatches that event
    // only when the REQUEST method was CONNECT, and the six routes are GET and
    // POST — so a handler for it could never run, and an unreachable line reads
    // as a covered case while proving nothing. The 'close' backstop below is
    // the general answer, and it covers that shape too.
    req.on('upgrade', (_res, socket: { destroy: () => void }) => {
      fail('the deployment answered with a protocol upgrade');
      socket.destroy();
    });

    req.on('close', () => {
      // SETTLE FIRST, THEN clear. Clearing unconditionally is what made the
      // upgrade case hang forever rather than merely fail: the deadline was the
      // last thing that would have rejected this promise, and 'close' removed
      // it. A request that closed without settling has failed by definition.
      //
      // Read this as a BACKSTOP, not as a proven path. The suite does not
      // exercise it on its own — every close it reaches has already settled via
      // the response callback, the 'error' handler or the upgrade refusal, so
      // this `fail` is a no-op in all of them and removing it reds nothing.
      // It is kept because the alternative is not "one uncovered line" but the
      // original defect: with the clear unconditional, ANY path that reaches
      // neither the response callback nor an 'error' takes the deadline away
      // and hangs for ever. Converting that class into a rejection costs a line
      // and needs no advance knowledge of which path it was.
      fail('the connection closed before a response was read');
      clearTimeout(deadline);
    });
    req.on('error', (err: Error) => {
      fail(err.message);
    });

    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}
