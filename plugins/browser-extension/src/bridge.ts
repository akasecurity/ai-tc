/**
 * The isolated-world half of the network capture.
 *
 * The MAIN-world tap forwards raw request and response bytes for a build-time
 * list of endpoints; this file parses them with the site's adapter and relays
 * one exchange per assistant turn through background.ts to the native host.
 *
 * Three properties shape the whole file:
 *
 * 1. It sends the tap NOTHING. The port is write-only from the tap's side — it
 *    installs no `onmessage` and never calls `start()` — so a message posted at
 *    it is queued and never read. The handshake travels over the window event
 *    target the page can also read, so a bridge that wrote back would be a hook
 *    the page could drive into deciding what AKA records about it.
 * 2. A fault costs ONE exchange. This runs in the isolated world, so a throw
 *    here cannot reach page script — but an unhandled one would still take the
 *    relay down for the life of the tab, which is every later turn lost in
 *    silence. Everything the adapter touches is wrapped, and what is lost is
 *    counted.
 * 3. Installation is not visibility. A tap that patched cleanly and sees
 *    nothing reads exactly like a tab nobody used, so the counters here are the
 *    only thing that can tell a working capture from a site whose contract
 *    moved underneath it.
 */
import type { WebCaptureStatus, WebExchange } from '@akasecurity/schema';

import type { BackgroundRequest, BackgroundResponse } from './messaging.ts';
import { resolveAdapter } from './providers/registry.ts';
import type {
  EndpointKind,
  ExchangeAssembler,
  ProviderAdapter,
  WebExchangeSummary,
} from './providers/types.ts';
import type { SharedScope } from './tab-session.ts';
import { resolveSessionId, setDomSendListener } from './tab-session.ts';
import type { TapToPage } from './tap-protocol.ts';
import { TAP_CHANNEL } from './tap-protocol.ts';

// How long a DOM-observed send has to be answered by a conversation request on
// the network before it counts against the tab.
export const BLIND_WINDOW_MS = 5_000;
// How many unanswered sends make a tab blind. More than one because a single
// miss is ordinary — a retry, a draft discarded, a send the site itself
// dropped — while a run of them is the tap seeing nothing at all.
export const BLIND_STRIKES = 3;

// Monotone counters are bucketed at this value in the report SIGNATURE (never
// in the reported status itself) so a busy tab reports on transitions instead
// of once per message. Any consumer threshold read over a counter this bounds
// must sit at or below it, or a status that crossed it is not reported until
// the tab closes — test/bridge-constants.test.ts pins that against
// @akasecurity/detections' DRIFT_MIN_PARSE_FAILURES.
export const STATUS_COUNTER_CAP = 3;

// The most response text one exchange carries to the host.
//
// A COPY of RESPONSE_TEXT_MAX_BYTES in @akasecurity/schema, which this bundle
// cannot import: the content-script bundle takes nothing but the Node-free
// slice of the plugin SDK, and pulling schema in would put its whole validation
// dependency into the page's tab. test/bridge-constants.test.ts pins the two
// numbers together from the Node side, where both are readable.
//
// It is NOT the tap's own ceiling and neither subsumes the other: the tap
// bounds the RAW bytes it pulls from one response, this bounds the TEXT an
// adapter recovered from them. A long stream can yield short text and a short
// one long text, so `truncated` on the relayed exchange says only that the text
// is short of the reply — never which of the two ceilings cut it.
export const RESPONSE_TEXT_MAX_BYTES = 2 * 1024 * 1024;

// The most request body this side will hand an adapter. The tap puts no ceiling
// on a forwarded request body and no truncation signal in it — it reads a clone
// of what the site itself chose to send — so refusing an oversized one belongs
// here, where it can be refused whole rather than parsed half.
export const REQUEST_BODY_MAX_BYTES = 1024 * 1024;

// Exchanges the tap opened and never terminated. Every `request` gets exactly
// one `end`, so this is slack rather than a budget; it exists so a tap that
// stops mid-conversation costs a bounded amount of memory instead of growing
// for the life of the tab.
const MAX_IN_FLIGHT = 64;

export interface BridgeOptions {
  adapter: ProviderAdapter;
  sessionId: string;
  // Fire-and-forget: nothing the network path does may make the page wait.
  relay: (request: BackgroundRequest) => void;
  // Injected so the blind window is a property of the test rather than a race
  // against the runner.
  now: () => number;
}

export interface Bridge {
  onTapMessage(message: TapToPage): void;
  status(): WebCaptureStatus;
  noteDomSend(): void;
  /** Relay the current status now, whatever the signature says. */
  reportStatus(): void;
}

/** Whether `text` is longer than `max` bytes, without encoding when it need not. */
function exceedsBytes(text: string, max: number): boolean {
  // A UTF-8 encoding is never shorter than the UTF-16 code-unit count, so a
  // string longer than the ceiling is over it whatever it holds.
  if (text.length > max) return true;
  return new TextEncoder().encode(text).byteLength > max;
}

/**
 * Cut `text` to at most `maxBytes` UTF-8 bytes, on a character boundary.
 *
 * Exported for its own test. The ceiling is stated in BYTES and a JS string is
 * counted in UTF-16 code units, so a length-based cut keeps up to three times
 * the ceiling on non-Latin text — and cutting mid-character stores a
 * replacement character in place of the user's own.
 */
export function cutToBytes(text: string, maxBytes: number): { text: string; truncated: boolean } {
  const bytes = new TextEncoder().encode(text);
  if (bytes.byteLength <= maxBytes) return { text, truncated: false };
  let end = maxBytes;
  // Walk back off any continuation byte so the partial character is dropped
  // whole.
  while (end > 0 && ((bytes[end] ?? 0) & 0xc0) === 0x80) end -= 1;
  return { text: new TextDecoder().decode(bytes.subarray(0, end)), truncated: true };
}

/** Resolve a dotted field path against an object, `undefined` for any miss. */
export function resolveField(root: unknown, path: string): unknown {
  let value: unknown = root;
  for (const segment of path.split('.')) {
    if (typeof value !== 'object' || value === null) return undefined;
    value = (value as Record<string, unknown>)[segment];
  }
  return value;
}

export interface CompiledEndpoint {
  readonly host: string;
  readonly path: RegExp;
  readonly kind: EndpointKind;
}

// The same rule the tap compiles: the host is matched EXACTLY and the path
// pattern is anchored at the start of the path, so a pattern written for one
// site cannot reach another origin's URL that merely contains its text. Built
// from the same declarations, so the two sides agree about what a forwarded URL
// is.
export function compileEndpoints(adapter: ProviderAdapter): CompiledEndpoint[] {
  const compiled: CompiledEndpoint[] = [];
  for (const endpoint of adapter.endpoints) {
    try {
      compiled.push({
        host: endpoint.host,
        path: new RegExp(`^(?:${endpoint.path.source})`),
        kind: endpoint.kind,
      });
    } catch {
      // A pattern that will not compile classifies nothing, rather than taking
      // the rest of the table with it.
    }
  }
  return compiled;
}

/**
 * Classify a forwarded URL against a compiled endpoint table: exact host
 * match, path anchored at its start. `null` when the URL does not parse or no
 * endpoint claims it.
 */
export function classifyCompiled(
  compiled: readonly CompiledEndpoint[],
  url: string,
): EndpointKind | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // A URL whose host cannot be read is one no endpoint can claim.
    return null;
  }
  for (const endpoint of compiled) {
    if (parsed.host !== endpoint.host) continue;
    // The query rides along so a pattern MAY key on one; the anchor is what
    // stops a query reaching a pattern written against a path.
    if (endpoint.path.test(`${parsed.pathname}${parsed.search}`)) return endpoint.kind;
  }
  return null;
}

interface InFlight {
  startedAt: number;
  assembler: ExchangeAssembler | null;
  // Explicitly `| undefined` rather than optional: an adapter that recovered
  // neither is the ordinary case, and a missing key would read as a field
  // nobody set rather than one nothing was found for.
  model: string | undefined;
  conversationId: string | undefined;
  // The tap stopped pulling at its own ceiling: a finished exchange whose text
  // is short of the reply.
  truncatedOnWire: boolean;
  // Already lost — the page's call failed, the tap faulted, or the assembler
  // threw. Whatever counting it deserved has been done.
  broken: boolean;
}

export function createBridge(options: BridgeOptions): Bridge {
  const { adapter, sessionId, relay, now } = options;
  const endpoints = compileEndpoints(adapter);
  // Counted off the COMPILED list, not the declared one: an endpoint whose
  // pattern failed to compile (see compileEndpoints' own catch) classifies
  // nothing, so it must be reported as not declared rather than as
  // declared-and-silent. Conversation-kind only — an account endpoint cannot
  // observe a turn, so counting it would put a site into the drift-eligible
  // states while nothing could ever answer a DOM send.
  const conversationEndpoints = endpoints.filter((e) => e.kind === 'conversation').length;
  const inFlight = new Map<number, InFlight>();
  // DOM sends still waiting for a network turn to answer them, oldest first.
  const pendingSends: number[] = [];
  const shapeMisses = new Set<string>();

  let patchedFetch = false;
  let patchedXhr = false;
  let live = false;
  let sendsSeenDom = 0;
  let exchangesSeenNet = 0;
  let parseFailures = 0;
  let unparsedBodies = 0;
  let blindStrikes = 0;
  // The signature of the last status actually relayed — null until the first
  // report goes out, which is deliberately suppressed until the tap says it
  // patched (see maybeReport).
  let reported: string | null = null;

  function classify(url: string): EndpointKind | null {
    return classifyCompiled(endpoints, url);
  }

  // Retire every DOM send whose window has closed with nothing to answer it.
  // Lazy rather than timed: the counters are read on demand, and a timer in a
  // content script is one more thing to leak on navigation.
  function sweepBlind(): void {
    const cutoff = now() - BLIND_WINDOW_MS;
    while (pendingSends.length > 0 && (pendingSends[0] ?? 0) <= cutoff) {
      pendingSends.shift();
      blindStrikes += 1;
    }
  }

  function openExchange(message: Extract<TapToPage, { type: 'request' }>): void {
    // Classified here rather than trusted: the tap decides what to FORWARD, the
    // adapter's own declarations decide what a forwarded URL means. Anything
    // else — an account endpoint, or a URL this adapter does not claim — opens
    // no exchange and touches no counter.
    if (classify(message.url) !== 'conversation') return;

    sweepBlind();
    // This turn answers the oldest DOM send still inside its window.
    pendingSends.shift();
    exchangesSeenNet += 1;

    let model: string | undefined;
    let conversationId: string | undefined;
    if (message.body !== null) {
      if (exceedsBytes(message.body, REQUEST_BODY_MAX_BYTES)) {
        unparsedBodies += 1;
      } else {
        try {
          const parsed = adapter.parseRequest(message.body);
          model = parsed.model;
          conversationId = parsed.conversationId;
          if (!parsed.requiredPathsSeen) {
            // The adapter's own verdict on its request contract. It reports one
            // boolean rather than which key went missing, so every path it
            // depends on is recorded — coarse, and still the earliest signal
            // that the outbound shape moved.
            for (const path of adapter.requiredPaths.request) shapeMisses.add(path);
          }
        } catch {
          parseFailures += 1;
        }
      }
    }

    let assembler: ExchangeAssembler | null = null;
    try {
      assembler = adapter.parseStream();
    } catch {
      parseFailures += 1;
    }

    inFlight.set(message.id, {
      startedAt: now(),
      assembler,
      model,
      conversationId,
      truncatedOnWire: false,
      broken: false,
    });
    if (inFlight.size > MAX_IN_FLIGHT) {
      const oldest = inFlight.keys().next().value;
      if (oldest !== undefined) inFlight.delete(oldest);
    }
  }

  function pushChunk(message: Extract<TapToPage, { type: 'chunk' }>): void {
    const entry = inFlight.get(message.id);
    if (entry === undefined || entry.broken || entry.assembler === null) return;
    try {
      entry.assembler.push(message.text);
    } catch {
      // Counted once and the exchange dropped: an assembler that throws on one
      // chunk throws on the next thousand, and a per-chunk count would report a
      // single stale adapter as a thousand independent failures.
      parseFailures += 1;
      entry.broken = true;
    }
  }

  function closeExchange(message: Extract<TapToPage, { type: 'end' }>): void {
    const entry = inFlight.get(message.id);
    if (entry === undefined) return;
    inFlight.delete(message.id);
    // Already counted where it broke.
    if (entry.broken || entry.assembler === null) return;
    // A 4xx/5xx body is the site's own error rather than evidence the adapter
    // has gone stale, so it is dropped without touching the drift counters.
    if (!message.ok) return;

    let summary: WebExchangeSummary | null;
    try {
      summary = entry.assembler.end();
    } catch {
      parseFailures += 1;
      return;
    }
    // A summary with no usable message id cannot be keyed: the stored row's id
    // hashes on it, and a blank one collapses every turn of a conversation onto
    // a single row.
    if (summary === null || summary.messageId.trim() === '') {
      parseFailures += 1;
      return;
    }

    for (const path of adapter.requiredPaths.response) {
      if (resolveField(summary, path) === undefined) shapeMisses.add(path);
    }

    const cut =
      summary.responseText === undefined
        ? null
        : cutToBytes(summary.responseText, RESPONSE_TEXT_MAX_BYTES);
    const exchange: WebExchange = {
      ...summary,
      startedAt: summary.startedAt ?? new Date(entry.startedAt).toISOString(),
      ...(summary.model === undefined && entry.model !== undefined ? { model: entry.model } : {}),
      ...(summary.conversationId === undefined && entry.conversationId !== undefined
        ? { conversationId: entry.conversationId }
        : {}),
      ...(cut === null ? {} : { responseText: cut.text }),
      truncated: entry.truncatedOnWire || (cut?.truncated ?? false),
    };

    live = true;
    try {
      relay({ type: 'exchange', sessionId, tool: adapter.id, exchange });
    } catch {
      // An unreachable relay loses this exchange; the next one still tries.
    }
  }

  function noteError(message: Extract<TapToPage, { type: 'error' }>): void {
    const entry = inFlight.get(message.id);
    switch (message.reason) {
      case 'unparsed_body':
        // Opens no exchange and closes none — the tap says only that it
        // declined to read a body, and the request went out untouched.
        unparsedBodies += 1;
        return;
      case 'truncated':
        if (entry !== undefined) entry.truncatedOnWire = true;
        return;
      case 'aborted':
        // The page's own call failed. Nothing about the adapter is wrong, so
        // the exchange is dropped without counting drift.
        if (entry !== undefined) entry.broken = true;
        return;
      case 'tap_error':
        if (entry !== undefined) entry.broken = true;
        // Counted with the parse failures: this is a lost exchange, and the
        // status vocabulary carries one counter for that.
        parseFailures += 1;
        return;
    }
  }

  function dispatch(message: TapToPage): void {
    switch (message.type) {
      case 'ready':
        // Installation is reported by `patched`, which follows immediately and
        // says which transports are real.
        return;
      case 'patched':
        patchedFetch = message.fetch;
        patchedXhr = message.xhr;
        return;
      case 'request':
        openExchange(message);
        return;
      case 'chunk':
        pushChunk(message);
        return;
      case 'end':
        closeExchange(message);
        return;
      case 'error':
        noteError(message);
        return;
    }
  }

  function currentStatus(): WebCaptureStatus {
    sweepBlind();
    return {
      // A tap that installed with neither transport captured sees nothing,
      // which is a blind spot rather than a patch.
      patched: patchedFetch || patchedXhr,
      live,
      blind: blindStrikes >= BLIND_STRIKES,
      sendsSeenDom,
      exchangesSeenNet,
      parseFailures,
      unparsedBodies,
      shapeMisses: [...shapeMisses],
      conversationEndpoints,
    };
  }

  // A signature of `status()`, bucketing every monotone counter at
  // STATUS_COUNTER_CAP — so a busy tab reports on a TRANSITION (patched, live,
  // blind, a new shape miss, crossing the cap) rather than once per message,
  // while the reported status itself always carries the real counts.
  function reportSignature(s: WebCaptureStatus): string {
    return [
      s.patched,
      s.live,
      s.blind,
      s.conversationEndpoints,
      s.shapeMisses.length,
      Math.min(s.parseFailures, STATUS_COUNTER_CAP),
      Math.min(s.unparsedBodies, STATUS_COUNTER_CAP),
    ].join('|');
  }

  function maybeReport(): void {
    const status = currentStatus();
    // Suppressed until the tap has posted `patched`: reporting before then
    // writes a transient "unpatched" row into every tab on every load, which
    // is worse than the one honest limit this leaves (see bridge.ts's module
    // doc and the status-surface design).
    if (!patchedFetch && !patchedXhr && reported === null) return;
    const signature = reportSignature(status);
    if (signature === reported) return;
    reported = signature;
    try {
      relay({ type: 'capture_status', sessionId, tool: adapter.id, status });
    } catch {
      // An unreachable relay loses this report; the next transition retries.
    }
  }

  return {
    onTapMessage(message: TapToPage): void {
      try {
        dispatch(message);
      } catch {
        // The backstop under the per-step handling above. A fault that reached
        // here costs the exchange the message named and nothing else.
        parseFailures += 1;
        if ('id' in message) inFlight.delete(message.id);
      }
      sweepBlind();
      maybeReport();
    },

    status(): WebCaptureStatus {
      return currentStatus();
    },

    noteDomSend(): void {
      sweepBlind();
      sendsSeenDom += 1;
      pendingSends.push(now());
      maybeReport();
    },

    reportStatus(): void {
      const status = currentStatus();
      reported = reportSignature(status);
      try {
        relay({ type: 'capture_status', sessionId, tool: adapter.id, status });
      } catch {
        // Nothing left to report to on a page that is already unloading.
      }
    },
  };
}

/**
 * Take the tap's transferred port off its handshake and read from it.
 *
 * The handshake arrives on the window event target, which page script shares —
 * so nothing in it proves the tap sent it. What bounds that is registering at
 * `document_start`, before any page script has run, taking the FIRST handshake
 * and ignoring every later one; a forgery can then only arrive second.
 */
export function attachTap(win: Window, deliver: (message: TapToPage) => void): void {
  let attached = false;

  const onHandshake = (event: MessageEvent): void => {
    try {
      if (attached) return;
      // Another window's message is not this page's tap.
      if (event.source !== win) return;
      const data: unknown = event.data;
      if (typeof data !== 'object' || data === null) return;
      if ((data as { tag?: unknown }).tag !== TAP_CHANNEL) return;
      const port = event.ports[0];
      if (port === undefined) return;

      attached = true;
      win.removeEventListener('message', onHandshake);
      port.addEventListener('message', (portEvent: MessageEvent) => {
        try {
          deliver(portEvent.data as TapToPage);
        } catch {
          // One message, never the port.
        }
      });
      // The tap never calls this. A MessagePort queues until it is started, so
      // without it every forwarded exchange is held and none is ever read.
      port.start();
    } catch {
      // A malformed handshake leaves the listener in place for a real one.
    }
  };

  win.addEventListener('message', onHandshake);
}

function relayToBackground(request: BackgroundRequest): void {
  try {
    void chrome.runtime
      .sendMessage<BackgroundRequest, BackgroundResponse>(request)
      .catch(() => undefined);
  } catch {
    // The extension context is invalidated on reload or update; the page and
    // its own traffic carry on regardless.
  }
}

export interface InstallOptions {
  // The same object in production for both roles: content scripts share one
  // isolated-world global, which is both the window they listen on and the
  // scope they meet each other through. Named twice because a test that passed
  // two objects would be proving a wiring nothing ships.
  win: Window & SharedScope;
  hostname: string;
  relay: (request: BackgroundRequest) => void;
  now: () => number;
}

/**
 * Build the bridge for a page and connect both of its inputs.
 *
 * Exported so the wiring itself is testable rather than only its two ends.
 * Each end works in isolation whichever way this is misconnected — the DOM
 * path goes on reporting sends into a listener nobody registered, and the
 * bridge goes on counting exchanges — and the tab then reports a healthy patch
 * for the life of the session while the one signal that could contradict it
 * never arrives.
 *
 * Returns the bridge, or `null` for a page no adapter claims.
 */
export function installBridge(options: InstallOptions): Bridge | null {
  const { win, hostname, relay, now } = options;
  const adapter = resolveAdapter(hostname);
  if (!adapter) return null;
  const bridge = createBridge({
    adapter,
    sessionId: resolveSessionId(win),
    relay,
    now,
  });
  setDomSendListener(win, () => {
    bridge.noteDomSend();
  });
  attachTap(win, (message) => {
    bridge.onTapMessage(message);
  });
  // The tab's final word on its own capture status. `pagehide` rather than a
  // timer: a timer in a content script is one more thing to leak on
  // navigation (see sweepBlind's own comment), and this reporter adds none.
  win.addEventListener('pagehide', () => {
    bridge.reportStatus();
  });
  return bridge;
}

// Registered at document_start so the listener is in place before the tap
// posts. Nothing here waits on the page: an adapter that does not claim this
// hostname simply does nothing at all.
function bootstrap(): void {
  try {
    if (typeof window === 'undefined') return;
    installBridge({
      win: window,
      hostname: location.hostname,
      relay: relayToBackground,
      now: () => Date.now(),
    });
  } catch {
    // A page the bridge cannot attach to is a page it does nothing on.
  }
}

bootstrap();
