import { describe, expect, it, vi } from 'vitest';

import {
  attachTap,
  BLIND_STRIKES,
  BLIND_WINDOW_MS,
  classifyCompiled,
  compileEndpoints,
  createBridge,
  cutToBytes,
  installBridge,
  matchCompiled,
  REQUEST_BODY_MAX_BYTES,
  RESPONSE_TEXT_MAX_BYTES,
  STATUS_COUNTER_CAP,
} from '../src/bridge.ts';
import type { BackgroundRequest } from '../src/messaging.ts';
import type {
  ExchangeAssembler,
  MatchedExchange,
  ParsedRequest,
  ProviderAdapter,
  WebExchangeSummary,
} from '../src/providers/types.ts';
import type { EnforcementState, SharedScope } from '../src/tab-session.ts';
import { notifyDomSend, resolveSessionId } from '../src/tab-session.ts';
import type { TapToPage } from '../src/tap-protocol.ts';
import { TAP_CHANNEL } from '../src/tap-protocol.ts';
import { loadFixture, STREAM_FIXTURE } from './helpers/fixture-bar.ts';

// The isolated-world half. It is the only thing between the page's own bytes
// and what AKA persists, so every case here asserts one of three things: what
// reaches the relay, what the drift counters say, or that a fault cost exactly
// one exchange.

const CONVERSATION_URL = 'https://site.test/api/conversation';

// A summary shaped like the one a real adapter recovers, with the two fields
// the bridge owns left off.
function summaryOf(overrides: Partial<WebExchangeSummary> = {}): WebExchangeSummary {
  return {
    messageId: 'msg_1',
    usageSource: 'site',
    usage: { inputTokens: 11, outputTokens: 22 },
    model: 'model-x',
    toolCalls: [],
    responseText: 'the assistant said this',
    ...overrides,
  };
}

interface FakeAdapterOptions {
  // What parseStream was handed for this exchange, so a case can assert the
  // bridge passes the MATCHED endpoint rather than merely some endpoint.
  onExchange?: (exchange: MatchedExchange) => void;
  // The same, for the request half — it is reached on a different subset of
  // turns, so one option cannot stand in for the other.
  onRequestExchange?: (exchange: MatchedExchange) => void;
  summary?: WebExchangeSummary | null;
  onEnd?: () => void;
  onPush?: (chunk: string) => void;
  parseRequest?: (body: string, exchange: MatchedExchange) => ParsedRequest;
  requiredPaths?: { request: readonly string[]; response: readonly string[] };
}

function fakeAdapter(options: FakeAdapterOptions = {}): ProviderAdapter {
  return {
    id: 'claude-ai',
    hostnames: ['site.test'],
    findComposer: () => null,
    findSendButton: () => null,
    extractText: () => '',
    setText: () => undefined,
    watchSubmit: () => () => undefined,
    submit: () => false,
    endpoints: [
      { host: 'site.test', path: /\/api\/conversation/, kind: 'conversation' },
      { host: 'site.test', path: /\/api\/account/, kind: 'account' },
    ],
    requiredPaths: options.requiredPaths ?? { request: [], response: [] },
    protocolTokens: [],
    parseRequest: (body, exchange) => {
      options.onRequestExchange?.(exchange);
      return options.parseRequest?.(body, exchange) ?? { requiredPathsSeen: true };
    },
    parseStream: (exchange): ExchangeAssembler => ({
      push: (chunk) => {
        options.onExchange?.(exchange);
        options.onPush?.(chunk);
      },
      end: () => {
        options.onEnd?.();
        return options.summary === undefined ? summaryOf() : options.summary;
      },
    }),
  };
}

// A clock the test drives. `now()` in the bridge is injected for exactly this:
// the blind detector is defined over a window, and a wall clock makes that case
// a race against the runner.
function fakeClock(start = 1_700_000_000_000) {
  let value = start;
  return {
    now: () => value,
    advance: (ms: number) => {
      value += ms;
    },
  };
}

function harness(adapter: ProviderAdapter = fakeAdapter()) {
  const relayed: BackgroundRequest[] = [];
  const clock = fakeClock();
  // Injected the way `now` is: the DOM half publishes this into a shared global
  // the bridge cannot reach from a test, and reading the real one would make
  // every case here depend on content.ts having run.
  let enforcement: EnforcementState = 'watching';
  const bridge = createBridge({
    adapter,
    sessionId: 'sess_1',
    relay: (request) => {
      relayed.push(request);
      return Promise.resolve(true);
    },
    now: clock.now,
    readEnforcement: () => enforcement,
  });
  const exchanges = (): Extract<BackgroundRequest, { type: 'exchange' }>[] =>
    relayed.filter(
      (r): r is Extract<BackgroundRequest, { type: 'exchange' }> => r.type === 'exchange',
    );
  const feed = (...messages: TapToPage[]): void => {
    for (const message of messages) bridge.onTapMessage(message);
  };
  return {
    bridge,
    relayed,
    exchanges,
    feed,
    clock,
    setEnforcement: (next: EnforcementState) => {
      enforcement = next;
    },
  };
}

const request = (id = 1, url = CONVERSATION_URL): TapToPage => ({
  type: 'request',
  id,
  url,
  method: 'POST',
  body: '{"prompt":"hi"}',
});

describe('createBridge, one exchange end to end', () => {
  it('relays exactly one exchange carrying the adapter-s summary', () => {
    const h = harness();
    h.feed(request(), { type: 'chunk', id: 1, text: 'a' }, { type: 'chunk', id: 1, text: 'b' });
    h.feed({ type: 'end', id: 1, status: 200, ok: true });

    expect(h.exchanges()).toHaveLength(1);
    const relayed = h.exchanges()[0];
    expect(relayed?.sessionId).toBe('sess_1');
    expect(relayed?.tool).toBe('claude-ai');
    expect(relayed?.exchange).toMatchObject({
      messageId: 'msg_1',
      model: 'model-x',
      usageSource: 'site',
      usage: { inputTokens: 11, outputTokens: 22 },
      responseText: 'the assistant said this',
      truncated: false,
    });
    // The exchange is the WHOLE of what this side sends. Asserting only what
    // reached `exchanges()` bounds the fields of one message and says nothing
    // about a second one of another type — and the same relay reaches the
    // native host that the DOM path's raw prompt captures travel on.
    expect(h.relayed.map((message) => message.type)).toEqual(['exchange']);
  });

  it('stamps startedAt from the request-s own arrival, not from close', () => {
    const h = harness();
    const openedAt = h.clock.now();
    h.feed(request());
    // A stream takes time; the turn started when the request did.
    h.clock.advance(4_000);
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    expect(h.exchanges()[0]?.exchange.startedAt).toBe(new Date(openedAt).toISOString());
  });

  it('prefers a time the adapter itself recovered', () => {
    // The site may report when the turn began; the bridge's own stamp is the
    // fallback for when it does not.
    const siteTime = '2026-01-02T03:04:05.000Z';
    const h = harness(fakeAdapter({ summary: summaryOf({ startedAt: siteTime }) }));
    h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    expect(h.exchanges()[0]?.exchange.startedAt).toBe(siteTime);
  });

  it('carries the request-s own model and conversation id when the stream had neither', () => {
    // The only reason the request body is parsed at all: a stream that names
    // neither leaves the turn unjoinable to the conversation it belongs to.
    const h = harness(
      fakeAdapter({
        parseRequest: () => ({
          model: 'from-request',
          conversationId: 'conv_9',
          requiredPathsSeen: true,
        }),
        summary: summaryOf({ model: undefined }),
      }),
    );
    h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    expect(h.exchanges()[0]?.exchange).toMatchObject({
      model: 'from-request',
      conversationId: 'conv_9',
    });
  });

  it('lets the stream-s own model win over the request-s', () => {
    // The positive control on the merge: the response is what the site
    // actually answered with, and a request may name a model it did not use.
    const h = harness(
      fakeAdapter({
        parseRequest: () => ({
          model: 'from-request',
          conversationId: 'conv_9',
          requiredPathsSeen: true,
        }),
        summary: summaryOf({ conversationId: 'conv_from_stream' }),
      }),
    );
    h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    expect(h.exchanges()[0]?.exchange).toMatchObject({
      model: 'model-x',
      conversationId: 'conv_from_stream',
    });
  });

  it('relays nothing an adapter recovered beyond the exchange contract', () => {
    // parseRequest recovers the outbound PROMPT, and the network path does not
    // record it — the DOM path is what captures a prompt, where the user's own
    // decision to send it is what authorised the capture. Nothing may carry it
    // out of here by riding along on the exchange.
    const prompt = 'Zx7Z-qLm93VtRhK2-pWnE4dCsJb8YfU6';
    const h = harness(
      fakeAdapter({
        parseRequest: () => ({ prompt, requiredPathsSeen: true }),
      }),
    );
    h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    // The positive control: without it the absence check below is satisfied by
    // a bridge that relayed nothing at all.
    expect(h.relayed.map((message) => message.type)).toEqual(['exchange']);
    expect(JSON.stringify(h.relayed)).not.toContain(prompt);
  });

  it('feeds every chunk to the assembler, in order', () => {
    const pushed: string[] = [];
    const h = harness(fakeAdapter({ onPush: (chunk) => pushed.push(chunk) }));
    h.feed(request(), { type: 'chunk', id: 1, text: 'a' }, { type: 'chunk', id: 1, text: 'b' });
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    expect(pushed).toEqual(['a', 'b']);
  });

  it('ignores a url no endpoint matches, and one on another host', () => {
    const h = harness();
    h.feed(request(2, 'https://site.test/api/telemetry'));
    h.feed({ type: 'end', id: 2, status: 200, ok: true });
    h.feed(request(3, 'https://other.test/api/conversation'));
    h.feed({ type: 'end', id: 3, status: 200, ok: true });
    expect(h.exchanges()).toHaveLength(0);
    expect(h.bridge.status().exchangesSeenNet).toBe(0);
  });

  it('anchors a path pattern at the start of the path, on this host too', () => {
    // The bridge compiles the adapter's own declarations a second time — the
    // tap's `request` carries no kind — so the containment has to hold on both
    // sides or they disagree about what a forwarded URL IS. Unanchored, a
    // pattern written for the conversation endpoint reaches any URL on this
    // host that merely carries its text: the account endpoint below is
    // declared on the SAME host, so an account payload whose query named the
    // conversation path would be opened, parsed and relayed as a turn.
    const h = harness();
    h.feed(request(2, 'https://site.test/redirect/api/conversation'));
    h.feed({ type: 'end', id: 2, status: 200, ok: true });
    h.feed(request(3, 'https://site.test/api/account?next=/api/conversation'));
    h.feed({ type: 'end', id: 3, status: 200, ok: true });
    h.feed(request(4, 'https://site.test/collect?next=/api/conversation'));
    h.feed({ type: 'end', id: 4, status: 200, ok: true });
    expect(h.exchanges()).toHaveLength(0);
    expect(h.bridge.status().exchangesSeenNet).toBe(0);

    // The positive control on the same matcher: the genuine path still opens.
    h.feed(request(5), { type: 'end', id: 5, status: 200, ok: true });
    expect(h.exchanges()).toHaveLength(1);
    expect(h.bridge.status().exchangesSeenNet).toBe(1);
  });

  it('records an account endpoint as neither an exchange nor a miss', () => {
    // Nothing reads account payloads yet. Classifying them is what keeps them
    // out of the conversation counters rather than landing as parse failures.
    const h = harness();
    h.feed(request(4, 'https://site.test/api/account'));
    h.feed({ type: 'end', id: 4, status: 200, ok: true });
    expect(h.exchanges()).toHaveLength(0);
    expect(h.bridge.status().parseFailures).toBe(0);
    expect(h.bridge.status().exchangesSeenNet).toBe(0);
  });

  it('sends the tap nothing', () => {
    // The port is write-only from the tap's side: it installs no onmessage and
    // never calls start(), so a message posted at it is queued and never read.
    // A bridge that posts back is a command channel the page could drive.
    const port = { addEventListener: vi.fn(), start: vi.fn(), postMessage: vi.fn() };
    const win = fakeWindow();
    attachTap(win.win, () => undefined);
    win.deliverHandshake(port);
    expect(port.postMessage).not.toHaveBeenCalled();
  });
});

describe('liveness', () => {
  it('reports live only once an exchange has actually parsed', () => {
    const h = harness();
    expect(h.bridge.status().live).toBe(false);
    h.feed(request());
    // A request seen is not a turn recovered.
    expect(h.bridge.status().live).toBe(false);
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    expect(h.bridge.status().live).toBe(true);
  });

  it('reports what the tap said it patched', () => {
    const h = harness();
    expect(h.bridge.status().patched).toBe(false);
    h.feed({ type: 'patched', fetch: false, xhr: false });
    // Installed with neither transport captured is a blind spot, not a patch.
    expect(h.bridge.status().patched).toBe(false);
    h.feed({ type: 'patched', fetch: true, xhr: false });
    expect(h.bridge.status().patched).toBe(true);
  });

  it('counts a conversation exchange the network saw even when parsing fails', () => {
    // exchangesSeenNet is the counterpart of sendsSeenDom — one turn observed
    // by that path. A site whose parser broke must not read as a network path
    // that saw nothing.
    const h = harness(fakeAdapter({ summary: null }));
    h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    expect(h.bridge.status().exchangesSeenNet).toBe(1);
    expect(h.bridge.status().parseFailures).toBe(1);
  });
});

describe('the blind detector', () => {
  it('goes blind after enough DOM sends the network never answered', () => {
    const h = harness();
    for (let strike = 0; strike < BLIND_STRIKES; strike += 1) {
      h.bridge.noteDomSend();
      h.clock.advance(BLIND_WINDOW_MS + 1);
    }
    const status = h.bridge.status();
    expect(status.sendsSeenDom).toBe(BLIND_STRIKES);
    expect(status.exchangesSeenNet).toBe(0);
    expect(status.blind).toBe(true);
  });

  it('stays sighted when each DOM send is answered on the network', () => {
    // The positive control. Without it the case above passes for a detector
    // wired to `true`.
    const h = harness();
    for (let turn = 0; turn < BLIND_STRIKES + 2; turn += 1) {
      h.bridge.noteDomSend();
      h.clock.advance(BLIND_WINDOW_MS - 1);
      h.feed(request(turn + 1), { type: 'end', id: turn + 1, status: 200, ok: true });
      h.clock.advance(BLIND_WINDOW_MS + 1);
    }
    expect(h.bridge.status().blind).toBe(false);
  });

  it('does not go blind on unanswered sends still inside the window', () => {
    const h = harness();
    for (let strike = 0; strike < BLIND_STRIKES; strike += 1) h.bridge.noteDomSend();
    h.clock.advance(BLIND_WINDOW_MS - 1);
    expect(h.bridge.status().blind).toBe(false);
  });

  it('needs the full count, not one strike', () => {
    // Pins the threshold pairwise: a detector that collapsed the count to one
    // goes red here rather than silently reporting every quiet tab blind.
    const h = harness();
    h.bridge.noteDomSend();
    h.clock.advance(BLIND_WINDOW_MS + 1);
    expect(h.bridge.status().blind).toBe(false);
  });
});

describe('faults cost one exchange, never the relay', () => {
  it('counts an assembler whose end() throws, relays nothing, and does not throw out', () => {
    const h = harness(
      fakeAdapter({
        onEnd: () => {
          throw new Error('the site changed shape');
        },
      }),
    );
    h.feed(request());
    expect(() => {
      h.feed({ type: 'end', id: 1, status: 200, ok: true });
    }).not.toThrow();
    expect(h.exchanges()).toHaveLength(0);
    expect(h.bridge.status().parseFailures).toBe(1);
  });

  it('counts a push that throws once, not once per chunk', () => {
    const h = harness(
      fakeAdapter({
        onPush: () => {
          throw new Error('bad chunk');
        },
      }),
    );
    h.feed(request(), { type: 'chunk', id: 1, text: 'a' }, { type: 'chunk', id: 1, text: 'b' });
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    expect(h.bridge.status().parseFailures).toBe(1);
    expect(h.exchanges()).toHaveLength(0);
  });

  it('counts a parseRequest that throws, and still runs the response half', () => {
    // The turn is in the response. Losing the request parse costs the
    // correlation ids it would have supplied, not the exchange.
    const h = harness(
      fakeAdapter({
        parseRequest: () => {
          throw new Error('unrecognised request body');
        },
      }),
    );
    h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    expect(h.bridge.status().parseFailures).toBe(1);
    expect(h.exchanges()).toHaveLength(1);
  });

  it('counts a parseStream that throws, and relays nothing for that exchange', () => {
    const adapter = fakeAdapter();
    const h = harness({
      ...adapter,
      parseStream: () => {
        throw new Error('cannot build an assembler');
      },
    });
    h.feed(request(), { type: 'chunk', id: 1, text: 'a' });
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    // Once, at the open — the end must not count the same loss again.
    expect(h.bridge.status().parseFailures).toBe(1);
    expect(h.exchanges()).toHaveLength(0);
  });

  it('catches a fault outside the per-step handling and costs one exchange', () => {
    // The backstop. `requiredPaths` is read while a summary is being turned
    // into an exchange, outside any inner try — an adapter that throws there
    // would otherwise take the relay down for the life of the tab.
    const adapter = fakeAdapter();
    const h = harness({
      ...adapter,
      get requiredPaths(): ProviderAdapter['requiredPaths'] {
        throw new Error('a malformed adapter');
      },
    });
    h.feed(request());
    expect(() => {
      h.feed({ type: 'end', id: 1, status: 200, ok: true });
    }).not.toThrow();
    expect(h.exchanges()).toHaveLength(0);
    expect(h.bridge.status().parseFailures).toBe(1);
  });

  it('refuses a summary whose message id is blank or only spaces', () => {
    // The stored row's id hashes on the message id, so a blank one collapses
    // every turn of a conversation onto a single row. The schema's own floor
    // is a minimum LENGTH, which a run of spaces clears — this is the only
    // thing that does not.
    for (const messageId of ['', '   ']) {
      const h = harness(fakeAdapter({ summary: summaryOf({ messageId }) }));
      h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
      expect(h.exchanges(), `messageId ${JSON.stringify(messageId)} was relayed`).toHaveLength(0);
      expect(h.bridge.status().parseFailures).toBe(1);
    }
    // The positive control: a real id on the same path still relays.
    const ok = harness();
    ok.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    expect(ok.exchanges()).toHaveLength(1);
  });

  it('ignores a url it cannot parse at all', () => {
    const h = harness();
    h.feed(request(1, 'not a url'));
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    expect(h.exchanges()).toHaveLength(0);
    expect(h.bridge.status().exchangesSeenNet).toBe(0);
  });

  it('takes nothing from a ready message', () => {
    // Installation is reported by `patched`; `ready` says only that the tap
    // reached the end of its install.
    const h = harness();
    h.feed({ type: 'ready' });
    expect(h.bridge.status()).toMatchObject({
      patched: false,
      live: false,
      exchangesSeenNet: 0,
      parseFailures: 0,
    });
  });

  it('bounds how many exchanges the tap can leave open', () => {
    // Every `request` gets exactly one `end`, so this is slack — but a tap that
    // stops mid-conversation must cost a bounded amount of memory rather than
    // growing for the life of the tab. The oldest is dropped, so the newest
    // exchange still completes.
    const h = harness();
    for (let id = 1; id <= 200; id += 1) h.feed(request(id));
    h.feed({ type: 'end', id: 200, status: 200, ok: true });
    expect(h.exchanges()).toHaveLength(1);
    // The first one was evicted long ago, so its end finds nothing and relays
    // nothing — without counting a parse failure for an exchange nobody lost.
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    expect(h.exchanges()).toHaveLength(1);
    expect(h.bridge.status().parseFailures).toBe(0);
  });

  it('survives a relay that throws', () => {
    const clock = fakeClock();
    const bridge = createBridge({
      adapter: fakeAdapter(),
      sessionId: 'sess_1',
      relay: () => {
        throw new Error('the extension context went away');
      },
      now: clock.now,
      readEnforcement: () => 'watching',
    });
    bridge.onTapMessage(request());
    expect(() => {
      bridge.onTapMessage({ type: 'end', id: 1, status: 200, ok: true });
    }).not.toThrow();
  });

  it('drops an exchange the page-s own call aborted, without calling it drift', () => {
    const h = harness();
    h.feed(request(), { type: 'error', id: 1, reason: 'aborted' });
    h.feed({ type: 'end', id: 1, status: 0, ok: false });
    expect(h.exchanges()).toHaveLength(0);
    expect(h.bridge.status().parseFailures).toBe(0);
  });

  it('drops a non-ok response without calling it drift', () => {
    // A 500 body is the site's own error, not evidence the adapter is stale.
    const h = harness();
    h.feed(request(), { type: 'end', id: 1, status: 500, ok: false });
    expect(h.exchanges()).toHaveLength(0);
    expect(h.bridge.status().parseFailures).toBe(0);
  });

  it('counts a tap fault as a lost exchange', () => {
    const h = harness();
    h.feed(request(), { type: 'error', id: 1, reason: 'tap_error' });
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    expect(h.exchanges()).toHaveLength(0);
    expect(h.bridge.status().parseFailures).toBe(1);
  });

  it('ignores a chunk and an end for an id it never opened', () => {
    const h = harness();
    expect(() => {
      h.feed({ type: 'chunk', id: 99, text: 'x' }, { type: 'end', id: 99, status: 200, ok: true });
    }).not.toThrow();
    expect(h.exchanges()).toHaveLength(0);
    expect(h.bridge.status().parseFailures).toBe(0);
  });
});

describe('shape misses', () => {
  it('records a required response path absent from the summary exactly once', () => {
    const h = harness(
      fakeAdapter({
        requiredPaths: { request: [], response: ['model', 'usage.outputTokens', 'stopReason'] },
        summary: summaryOf({ stopReason: undefined }),
      }),
    );
    h.feed(request(), { type: 'chunk', id: 1, text: 'a' }, { type: 'chunk', id: 1, text: 'b' });
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    // Once for the path that was missing, and not once per chunk: a stream of a
    // thousand events must not report a thousand misses of the same key.
    expect(h.bridge.status().shapeMisses).toEqual(['stopReason']);
  });

  it('does not repeat a miss across exchanges', () => {
    const h = harness(
      fakeAdapter({
        requiredPaths: { request: [], response: ['stopReason'] },
        summary: summaryOf({ stopReason: undefined }),
      }),
    );
    for (const id of [1, 2, 3]) {
      h.feed(request(id), { type: 'end', id, status: 200, ok: true });
    }
    expect(h.bridge.status().shapeMisses).toEqual(['stopReason']);
  });

  it('records the request paths when the adapter reports its request shape unmet', () => {
    const h = harness(
      fakeAdapter({
        requiredPaths: { request: ['messages[0].content'], response: [] },
        parseRequest: () => ({ requiredPathsSeen: false }),
      }),
    );
    h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    expect(h.bridge.status().shapeMisses).toEqual(['messages[0].content']);
  });

  it('records nothing when every required path is present', () => {
    const h = harness(
      fakeAdapter({ requiredPaths: { request: ['a'], response: ['model', 'usage.inputTokens'] } }),
    );
    h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    expect(h.bridge.status().shapeMisses).toEqual([]);
  });
});

describe('bodies the bridge will not parse', () => {
  it('counts a body the tap declined to read', () => {
    const h = harness();
    h.feed({ type: 'error', id: 7, reason: 'unparsed_body' });
    expect(h.bridge.status().unparsedBodies).toBe(1);
    // It opened no exchange, so nothing is in flight and no end follows.
    expect(h.bridge.status().exchangesSeenNet).toBe(0);
  });

  it('refuses an oversized request body rather than half-parsing it', () => {
    // The tap puts no ceiling on a forwarded request body — it reads a clone of
    // what the site itself chose to send — so bounding it is this side's job.
    const parsed: string[] = [];
    const h = harness(
      fakeAdapter({
        parseRequest: (body) => {
          parsed.push(body);
          return { requiredPathsSeen: true };
        },
      }),
    );
    h.feed({
      type: 'request',
      id: 1,
      url: CONVERSATION_URL,
      method: 'POST',
      body: 'x'.repeat(REQUEST_BODY_MAX_BYTES + 1),
    });
    expect(parsed).toEqual([]);
    expect(h.bridge.status().unparsedBodies).toBe(1);
    // The exchange still runs: the response half is where the turn is.
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    expect(h.exchanges()).toHaveLength(1);
  });

  it('measures that ceiling in BYTES, not in code units', () => {
    // The ceiling above is cleared by an ASCII body on the code-unit fast path
    // alone, so it says nothing about the measurement that has to answer for
    // every other script. '€' is three UTF-8 bytes and one code unit, so this
    // body is under the ceiling counted one way and over it counted the other
    // — a prompt in CJK or emoji is the ordinary case that reaches it.
    const body = '€'.repeat(REQUEST_BODY_MAX_BYTES / 2);
    expect(body.length).toBeLessThan(REQUEST_BODY_MAX_BYTES);
    expect(new TextEncoder().encode(body).byteLength).toBeGreaterThan(REQUEST_BODY_MAX_BYTES);

    const parsed: string[] = [];
    const h = harness(
      fakeAdapter({
        parseRequest: (received) => {
          parsed.push(received);
          return { requiredPathsSeen: true };
        },
      }),
    );
    h.feed({ type: 'request', id: 1, url: CONVERSATION_URL, method: 'POST', body });
    expect(parsed).toEqual([]);
    expect(h.bridge.status().unparsedBodies).toBe(1);
  });

  it('hands an ordinary body straight to the adapter', () => {
    // The positive control on both cases above: a bridge that refused every
    // body would satisfy them and parse nothing at all.
    const parsed: string[] = [];
    const h = harness(
      fakeAdapter({
        parseRequest: (body) => {
          parsed.push(body);
          return { requiredPathsSeen: true };
        },
      }),
    );
    h.feed(request());
    expect(parsed).toEqual(['{"prompt":"hi"}']);
    expect(h.bridge.status().unparsedBodies).toBe(0);
  });
});

describe('the response-text ceiling', () => {
  it('cuts an oversized response and says so', () => {
    const huge = 'y'.repeat(RESPONSE_TEXT_MAX_BYTES + 1000);
    const h = harness(fakeAdapter({ summary: summaryOf({ responseText: huge }) }));
    h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    const exchange = h.exchanges()[0]?.exchange;
    expect(exchange?.truncated).toBe(true);
    expect(new TextEncoder().encode(exchange?.responseText ?? '').byteLength).toBeLessThanOrEqual(
      RESPONSE_TEXT_MAX_BYTES,
    );
    // Non-vacuous: a cut that kept nothing would also satisfy the bound.
    expect((exchange?.responseText ?? '').length).toBeGreaterThan(RESPONSE_TEXT_MAX_BYTES / 2);
  });

  it('leaves a short response whole and untruncated', () => {
    // The positive control: without it the case above passes for a bridge that
    // marks every exchange truncated.
    const h = harness();
    h.feed(request(), { type: 'end', id: 1, status: 200, ok: true });
    const exchange = h.exchanges()[0]?.exchange;
    expect(exchange?.responseText).toBe('the assistant said this');
    expect(exchange?.truncated).toBe(false);
  });

  it('carries the tap-s own truncation through as a completed-but-cut exchange', () => {
    // The tap stops pulling at its own byte ceiling and says `truncated` before
    // the `end`. That is a finished exchange whose text is short of the reply,
    // not a parse failure.
    const h = harness();
    h.feed(request(), { type: 'error', id: 1, reason: 'truncated' });
    h.feed({ type: 'end', id: 1, status: 200, ok: true });
    expect(h.exchanges()).toHaveLength(1);
    expect(h.exchanges()[0]?.exchange.truncated).toBe(true);
    expect(h.bridge.status().parseFailures).toBe(0);
  });
});

describe('cutToBytes', () => {
  it('measures BYTES, not code units', () => {
    // '€' is three UTF-8 bytes and one JS code unit, so a length-based cut
    // would keep three times the ceiling.
    const text = '€'.repeat(10);
    const cut = cutToBytes(text, 9);
    expect(cut.truncated).toBe(true);
    expect(new TextEncoder().encode(cut.text).byteLength).toBe(9);
    expect(cut.text).toBe('€€€');
  });

  it('never splits a character in half', () => {
    const cut = cutToBytes('€€€', 4);
    // 4 bytes lands inside the second character; keeping it would store a
    // replacement character in place of the user's own text.
    expect(cut.text).toBe('€');
    expect(cut.truncated).toBe(true);
  });

  it('leaves text inside the ceiling untouched', () => {
    const cut = cutToBytes('short', 1024);
    expect(cut).toEqual({ text: 'short', truncated: false });
  });
});

// A window stand-in for the handshake. The real one is not usable here: jsdom
// drops transferred ports on window.postMessage, and its MessagePort delivers
// without start() — so a real-object test would assert neither of the two
// things the handshake owes.
function fakeWindow() {
  const listeners: ((event: MessageEvent) => void)[] = [];
  const pagehideListeners: (() => void)[] = [];
  const win = {
    addEventListener: (type: string, listener: (event: MessageEvent) => void) => {
      if (type === 'message') listeners.push(listener);
      else if (type === 'pagehide') pagehideListeners.push(listener as unknown as () => void);
    },
    removeEventListener: (type: string, listener: (event: MessageEvent) => void) => {
      const at = listeners.indexOf(listener);
      if (at >= 0) listeners.splice(at, 1);
    },
  };
  const dispatch = (event: Partial<MessageEvent>): void => {
    for (const listener of [...listeners]) listener(event as MessageEvent);
  };
  const deliverHandshake = (port: unknown, overrides: Partial<MessageEvent> = {}): void => {
    dispatch({
      source: win as unknown as MessageEventSource,
      data: { tag: TAP_CHANNEL },
      ports: [port] as unknown as readonly MessagePort[],
      ...overrides,
    });
  };
  const firePagehide = (): void => {
    for (const listener of [...pagehideListeners]) listener();
  };
  return { win: win as unknown as Window, dispatch, deliverHandshake, firePagehide, listeners };
}

function fakePort() {
  const handlers: ((event: MessageEvent) => void)[] = [];
  const port = {
    addEventListener: (type: string, handler: (event: MessageEvent) => void) => {
      if (type === 'message') handlers.push(handler);
    },
    start: vi.fn(),
    postMessage: vi.fn(),
  };
  const emit = (message: TapToPage): void => {
    for (const handler of [...handlers]) handler({ data: message } as MessageEvent);
  };
  return { port, emit, handlers };
}

describe('attachTap, the handshake', () => {
  it('starts the port it took — the tap never does', () => {
    // A MessagePort queues until start(); the tap installs no onmessage and
    // calls no start(), so without this the queue is never drained and every
    // forwarded exchange is held silently.
    const win = fakeWindow();
    const { port } = fakePort();
    attachTap(win.win, () => undefined);
    win.deliverHandshake(port);
    expect(port.start).toHaveBeenCalledTimes(1);
  });

  it('delivers what arrives on that port', () => {
    const seen: TapToPage[] = [];
    const win = fakeWindow();
    const { port, emit } = fakePort();
    attachTap(win.win, (message) => seen.push(message));
    win.deliverHandshake(port);
    emit({ type: 'ready' });
    expect(seen).toEqual([{ type: 'ready' }]);
  });

  it('takes the first handshake and ignores every later one', () => {
    // Page script shares this window's event target and sees the tap's
    // handshake go by, so a second one is a forgery — and taking it would swap
    // the real tap's port for one the page writes.
    const seen: TapToPage[] = [];
    const win = fakeWindow();
    const first = fakePort();
    const second = fakePort();
    attachTap(win.win, (message) => seen.push(message));
    win.deliverHandshake(first.port);
    win.deliverHandshake(second.port);
    expect(second.port.start).not.toHaveBeenCalled();
    second.emit({ type: 'ready' });
    expect(seen).toEqual([]);
    first.emit({ type: 'ready' });
    expect(seen).toEqual([{ type: 'ready' }]);
  });

  it('ignores a handshake from another window, a wrong tag, and one carrying no port', () => {
    const win = fakeWindow();
    const { port } = fakePort();
    attachTap(win.win, () => undefined);
    win.deliverHandshake(port, { source: {} as unknown as MessageEventSource });
    win.deliverHandshake(port, { data: { tag: 'not-aka' } });
    win.dispatch({
      source: win.win,
      data: { tag: TAP_CHANNEL },
      ports: [],
    });
    win.dispatch({ source: win.win, data: 'a string' });
    expect(port.start).not.toHaveBeenCalled();
    // Still listening: none of those consumed the one handshake it will take.
    win.deliverHandshake(port);
    expect(port.start).toHaveBeenCalledTimes(1);
  });

  it('stops listening once attached', () => {
    const win = fakeWindow();
    const { port } = fakePort();
    attachTap(win.win, () => undefined);
    expect(win.listeners).toHaveLength(1);
    win.deliverHandshake(port);
    expect(win.listeners).toHaveLength(0);
  });

  it('does not let a delivery fault reach the port', () => {
    const win = fakeWindow();
    const { port, emit } = fakePort();
    attachTap(win.win, () => {
      throw new Error('one bad message');
    });
    win.deliverHandshake(port);
    expect(() => {
      emit({ type: 'ready' });
    }).not.toThrow();
  });
});

describe('installBridge, the wiring itself', () => {
  // Both of the bridge's inputs are registered here, and each of them works in
  // isolation whichever way this is misconnected: the DOM path goes on
  // reporting sends into a listener nobody registered, and the bridge goes on
  // counting the exchanges it is handed. The tab then reports a healthy patch
  // for the life of the session while the one signal that could contradict it
  // never arrives — which is the failure the counters exist to make visible.
  function install(hostname = 'claude.ai') {
    const win = fakeWindow();
    // One object for both roles, as in production: the two content scripts
    // share the isolated world's global, which is both the window they listen
    // on and the scope they meet each other through.
    const scope = win.win as unknown as SharedScope;
    const relayed: BackgroundRequest[] = [];
    const clock = fakeClock();
    const bridge = installBridge({
      win: win.win,
      hostname,
      relay: (request) => {
        relayed.push(request);
        return Promise.resolve(true);
      },
      now: clock.now,
    });
    return { win, scope, relayed, clock, bridge };
  }

  it('routes the DOM path-s send signal into the blind detector', () => {
    const h = install();
    expect(h.bridge?.status().sendsSeenDom).toBe(0);
    notifyDomSend(h.scope);
    expect(h.bridge?.status().sendsSeenDom).toBe(1);
  });

  it('routes what arrives on the tap-s port into the bridge', () => {
    const h = install();
    const { port, emit } = fakePort();
    h.win.deliverHandshake(port);
    expect(port.start).toHaveBeenCalledTimes(1);
    expect(h.bridge?.status().patched).toBe(false);
    emit({ type: 'patched', fetch: true, xhr: false });
    expect(h.bridge?.status().patched).toBe(true);
  });

  it('reports under the session id the tab already agreed on', () => {
    // A second id would put this tab's exchanges under a different session
    // root than the prompts that produced them.
    //
    // Asserted on what the bridge RELAYS, which is the only place the id it
    // uses is observable. `resolveSessionId` stores the id on the scope before
    // `installBridge` runs and nothing in installBridge writes it back, so
    // reading the scope again proves only that the helper is idempotent —
    // replacing `sessionId: resolveSessionId(win)` with a fresh uuid, which is
    // exactly the two-ids-for-one-tab bug the module comment warns about,
    // leaves that green.
    const win = fakeWindow();
    const scope = win.win as unknown as SharedScope;
    const existing = resolveSessionId(scope);
    const relayed: BackgroundRequest[] = [];
    const clock = fakeClock();
    installBridge({
      win: win.win,
      hostname: 'claude.ai',
      relay: (request) => {
        relayed.push(request);
        return Promise.resolve(true);
      },
      now: clock.now,
    });

    // Driven over the site's declared route with the committed capture's own
    // bytes, so the exchange reaches the relay through the real endpoint
    // matcher and the real stream parser rather than a stub of either.
    const stream = loadFixture('claude-ai', STREAM_FIXTURE);
    const { port, emit } = fakePort();
    win.deliverHandshake(port);
    emit({ type: 'patched', fetch: true, xhr: false });
    emit({ type: 'request', id: 1, url: stream.url, method: 'POST', body: null });
    for (const chunk of stream.chunks) emit({ type: 'chunk', id: 1, text: chunk });
    emit({ type: 'end', id: 1, status: 200, ok: true });

    const exchange = relayed.find((r) => r.type === 'exchange');
    // The positive control: with no exchange on the wire every assertion
    // below holds vacuously, and that is the state this case was in.
    expect(exchange).toBeDefined();
    expect(exchange?.sessionId).toBe(existing);
    expect(resolveSessionId(scope)).toBe(existing);
  });

  it('builds nothing for a page no adapter claims', () => {
    const h = install('example.test');
    expect(h.bridge).toBeNull();
    // And registers neither input, so nothing on that page is listening.
    expect(h.win.listeners).toHaveLength(0);
    expect(() => {
      notifyDomSend(h.scope);
    }).not.toThrow();
  });
});

describe('reporting capture status', () => {
  function statuses(
    relayed: BackgroundRequest[],
  ): Extract<BackgroundRequest, { type: 'capture_status' }>[] {
    return relayed.filter(
      (r): r is Extract<BackgroundRequest, { type: 'capture_status' }> =>
        r.type === 'capture_status',
    );
  }

  it('reports how many conversation endpoints the adapter compiled', () => {
    // fakeAdapter() declares one conversation + one account endpoint.
    const h = harness();
    h.feed({ type: 'patched', fetch: true, xhr: false });
    expect(h.bridge.status().conversationEndpoints).toBe(1);
  });

  it('does not report an endpoint whose pattern cannot be compiled as declared', () => {
    const throwing: ProviderAdapter = {
      ...fakeAdapter(),
      endpoints: [
        {
          host: 'site.test',
          // A pattern object whose `.source` getter throws — `new RegExp`
          // reading it fails, so compileEndpoints' own catch drops the entry.
          get path(): RegExp {
            throw new Error('boom');
          },
          kind: 'conversation',
        },
      ],
    };
    const h = harness(throwing);
    expect(h.bridge.status().conversationEndpoints).toBe(0);
  });

  it('reports once the tap says it patched, and not before', () => {
    const h = harness();
    h.feed({ type: 'ready' });
    expect(statuses(h.relayed)).toHaveLength(0);
    h.feed({ type: 'patched', fetch: true, xhr: false });
    expect(statuses(h.relayed)).toHaveLength(1);
  });

  it('retries a report whose delivery failed, rather than counting it as sent', async () => {
    // `reported = signature` is set before the relay, and the shipped relay
    // swallows both a synchronous throw and the sendMessage rejection — so a
    // LOST report was indistinguishable from a delivered one. Once the status
    // reaches a signature that stops changing (`blind`, or counters at the
    // cap), that report is never re-sent, and the drift reaches neither the
    // host nor any surface: the silent failure this path exists to surface.
    const relayed: BackgroundRequest[] = [];
    let delivered = false;
    const clock = fakeClock();
    const bridge = createBridge({
      adapter: fakeAdapter(),
      sessionId: 'sess_retry',
      relay: (request) => {
        relayed.push(request);
        return Promise.resolve(delivered);
      },
      now: clock.now,
    });
    const settle = (): Promise<void> =>
      new Promise((resolve) => {
        setTimeout(resolve, 0);
      });

    bridge.onTapMessage({ type: 'patched', fetch: true, xhr: false });
    await settle();
    expect(statuses(relayed)).toHaveLength(1);

    // The same signature again. With the rollback it is re-sent, because the
    // first attempt was never delivered; without it the bridge believes the
    // report landed and sends nothing — which is the bug.
    delivered = true;
    bridge.onTapMessage({ type: 'patched', fetch: true, xhr: false });
    await settle();
    expect(statuses(relayed)).toHaveLength(2);

    // The control: once a report IS delivered, an identical signature is not
    // re-sent, so the rollback has not turned this into a resend loop.
    bridge.onTapMessage({ type: 'patched', fetch: true, xhr: false });
    await settle();
    expect(statuses(relayed)).toHaveLength(2);
  });

  it('does not re-report an unchanged signature', () => {
    const h = harness();
    h.feed({ type: 'patched', fetch: true, xhr: false });
    const before = statuses(h.relayed).length;
    for (let i = 0; i < 50; i += 1) {
      h.feed(request(100 + i));
      h.feed({ type: 'chunk', id: 100 + i, text: 'x' });
      h.feed({ type: 'end', id: 100 + i, status: 200, ok: true });
    }
    // Every one of those exchanges succeeds identically, so `live`/counts move
    // but the SIGNATURE (bucketed) does not past the first transition.
    expect(statuses(h.relayed).length).toBeLessThanOrEqual(before + 1);
  });

  it('a state change re-reports, carrying the exact (unbucketed) counts', () => {
    const h = harness();
    h.feed({ type: 'patched', fetch: true, xhr: false });
    h.feed(request(), { type: 'chunk', id: 1, text: 'a' });
    h.feed({ type: 'end', id: 1, status: 200, ok: true }); // goes live
    const reports = statuses(h.relayed);
    const last = reports[reports.length - 1];
    expect(last?.status.exchangesSeenNet).toBe(1);
  });

  it('buckets counters so a busy tab does not report per failure', () => {
    const failing = fakeAdapter({
      parseRequest: () => {
        throw new Error('bad body');
      },
    });
    const h = harness(failing);
    h.feed({ type: 'patched', fetch: true, xhr: false });
    // One exchange first, so `live` has already made its one-time transition
    // and only the parseFailures-bucket transitions are what the loop below
    // measures.
    h.feed(request(199), { type: 'end', id: 199, status: 200, ok: true });
    const baseline = statuses(h.relayed).length;
    for (let i = 0; i < STATUS_COUNTER_CAP + 5; i += 1) {
      h.feed(request(200 + i));
      h.feed({ type: 'end', id: 200 + i, status: 200, ok: true });
    }
    // parseFailures climbs through STATUS_COUNTER_CAP distinct bucketed
    // values and then stops changing the signature — never one report per
    // failure, of which there are STATUS_COUNTER_CAP + 5.
    expect(statuses(h.relayed).length).toBeLessThanOrEqual(baseline + STATUS_COUNTER_CAP);
  });

  it('marks the pagehide report as the document closing, and no earlier one', () => {
    const win = fakeWindow();
    const relayed: BackgroundRequest[] = [];
    const clock = fakeClock();
    const bridge = installBridge({
      win: win.win,
      hostname: 'claude.ai',
      relay: (request) => {
        relayed.push(request);
        return Promise.resolve(true);
      },
      now: clock.now,
    });
    // Also the positive control on the hostname: an adapter that stopped
    // claiming claude.ai would install nothing and make every assertion below
    // hold over an empty relay.
    if (bridge === null) throw new Error('claude.ai is expected to be a claimed hostname');
    // A live report before the unload one, so this reads the two APART rather
    // than holding on a single-element array — `closed` is what stops a
    // document voting on the site's state, so a report that carried it early
    // would silence a tab that is still open.
    bridge.onTapMessage({ type: 'patched', fetch: true, xhr: false });
    win.firePagehide();
    expect(statuses(relayed).map((r) => r.status.closed)).toEqual([false, true]);
  });

  it('reports again on each send a blind tab still swallows', () => {
    const h = harness();
    h.feed({ type: 'patched', fetch: true, xhr: false });
    // Drive `blind` all the way to latched, the final sweep included, so every
    // other term in the signature has stopped moving before the loop below.
    for (let strike = 0; strike <= BLIND_STRIKES; strike += 1) {
      h.bridge.noteDomSend();
      h.clock.advance(BLIND_WINDOW_MS + 1);
    }
    h.bridge.noteDomSend();
    expect(h.bridge.status().blind).toBe(true);

    const settled = statuses(h.relayed).length;
    const swallowed = 3;
    for (let more = 0; more < swallowed; more += 1) {
      h.clock.advance(BLIND_WINDOW_MS + 1);
      h.bridge.noteDomSend();
    }
    // One row per send into a tab that is still swallowing them. The read side
    // retires a document that has gone quiet for CAPTURE_STATUS_DOCUMENT_QUIET_MS,
    // and with `blindStrikes` out of the signature every term here is latched
    // — so the tab the user is actively hitting the bug in would report once
    // and then be retired while the bug is still happening.
    expect(statuses(h.relayed).length).toBe(settled + swallowed);
  });

  it('reports the final status unconditionally on pagehide', () => {
    const win = fakeWindow();
    const relayed: BackgroundRequest[] = [];
    const clock = fakeClock();
    installBridge({
      win: win.win,
      hostname: 'claude.ai',
      relay: (request) => {
        relayed.push(request);
        return Promise.resolve(true);
      },
      now: clock.now,
    });
    // No signature change pending — nothing has happened on the page yet, and
    // the pre-patched suppression would otherwise hold this back too.
    win.firePagehide();
    expect(statuses(relayed)).toHaveLength(1);
  });
});

describe("the DOM path's state travels on the status the network half reports", () => {
  const statuses = (h: ReturnType<typeof harness>) =>
    h.relayed.filter(
      (r): r is Extract<BackgroundRequest, { type: 'capture_status' }> =>
        r.type === 'capture_status',
    );

  it('carries whatever the DOM half last published', () => {
    const h = harness();
    h.setEnforcement('composer-only');
    expect(h.bridge.status().enforcement).toBe('composer-only');
  });

  it('reports a transition to unattached rather than computing it and sitting on it', () => {
    // reportSignature is what decides whether a recomputed status is worth
    // relaying. A field left out of it is a field whose changes are silent —
    // which is how `sendsSeenDom` already behaves, and the exact failure this
    // whole signal exists to end.
    const h = harness();
    h.feed({ type: 'patched', fetch: true, xhr: true });
    const before = statuses(h).length;

    h.setEnforcement('unattached');
    h.bridge.noteDomSend();

    const after = statuses(h);
    expect(after.length).toBeGreaterThan(before);
    expect(after[after.length - 1]?.status.enforcement).toBe('unattached');
  });
});

describe('the network half re-reports when only the DOM half moved', () => {
  const statuses = (h: ReturnType<typeof harness>) =>
    h.relayed.filter(
      (r): r is Extract<BackgroundRequest, { type: 'capture_status' }> =>
        r.type === 'capture_status',
    );

  it('emits a status on an enforcement change with no network traffic at all', () => {
    // maybeReport() previously ran only from onTapMessage and noteDomSend, so
    // a tab whose watcher died reported nothing until some unrelated network
    // event happened to fire. On a quiet tab, never.
    const h = harness();
    h.feed({ type: 'patched', fetch: true, xhr: true });
    const before = statuses(h).length;

    h.setEnforcement('unattached');
    h.bridge.noteEnforcementChange();

    const after = statuses(h);
    expect(after.length).toBeGreaterThan(before);
    expect(after[after.length - 1]?.status.enforcement).toBe('unattached');
  });

  it('says nothing when the state has not actually moved', () => {
    const h = harness();
    h.feed({ type: 'patched', fetch: true, xhr: true });
    const before = statuses(h).length;

    h.bridge.noteEnforcementChange();

    expect(statuses(h).length).toBe(before);
  });
});

describe('the exchange parseStream is handed', () => {
  it("names the endpoint that matched, by reference to the adapter's own declaration", () => {
    // Identity, not equality. An adapter serving several routes of the same
    // KIND has nothing else to branch on — two `conversation` endpoints are
    // indistinguishable by kind — so handing back a re-anchored copy would
    // leave it exactly as stuck as passing nothing did.
    const seen: MatchedExchange[] = [];
    const adapter = fakeAdapter({
      onExchange: (exchange) => {
        seen.push(exchange);
      },
    });
    const h = harness(adapter);
    h.feed(
      { type: 'patched', fetch: true, xhr: true },
      {
        type: 'request',
        id: 1,
        url: 'https://site.test/api/conversation/abc',
        method: 'POST',
        body: '{}',
      },
      { type: 'chunk', id: 1, text: 'x' },
    );

    expect(seen).toHaveLength(1);
    expect(seen[0]?.url).toBe('https://site.test/api/conversation/abc');
    // The conversation endpoint, not the account one declared beside it.
    expect(seen[0]?.endpoint).toBe(adapter.endpoints[0]);
    expect(seen[0]?.endpoint).not.toBe(adapter.endpoints[1]);
  });

  it('reaches parseRequest too, with the same match', () => {
    const stream: MatchedExchange[] = [];
    const request: MatchedExchange[] = [];
    const adapter = fakeAdapter({
      onExchange: (e) => {
        stream.push(e);
      },
      onRequestExchange: (e) => {
        request.push(e);
      },
    });
    const h = harness(adapter);
    h.feed(
      { type: 'patched', fetch: true, xhr: true },
      {
        type: 'request',
        id: 1,
        url: 'https://site.test/api/conversation/abc',
        method: 'POST',
        body: '{}',
      },
      { type: 'chunk', id: 1, text: 'x' },
    );
    expect(request).toHaveLength(1);
    expect(request[0]?.endpoint).toBe(adapter.endpoints[0]);
    expect(request[0]?.url).toBe('https://site.test/api/conversation/abc');
    // Both halves of one exchange are told the same thing.
    expect(request[0]).toEqual(stream[0]);
  });

  it('does NOT reach parseRequest for a body the bridge declined, though the stream half still runs', () => {
    // Why anything read off the URL belongs in parseStream: this seam is
    // skipped for a body over REQUEST_BODY_MAX_BYTES, so a field recovered
    // here goes missing on exactly those turns.
    const stream: MatchedExchange[] = [];
    const request: MatchedExchange[] = [];
    const adapter = fakeAdapter({
      onExchange: (e) => {
        stream.push(e);
      },
      onRequestExchange: (e) => {
        request.push(e);
      },
    });
    const h = harness(adapter);
    h.feed(
      { type: 'patched', fetch: true, xhr: true },
      {
        type: 'request',
        id: 1,
        url: 'https://site.test/api/conversation/abc',
        method: 'POST',
        body: 'x'.repeat(REQUEST_BODY_MAX_BYTES + 1),
      },
      { type: 'chunk', id: 1, text: 'x' },
    );
    expect(request).toHaveLength(0);
    expect(stream).toHaveLength(1);
  });

  it('classifyCompiled agrees with matchCompiled, because it is derived from it', () => {
    // Two matchers over one table are free to disagree about what a URL is,
    // and that disagreement is invisible until a site moves.
    const compiled = compileEndpoints(fakeAdapter());
    for (const url of [
      'https://site.test/api/conversation/abc',
      'https://site.test/api/account/me',
      'https://site.test/api/other',
      'https://other.test/api/conversation/abc',
      'not a url',
    ]) {
      expect(classifyCompiled(compiled, url), url).toBe(matchCompiled(compiled, url)?.kind ?? null);
    }
  });
});
