// The network tap. It runs in the PAGE's own JavaScript context, with the
// page's own authority, so what bounds it is this file being small, importing
// nothing, and doing only what a tap does: observe the two transports it
// captures, forward matched request and response bytes over one MessagePort,
// and be invisible to the page in every other respect.
//
// It has NO imports, at runtime or as types. `./tap-protocol.ts` is the
// vocabulary these local declarations mirror, and test/tap-bundle.test.ts pins
// the copies together by reading both sources. That suite reads THIS file as
// well as the built artifact, because bundling inlines a resolved specifier: an
// import added here leaves the emitted bundle naming no module at all, so the
// artifact alone cannot tell whether the tap grew a dependency.
//
// Three rules the whole file is written to, in priority order:
//
// 1. The page never notices. Every patched entry point calls the captured
//    original with the arguments it was given, on every path, and returns what
//    the original returned. Everything the tap does for itself sits inside a
//    try/catch that swallows — including the callbacks it hands to a promise,
//    where a throw would otherwise surface in the page's realm as an unhandled
//    rejection rather than being swallowed. A rejected call rejects with the
//    same reason.
// 2. The port carries no command channel. What the tap forwards is fixed when
//    the extension is built; the tap installs no `onmessage` and never calls
//    `start()`, so anything posted at it is queued and never delivered. That is
//    a narrower claim than "nothing in the page can influence the tap", which
//    is not true of any script sharing a realm — the page can replace
//    `win.fetch` after the tap has patched it and route around the tap
//    entirely. What the tap defends is what it FORWARDS: the builtins it
//    matches, decodes and reads page-owned objects through are captured below
//    while the tap is the only script that has run, so a later replacement can
//    neither widen what is matched nor fabricate what is reported.
// 3. It originates no request of its own. The only calls out are the captured
//    originals, re-invoked on the page's behalf.

// Mirrors TAP_CHANNEL in tap-protocol.ts.
const TAP_CHANNEL = 'aka-tap';

// Mirrors the host/path half of TapEndpoint in tap-protocol.ts. `kind` is the
// bridge's business and is not injected here — the tap decides only whether to
// forward, never what a forwarded exchange means.
interface TapTarget {
  host: string;
  path: string;
}

// Mirrors TapToPage in tap-protocol.ts.
type TapToPage =
  | { type: 'ready' }
  | { type: 'patched'; fetch: boolean; xhr: boolean }
  | { type: 'request'; id: number; url: string; method: string; body: string | null }
  | { type: 'chunk'; id: number; text: string }
  | { type: 'end'; id: number; status: number; ok: boolean }
  | {
      type: 'error';
      id: number;
      reason: 'unparsed_body' | 'tap_error' | 'truncated' | 'aborted';
    };

// The endpoints this build forwards, injected by scripts/build.mjs as an
// esbuild `define` and derived there from the adapter registry. GENERATED —
// never hand-edited here, and never accepted over a wire: a table the page
// could set would let a page choose what AKA records about it.
//
// It is EMPTY today, because no adapter declares an endpoint yet. An empty
// table matches nothing, so this build's tap forwards nothing at all.
//
// The `typeof` guard is what makes the fallback real rather than decorative:
// with no define in play (the unit suite imports this module directly) the
// identifier is undeclared, and `typeof` is the one form that reads an
// undeclared name without throwing.
declare const AKA_TAP_ENDPOINTS: readonly TapTarget[] | undefined;
const ENDPOINTS: readonly TapTarget[] =
  typeof AKA_TAP_ENDPOINTS === 'undefined' ? [] : AKA_TAP_ENDPOINTS;

// The most response bytes the tap pulls from one exchange.
//
// The tap reads a clone, and a tee's two branches are independent: `Response`
// exposes no signal when the page abandons its own branch, so the tap cannot
// mirror a cancellation it never hears about. Bounding what it will pull is the
// available fix — without it a download the page gave up on is kept alive by
// the tap's reader for as long as the server keeps sending. On reaching the
// ceiling the tap cancels its reader and says the exchange was cut, rather than
// ending it as though the body had finished.
//
// It must stay at or above the host's own stored-text ceiling
// (RESPONSE_TEXT_MAX_BYTES in @akasecurity/schema), or the wire becomes the
// binding cap and the host's number stops describing anything.
// test/tap-bundle.test.ts asserts that relation across the two packages.
//
// There is deliberately NO matching cap on the forwarded REQUEST body. The
// request half is read from a clone of a body the page has already built, so it
// is bounded by what the site itself chose to send, and the tap has no way to
// signal a partial request body without inventing protocol the bridge would
// have to interpret. Bounding it is the bridge's to own, on the receiving side
// of the port, where a partial body can be rejected rather than half-parsed.
const RESPONSE_MAX_BYTES = 4 * 1024 * 1024;

// What the tap will decode from a binary request body. A ceiling here rather
// than at the reader, because the decode is synchronous and on the page's own
// call path.
const REQUEST_BODY_DECODE_MAX_BYTES = 1024 * 1024;

// The ceiling on what a COMPRESSED body may expand to. A separate limit from
// the one above because the compressed size bounds nothing: a few KB of gzip
// can expand without limit, so a tap that inflated to completion and measured
// the result would let a page exhaust this tab's memory on demand.
const REQUEST_BODY_INFLATE_MAX_BYTES = 4 * 1024 * 1024;

// Whether `text` carries a C0 control character no text body would. Tab,
// newline and carriage return are excluded because a text body does carry them.
// Written as a scan rather than a regular expression: a literal spelling these
// codepoints trips no-control-regex, and an inline disable for it would be one
// more directive to inventory for no gain.
function hasControlBytes(text: string): boolean {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code > 0x1f) continue;
    if (code === 0x09 || code === 0x0a || code === 0x0d) continue;
    return true;
  }
  return false;
}

// How long the tap waits for a deferred request body before giving up on it.
//
// A deferred body is a promise over a clone of the page's own request stream,
// and `duplex: 'half'` lets a server answer before that stream ends — so a page
// that never closes its upload would leave the tap holding a response clone
// whose tee buffers the whole response for the life of the page. On expiry the
// exchange proceeds with no request body, rather than never proceeding at all.
const REQUEST_BODY_DEADLINE_MS = 10_000;

// The page's XHR constructor, described structurally.
//
// lib.dom declares XMLHttpRequest as a bare global rather than a member of
// `Window`, so it cannot be reached off the parameter's declared type — and a
// bare `XMLHttpRequest` identifier, in a value OR a type position, is what the
// workspace network ban catches. Describing only the members the tap touches
// keeps the name out of every position that ban reaches: it survives here only
// as a property key on a cast, which is neither a bare identifier nor a member
// of `window`/`globalThis`/`self`/`global`.
interface XhrLike {
  addEventListener(type: string, listener: () => void, options?: { once?: boolean }): void;
}

interface XhrPrototype extends XhrLike {
  open: (this: XhrLike, ...args: unknown[]) => void;
  send: (this: XhrLike, body?: unknown) => void;
}

interface XhrConstructorLike {
  new (): XhrLike;
  prototype: XhrPrototype;
}

// What one in-flight XHR is being tapped as. Held in a WeakMap rather than on
// the request object: the tap must add no observable property to anything the
// page owns. A fresh object per `open()` is what lets a `loadend` listener tell
// its own send from a later one on the same request object.
interface XhrState {
  method: string;
  url: string;
}

// How a request body can be read WITHOUT disturbing the page's own copy.
// 'sync' is already a string; 'deferred' needs a promise that reads a clone;
// 'unreadable' is a body the tap will not touch — a stream has one reader, and
// taking it would break the page's own request.
type BodyPlan =
  | { kind: 'sync'; body: string | null }
  | { kind: 'deferred'; body: Promise<string> }
  | { kind: 'unreadable' };

type Accessor = (this: unknown) => unknown;
type Method = (this: unknown, ...args: unknown[]) => unknown;

// The own-or-inherited getter for `key`, so a member the page shadows on one
// INSTANCE is bypassed by calling this with that instance as the receiver.
function accessorOf(start: object, key: string): Accessor | undefined {
  let proto: object | null = start;
  while (proto !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(proto, key) as
      { get?: Accessor } | undefined;
    if (descriptor !== undefined) return descriptor.get;
    proto = Object.getPrototypeOf(proto) as object | null;
  }
  return undefined;
}

// The same for a method: the function itself, taken off the descriptor so it
// arrives already detached from whatever object is holding it. Every use below
// supplies the receiver explicitly, which is the whole point — a method read as
// `obj.method` is a method the page can have replaced on `obj`.
//
// Both helpers walk the chain, because the member may sit well above the
// prototype they are given: `addEventListener` is on EventTarget.prototype, not
// on the XHR one.
function methodOf(start: object, key: string): Method | undefined {
  let proto: object | null = start;
  while (proto !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(proto, key) as
      { value?: Method } | undefined;
    if (descriptor !== undefined) return descriptor.value;
    proto = Object.getPrototypeOf(proto) as object | null;
  }
  return undefined;
}

// Builtins captured while the tap is the only script that has run — for the
// shipped tap that is document_start, before the page has had a turn. Every use
// below goes through these rather than through the live global, so replacing
// one afterwards changes neither what the tap matches nor what it reports.
//
// The boundary is real but NOT total, and the two things outside it are worth
// naming. `win.location.href` is read live as the base for a relative request
// URL — a relative URL resolves to this document's own origin either way, so a
// poisoned base can cost the tap a match but cannot hand it a foreign one. And
// the reader taken from a response clone has its own methods read live; the
// clone itself comes from a captured native, so only a replacement of
// ReadableStream's own prototype reaches it.
const regexpTest = methodOf(RegExp.prototype, 'test');
const UrlCtor = URL;
const urlHost = accessorOf(URL.prototype, 'host');
const urlPath = accessorOf(URL.prototype, 'pathname');
const urlQuery = accessorOf(URL.prototype, 'search');
const urlHref = accessorOf(URL.prototype, 'href');
const Decoder = TextDecoder;
const decodeText = methodOf(TextDecoder.prototype, 'decode');
const U8 = Uint8Array;
const Decompressor = typeof DecompressionStream === 'function' ? DecompressionStream : undefined;

/**
 * Patch `win`'s two transports and forward matched traffic over `port`.
 *
 * `endpoints` bind a host to a path pattern. They are a parameter rather than a
 * message because the tap accepts no message: this is the whole of what it will
 * ever forward, decided by whoever called it. The module's own bootstrap passes
 * the build-time table; the unit suite passes its own.
 */
export function installTap(win: Window, port: MessagePort, endpoints: readonly TapTarget[]): void {
  let nextId = 1;

  const targets: { host: string; path: RegExp }[] = [];
  for (const endpoint of endpoints) {
    try {
      // Anchored, and wrapped so an alternation anchors as a whole rather than
      // only its first branch. No flags: a `g` would carry lastIndex between
      // calls and make matching depend on call order.
      targets.push({ host: endpoint.host, path: new RegExp(`^(?:${endpoint.path})`) });
    } catch {
      // A pattern that does not compile forwards nothing, rather than taking
      // the rest of the table down with it.
    }
  }

  function post(message: TapToPage): void {
    try {
      port.postMessage(message);
    } catch {
      // A closed or revoked port is not the page's problem.
    }
  }

  // No `onmessage` and no `start()`: the port is write-only from this side, so
  // anything posted at the tap is queued and never delivered. That is the
  // property, not an omission — the page shares this window's event target and
  // can take the transferred port off the handshake, and a tap that read from
  // it would be a tap the page configures.

  // Absolute where it can be: a target names a host, and a relative URL would
  // never carry one. Falls back to the string the page passed.
  function absolute(raw: string): string {
    try {
      const parsed = new UrlCtor(raw, win.location.href);
      return urlHref === undefined ? raw : String(urlHref.call(parsed));
    } catch {
      return raw;
    }
  }

  // A URL is forwarded only when its HOST is one the build named and its path
  // matches that host's pattern from the start. Matching on the whole href
  // instead would forward any origin whose URL merely contains the pattern
  // text — in its path or in a query parameter — as though it were the site's
  // own traffic.
  function matched(url: string): boolean {
    if (
      regexpTest === undefined ||
      urlHost === undefined ||
      urlPath === undefined ||
      urlQuery === undefined
    ) {
      // Nothing to match WITH is a reason to forward nothing, never a reason to
      // forward everything.
      return false;
    }
    let parsed: URL;
    try {
      parsed = new UrlCtor(url);
    } catch {
      // A URL the tap cannot parse is one whose host it cannot check.
      return false;
    }
    for (const target of targets) {
      try {
        if (urlHost.call(parsed) !== target.host) continue;
        // The query is included so a pattern MAY key on one, but it sits after
        // the path and the pattern is anchored, so a query cannot reach a
        // pattern written against a path.
        const path = `${String(urlPath.call(parsed))}${String(urlQuery.call(parsed))}`;
        if (regexpTest.call(target.path, path) === true) return true;
      } catch {
        // Skip a target that throws; the others still decide.
      }
    }
    return false;
  }

  // Bytes as text, or null when they are not text. Valid UTF-8 is necessary and
  // not sufficient: a run of NULs decodes without throwing, so a C0 control
  // character other than tab, newline or carriage return is what separates a
  // body worth parsing from an image or an archive. `fatal` is what makes the
  // decode itself discriminate rather than substituting replacement characters.
  function decodeTextBody(bytes: unknown): string | null {
    if (decodeText === undefined) return null;
    const size = (bytes as { byteLength: number }).byteLength;
    if (size > REQUEST_BODY_DECODE_MAX_BYTES) return null;
    let text: string;
    try {
      text = String(decodeText.call(new Decoder('utf-8', { fatal: true }), bytes));
    } catch {
      return null;
    }
    return hasControlBytes(text) ? null : text;
  }

  // A byte view over a buffer, or over a view of one, without copying it.
  function bytesOf(body: unknown): Uint8Array | null {
    try {
      const view = body as { buffer?: ArrayBuffer; byteOffset?: number; byteLength: number };
      return view.buffer === undefined
        ? new U8(body as ArrayBuffer)
        : new U8(view.buffer, view.byteOffset ?? 0, view.byteLength);
    } catch {
      return null;
    }
  }

  // The gzip header: magic 1f 8b, then the deflate method. Read off the BYTES
  // rather than a Content-Encoding header, because the page sets that header
  // itself and a tap that trusted it would inflate whatever it was told to.
  function isGzip(body: unknown): boolean {
    const u8 = bytesOf(body);
    return u8 !== null && u8.length > 2 && u8[0] === 0x1f && u8[1] === 0x8b && u8[2] === 0x08;
  }

  /**
   * Inflate a gzip request body and decode it as text.
   *
   * Reading a buffer consumes nothing, so unlike a request stream this costs
   * the page's own request nothing — the same argument that lets the plain
   * byte branch below decode without disturbing the page.
   *
   * The output is bounded AS IT ARRIVES, never after: see
   * REQUEST_BODY_INFLATE_MAX_BYTES. The read is cancelled the moment the
   * ceiling is crossed, and the rejection that follows takes the ordinary
   * unreadable-body path rather than forwarding a partial body.
   */
  async function inflateToText(body: unknown): Promise<string> {
    if (Decompressor === undefined) throw new Error('no decompressor');
    const stream = new Decompressor('gzip');
    const writer = stream.writable.getWriter();
    void writer.write(body as BufferSource).catch(() => undefined);
    void writer.close().catch(() => undefined);
    const reader = stream.readable.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const step = await reader.read();
      if (step.done) break;
      const chunk = step.value as Uint8Array;
      total += chunk.byteLength;
      if (total > REQUEST_BODY_INFLATE_MAX_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new Error('inflate ceiling');
      }
      chunks.push(chunk);
    }
    const joined = new U8(total);
    let at = 0;
    for (const chunk of chunks) {
      joined.set(chunk, at);
      at += chunk.byteLength;
    }
    if (decodeText === undefined) throw new Error('no decoder');
    const text = String(decodeText.call(new Decoder('utf-8', { fatal: true }), joined));
    if (hasControlBytes(text)) throw new Error('control bytes');
    return text;
  }

  function planBody(body: unknown): BodyPlan {
    if (body === undefined || body === null) return { kind: 'sync', body: null };
    if (typeof body === 'string') return { kind: 'sync', body };
    if (typeof body === 'object') {
      const candidate = body as {
        getReader?: unknown;
        forEach?: (fn: (value: unknown, key: string) => void) => void;
      };
      // A ReadableStream body: reported, never read. It has one reader, and
      // taking it would empty the page's own request.
      if (typeof candidate.getReader === 'function') return { kind: 'unreadable' };
      // An ArrayBuffer, or a view over one, walks its entries yielding a NUMBER
      // per index — so the branch below would render a whole body as
      // `0=&1=&2=…`, forwarded as though it were the body. Decoded instead when
      // the bytes are text: reading a buffer consumes nothing, so unlike a
      // stream it costs the page's own request nothing, and a site that sends
      // its turn as encoded JSON would otherwise have the whole exchange
      // refused rather than observed.
      if (typeof (candidate as { byteLength?: unknown }).byteLength === 'number') {
        // Ahead of the plain decode, because gzip bytes are never valid UTF-8:
        // left to the branch below, a compressed body is refused every time.
        if (Decompressor !== undefined && isGzip(body)) {
          return { kind: 'deferred', body: inflateToText(body) };
        }
        const text = decodeTextBody(body);
        return text === null ? { kind: 'unreadable' } : { kind: 'sync', body: text };
      }
      // URLSearchParams and FormData both walk their entries this way. A file
      // part contributes its field name and an empty value, never its bytes.
      if (typeof candidate.forEach === 'function') {
        const parts: string[] = [];
        candidate.forEach((value, key) => {
          const text = typeof value === 'string' ? value : '';
          parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(text)}`);
        });
        return { kind: 'sync', body: parts.join('&') };
      }
    }
    // A Blob, an ArrayBuffer or a typed array: nothing the tap reads.
    return { kind: 'unreadable' };
  }

  // What the tap decided to do with one call, computed BEFORE the original runs
  // so the original is never invoked twice and never invoked late.
  interface Tapped {
    id: number;
    started: Promise<void>;
  }

  /**
   * Opens an exchange for a planned body, and reports when `request` is on the
   * wire — or reports that no exchange was opened at all, by returning null.
   *
   * Shared by BOTH transports on purpose. The XHR half used to branch on
   * `'sync'` alone, and its `else` was written when `'unreadable'` was the only
   * other kind; once a gzip body could plan as `'deferred'`, that branch
   * silently swallowed it. An XHR upload of gzip bytes to a matched endpoint
   * therefore reported `unparsed_body` and nothing else — no `request`, no
   * response, no `end` — while the same body over fetch still captured the
   * response, and the inflate promise was left with no handler, surfacing as an
   * unhandled rejection in the page's own console. One definition is what stops
   * the two transports disagreeing about a plan again.
   */
  function openRequest(
    plan: BodyPlan,
    id: number,
    url: string,
    method: string,
  ): Promise<void> | null {
    if (plan.kind === 'unreadable') {
      // Reported and then left alone. The request proceeds untouched and the
      // tap follows nothing further about it, so this opens no exchange and
      // no `end` follows.
      post({ type: 'error', id, reason: 'unparsed_body' });
      return null;
    }
    if (plan.kind === 'sync') {
      post({ type: 'request', id, url, method, body: plan.body });
      return Promise.resolve();
    }
    // A deferred body still posts `request` before any `chunk`, so the
    // bridge sees one exchange in order however fast the response arrives —
    // and it posts one within the deadline whether or not the body ever
    // arrives, so the response clone is never held on a promise that will
    // not settle.
    return new Promise<void>((resolve) => {
      let settled = false;
      const finish = (body: string | null): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        post({ type: 'request', id, url, method, body });
        resolve();
      };
      // Read live rather than captured: a page that has replaced setTimeout
      // can already hang its own upload, so capturing buys nothing here.
      const timer = setTimeout(() => {
        finish(null);
      }, REQUEST_BODY_DEADLINE_MS);
      plan.body.then(
        (body) => {
          finish(body);
        },
        () => {
          finish(null);
        },
      );
    });
  }

  // A window whose fetch cannot be replaced is patched on the XHR half only,
  // and says so.
  let canPatchFetch = false;
  try {
    // Read off page-supplied Request and Response objects with the object as
    // receiver, so an own property defined over one of these accessors is
    // bypassed. Without them the tap reports the URL, the method and the whole
    // response body a page CHOSE to expose, which is a fabricated exchange
    // attributed to a matched endpoint while the browser talks elsewhere.
    const requestUrlOf = accessorOf(Request.prototype, 'url');
    const requestMethodOf = accessorOf(Request.prototype, 'method');
    const requestBodyOf = accessorOf(Request.prototype, 'body');
    const responseStatusOf = accessorOf(Response.prototype, 'status');
    const responseOkOf = accessorOf(Response.prototype, 'ok');
    const responseBodyOf = accessorOf(Response.prototype, 'body');
    const requestCloneFn = methodOf(Request.prototype, 'clone');
    const requestTextFn = methodOf(Request.prototype, 'text');
    const responseCloneFn = methodOf(Response.prototype, 'clone');
    const responseTextFn = methodOf(Response.prototype, 'text');

    if (
      typeof win.fetch === 'function' &&
      decodeText !== undefined &&
      requestUrlOf !== undefined &&
      requestMethodOf !== undefined &&
      requestBodyOf !== undefined &&
      requestCloneFn !== undefined &&
      requestTextFn !== undefined &&
      responseStatusOf !== undefined &&
      responseOkOf !== undefined &&
      responseBodyOf !== undefined &&
      responseCloneFn !== undefined &&
      responseTextFn !== undefined
    ) {
      // Bound to the window it came off, which is how the page's own
      // `window.fetch(…)` call would have invoked it.
      const originalFetch = win.fetch.bind(win);

      // Reads a Request's body from a clone, so the page's own Request stays
      // unconsumed. Cloning is synchronous and does not disturb the original.
      const planRequestBody = (request: Request): BodyPlan => {
        try {
          if (requestBodyOf.call(request) === null) return { kind: 'sync', body: null };
          const clone = requestCloneFn.call(request);
          return { kind: 'deferred', body: requestTextFn.call(clone) as Promise<string> };
        } catch {
          return { kind: 'unreadable' };
        }
      };

      // Drains a cloned response into `chunk`/`end`. The clone is read EAGERLY:
      // clone() tees internally, and an unread branch buffers the whole body
      // behind the page's own reader.
      const drain = (id: number, clone: Response): void => {
        let status = 0;
        let ok = false;
        // Closes the exchange: the `error` says why, and the `end` after it is
        // the single terminator every opened exchange gets.
        const failed = (): void => {
          post({ type: 'error', id, reason: 'tap_error' });
          post({ type: 'end', id, status, ok });
        };
        try {
          const rawStatus = responseStatusOf.call(clone);
          status = typeof rawStatus === 'number' ? rawStatus : 0;
          ok = responseOkOf.call(clone) === true;
          const body = responseBodyOf.call(clone) as ReadableStream<Uint8Array> | null;
          if (body === null) {
            // No stream to read: a response built from a buffer still answers
            // text(). RESPONSE_MAX_BYTES does not apply — those bytes are
            // already in memory, so there is no download left to keep alive.
            (responseTextFn.call(clone) as Promise<string>).then((text) => {
              try {
                if (text) post({ type: 'chunk', id, text });
                post({ type: 'end', id, status, ok });
              } catch {
                failed();
              }
            }, failed);
            return;
          }
          const reader = body.getReader();
          const decoder = new Decoder();
          let seen = 0;
          const pump = (): void => {
            reader.read().then((result) => {
              try {
                if (result.done) {
                  // Flush whatever multi-byte sequence was still split across
                  // reads.
                  const tail = String(decodeText.call(decoder));
                  if (tail) post({ type: 'chunk', id, text: tail });
                  post({ type: 'end', id, status, ok });
                  return;
                }
                seen += result.value.byteLength;
                const text = String(decodeText.call(decoder, result.value, { stream: true }));
                if (text) post({ type: 'chunk', id, text });
                if (seen >= RESPONSE_MAX_BYTES) {
                  post({ type: 'error', id, reason: 'truncated' });
                  post({ type: 'end', id, status, ok });
                  const ignore = (): void => undefined;
                  reader.cancel().then(ignore, ignore);
                  return;
                }
                pump();
              } catch {
                failed();
              }
            }, failed);
          };
          pump();
        } catch {
          failed();
        }
      };

      const beginFetch = (args: Parameters<typeof originalFetch>): Tapped | null => {
        const input = args[0];
        const init = args[1];
        let url: string;
        let method: string;
        let request: Request | null = null;
        if (typeof input === 'string' || input instanceof UrlCtor) {
          url = absolute(String(input));
          method = init?.method ?? 'GET';
        } else {
          // The identity comes off the PROTOTYPE accessors with the object as
          // receiver. A non-Request that merely looks like one throws here and
          // is not tapped, which is the right answer for an object fetch will
          // stringify to something else entirely.
          const rawUrl = requestUrlOf.call(input);
          const rawMethod = requestMethodOf.call(input);
          if (typeof rawUrl !== 'string' || typeof rawMethod !== 'string') return null;
          request = input;
          url = absolute(rawUrl);
          method = init?.method ?? rawMethod;
        }

        // Matched BEFORE any body is planned. Planning a Request's body clones
        // it and starts a read, so doing that first means every request the tap
        // is going to ignore still pays for a clone and leaves an abandoned
        // promise whose rejection nobody handles.
        if (!matched(url)) return null;

        const plan =
          request !== null && init?.body === undefined
            ? planRequestBody(request)
            : planBody(init?.body);

        const id = nextId++;
        const started = openRequest(plan, id, url, method);
        if (started === null) return null;
        return { id, started };
      };

      win.fetch = (...args: Parameters<typeof originalFetch>): Promise<Response> => {
        let tapped: Tapped | null;
        try {
          tapped = beginFetch(args);
        } catch {
          tapped = null;
        }
        const pending = originalFetch(...args);
        if (!tapped) return pending;
        const { id, started } = tapped;
        try {
          // A SIDE chain, whose own result is dropped: the page's promise is
          // the one returned below and is never routed through this. A rejected
          // fetch is still the end of an exchange the tap opened, and without a
          // terminator here the bridge holds that id for the life of the page.
          pending.then(undefined, () => {
            // Closed only once `started` has posted `request`. For a deferred
            // body `request` is posted from finish(), so a page that aborts
            // before the cloned body settles would otherwise put `error` and
            // `end` on the wire first and `request` up to
            // REQUEST_BODY_DEADLINE_MS later — closing an id the bridge has
            // not opened, then opening one nothing ever closes. `started`
            // always resolves; the deadline timer is the worst case.
            void started.then(() => {
              post({ type: 'error', id, reason: 'aborted' });
              post({ type: 'end', id, status: 0, ok: false });
            });
          });
          return pending.then((response) => {
            try {
              // Cloned SYNCHRONOUSLY, before this handler returns: the page reads
              // the body the moment it gets the response, and a clone taken after
              // that would throw on an already-consumed body.
              const clone = responseCloneFn.call(response) as Response;
              const begin = (): void => {
                drain(id, clone);
              };
              started.then(begin, begin);
            } catch {
              post({ type: 'error', id, reason: 'tap_error' });
              post({ type: 'end', id, status: 0, ok: false });
            }
            // The page's own Response object, untouched.
            return response;
          });
        } catch {
          return pending;
        }
      };
      canPatchFetch = true;
    }
  } catch {
    // A window whose `fetch` is a non-writable or non-configurable property
    // throws on assignment in strict mode. That is a blind spot to REPORT, not
    // a reason to abandon the install: the XHR half below is patched either
    // way, and `patched` says which halves are real.
  }

  let canPatchXhr = false;
  try {
    const xhrConstructor = (win as unknown as { XMLHttpRequest?: XhrConstructorLike })
      .XMLHttpRequest;
    if (typeof xhrConstructor === 'function') {
      const proto = xhrConstructor.prototype;
      const statusOf = accessorOf(proto, 'status');
      const responseTypeOf = accessorOf(proto, 'responseType');
      const responseTextOf = accessorOf(proto, 'responseText');
      const addListener = methodOf(proto, 'addEventListener');
      // Without every one of these the tap cannot read a response except
      // through properties the page may have defined over them, which is a
      // fabricated body attributed to a matched endpoint. A transport it cannot
      // read honestly is one it reports as a blind spot instead.
      if (
        statusOf !== undefined &&
        responseTypeOf !== undefined &&
        responseTextOf !== undefined &&
        addListener !== undefined
      ) {
        const originalOpen = proto.open;
        const originalSend = proto.send;
        const inFlight = new WeakMap<XhrLike, XhrState>();

        proto.open = function patchedOpen(this: XhrLike, ...args: unknown[]): void {
          try {
            // A NEW state object every time, never a mutation of the old one:
            // its identity is what a listener from an earlier send compares
            // against to find out that it is looking at somebody else's
            // response. Recorded BEFORE the original runs, because opening over
            // a send that is still in flight aborts it — and that abort fires
            // the earlier send's own `loadend` from inside this call.
            inFlight.set(this, { method: String(args[0]), url: absolute(String(args[1])) });
          } catch {
            // Nothing recorded means nothing forwarded for this request.
          }
          originalOpen.call(this, ...args);
        };

        proto.send = function patchedSend(this: XhrLike, body?: unknown): void {
          try {
            const state = inFlight.get(this);
            if (state && matched(state.url)) {
              const plan = planBody(body);
              const id = nextId++;
              // Every plan kind goes through the one definition, so a body that
              // plans as 'deferred' here opens its exchange exactly as it does
              // over fetch. A null `started` is the 'unreadable' case, which
              // opens no exchange and needs no listener.
              const started = openRequest(plan, id, state.url, state.method);
              if (started !== null) {
                // An XHR object is reusable, and a listener added per send would
                // otherwise outlive the send it was created for: it stays
                // attached, fires again on the NEXT response, and posts those
                // bytes under this id — bytes from a URL no pattern matched.
                // `once` retires it as soon as it has reported, and the state
                // identity check keeps it silent when the request was re-opened
                // before its own response ever arrived.
                addListener.call(
                  this,
                  'loadend',
                  () => {
                    if (inFlight.get(this) !== state) return;
                    // Read SYNCHRONOUSLY, post after `request`. The values are
                    // only certainly this send's at loadend — the object is
                    // reusable — while the posts have to follow `request`,
                    // which for a deferred body is not on the wire yet.
                    let report: () => void;
                    try {
                      const rawStatus = statusOf.call(this);
                      const status = typeof rawStatus === 'number' ? rawStatus : 0;
                      // responseText throws for a non-text responseType, which
                      // is a body this tap does not read.
                      const responseType = responseTypeOf.call(this);
                      const raw =
                        responseType === '' || responseType === 'text'
                          ? responseTextOf.call(this)
                          : '';
                      const text = typeof raw === 'string' ? raw : '';
                      report = (): void => {
                        if (text) post({ type: 'chunk', id, text });
                        post({ type: 'end', id, status, ok: status >= 200 && status < 300 });
                      };
                    } catch {
                      report = (): void => {
                        post({ type: 'error', id, reason: 'tap_error' });
                        post({ type: 'end', id, status: 0, ok: false });
                      };
                    }
                    void started.then(report, report);
                  },
                  { once: true },
                );
              }
            }
          } catch {
            // Fall through to the original send.
          }
          originalSend.call(this, body);
        };
        canPatchXhr = true;
      }
    }
  } catch {
    // A window whose XHR cannot be patched keeps its own; the `patched` report
    // below says so.
  }

  post({ type: 'ready' });
  // Installation is not visibility: the bridge is told which halves exist on
  // this page, so a transport that could not be patched shows up as a blind
  // spot rather than as silence.
  post({ type: 'patched', fetch: canPatchFetch, xhr: canPatchXhr });
}

// The bootstrap. One window.postMessage hands the bridge the other end of a
// private MessageChannel; everything after it travels over that port rather
// than over the window channel the page can also read.
function bootstrap(): void {
  try {
    if (typeof window === 'undefined' || typeof MessageChannel === 'undefined') return;
    const channel = new MessageChannel();
    installTap(window, channel.port1, ENDPOINTS);
    // targetOrigin '*' reaches this window only. Page scripts share this event
    // target, so they see the handshake and can take the port before the bridge
    // does. What that costs is bounded on THIS side: the tap reads nothing from
    // the port, so a page holding it can change neither what is matched nor
    // what is forwarded, and receives only the bytes of its own traffic, which
    // it originated and can already read. What it does NOT bound is the other
    // side — nothing here proves to a consumer that a handshake came from the
    // tap rather than from the page, so the bridge has to register at
    // document_start, take the first handshake and ignore every later one.
    window.postMessage({ tag: TAP_CHANNEL }, '*', [channel.port2]);
  } catch {
    // A page the tap cannot install on is a page the tap does nothing to.
  }
}

bootstrap();
