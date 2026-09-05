// The message vocabulary between the MAIN-world tap and the isolated-world
// bridge. Types only — no runtime imports either side, so the tap bundle stays
// dependency-free and the bridge can import these as types without pulling
// anything into the page.
//
// The traffic is ONE WAY, and that is the security property rather than a
// simplification. The tap accepts NO message: what it forwards is a table
// injected when the extension is built, so there is no bridge → tap type here
// because there is no bridge → tap message. That matters because the handshake
// travels over the shared window event target, which the page can also read —
// a page that takes the port would otherwise get to choose what the tap
// matches, and what the tap forwards is what AKA goes on to persist.
// test/tap.test.ts pins it by posting a well-formed command at a running tap
// and asserting nothing about its behaviour moves.
//
// The same shared event target is why the CONSUMER has an obligation the tap
// cannot discharge for it: nothing in a handshake proves it came from the tap
// rather than from page script that forged one. A bridge registers its window
// `message` listener at `document_start`, before any page script has run,
// accepts the FIRST handshake carrying the tag, ignores every later one, and
// drops any message whose source is not this window.

// The handshake tag on the one window.postMessage the tap sends. Everything
// after it travels over a transferred MessagePort, off the shared window
// channel the page can also read.
export const TAP_CHANNEL = 'aka-tap';

// One request shape the tap forwards, as an adapter declares it.
//
// `host` is matched EXACTLY against the parsed URL's host — an endpoint is a
// site's endpoint, not a string that may appear anywhere in a URL. Without it a
// pattern matched against the whole href forwards any origin whose URL merely
// contains the pattern text, in its path or in a query parameter, as though it
// were the site's own traffic. `path` is a RegExp source anchored at the start
// of the path when it is compiled, so a matching substring further along cannot
// reach it.
//
// The build reads these off the adapter registry and injects the host/path
// pairs into the tap bundle. They never travel over a wire.
export interface TapEndpoint {
  host: string;
  path: string;
  kind: 'conversation' | 'account';
}

// Tap → bridge. The only direction there is.
//
// Every exchange the tap OPENS with `request` is closed by exactly one `end`.
// An `error` before that `end` says why the finish is not a clean one — the
// page's call rejected ('aborted'), the tap stopped pulling at its own byte
// ceiling ('truncated'), or the tap itself faulted ('tap_error'). An `error`
// naming an id that never carried a `request` opens nothing and closes nothing:
// it reports a body the tap declined to read ('unparsed_body'), and no `end`
// follows it.
//
// A forwarded request body carries no ceiling and no truncation signal — the
// tap reads it from a clone of what the site itself chose to send. Bounding it
// belongs on this side of the port, where an oversized body can be refused
// rather than half-parsed.
export type TapToPage =
  | { type: 'ready' }
  // What the tap actually managed to patch. `false` on either half means that
  // transport is invisible on this page.
  | { type: 'patched'; fetch: boolean; xhr: boolean }
  | { type: 'request'; id: number; url: string; method: string; body: string | null }
  | { type: 'chunk'; id: number; text: string }
  | { type: 'end'; id: number; status: number; ok: boolean }
  | {
      type: 'error';
      id: number;
      reason: 'unparsed_body' | 'tap_error' | 'truncated' | 'aborted';
    };
