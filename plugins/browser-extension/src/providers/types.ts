import type { WebExchange } from '@akasecurity/schema';

import type { WebSourceTool } from '../native-host/protocol.ts';

// Which half of a site's traffic a matched request belongs to. 'conversation'
// is one assistant turn; 'account' is plan/quota, which nothing reads yet.
export type EndpointKind = 'conversation' | 'account';

// One request shape an adapter wants forwarded.
//
// The host is declared SEPARATELY from the path rather than written into one
// pattern, and that separation is the whole point: a pattern tested against a
// whole URL matches any origin that happens to carry the pattern text, in its
// path or in a query parameter. The tap binds the host exactly and anchors the
// path at its start, so neither half can float onto somebody else's traffic.
// `host` must be one of the adapter's own `hostnames`; src/tap-endpoints.ts
// refuses the table otherwise.
export interface ProviderEndpoint {
  readonly host: string;
  readonly path: RegExp;
  readonly kind: EndpointKind;
}

// What an adapter recovered from an outbound request body. Partial by design:
// a field the adapter did not recognise is absent rather than guessed, and
// `requiredPathsSeen` is the adapter's own verdict on whether the body still
// carries the shape it parses — the earliest signal that a site moved.
export interface ParsedRequest {
  prompt?: string;
  model?: string;
  conversationId?: string;
  requiredPathsSeen: boolean;
}

// One assistant turn as an adapter recovered it. The bridge owns the two fields
// left out: `startedAt` (the adapter may know a site-reported time, and the
// bridge stamps the request's own arrival when it does not) and `truncated`,
// which is a fact about the ceilings the bytes crossed rather than about the
// site's payload.
export type WebExchangeSummary = Omit<WebExchange, 'startedAt' | 'truncated'> & {
  startedAt?: string;
};

// The incremental response parser. `push` is called once per forwarded chunk
// and `end` once, after the last one.
export interface ExchangeAssembler {
  push(chunk: string): void;
  // `null` when nothing recognisable was recovered. A summary cannot be
  // half-built — its message id is the natural key the stored row hashes on —
  // so an adapter that found no turn says so rather than inventing one.
  end(): WebExchangeSummary | null;
}

// The one seam a new web provider (Gemini, DeepSeek, T3 Chat, …) implements —
// content.ts is written once, against this interface, and never touches a
// specific site's DOM directly. See providers/registry.ts for how a new
// adapter gets wired in.
//
// The network half below is called only from the isolated-world bridge, always
// inside its try/catch: a method that throws costs that one exchange and is
// counted as a parse failure, and a field that cannot be recovered is left
// undefined rather than thrown over.
export interface ProviderAdapter {
  readonly id: WebSourceTool;
  // The hostnames this adapter drives. Enumerable rather than a matches()
  // predicate so callers can READ the set: resolveAdapter tests membership,
  // and manifest.test.ts derives the grants it checks from the registry
  // instead of a hand-written list that a new adapter would leave stale.
  readonly hostnames: readonly string[];
  // Finds the current prompt composer element, or null if it isn't mounted
  // yet (SPA still loading) or no longer matches after a re-render — callers
  // re-poll rather than caching the result across the composer's lifetime.
  findComposer(): HTMLElement | null;
  // Finds the current send button, or null. content.ts tracks this alongside
  // the composer so an SPA re-render that replaces ONLY the button (leaving
  // the composer node intact) still triggers a listener re-attach — without
  // it, a remounted button would send unwatched.
  findSendButton(): HTMLElement | null;
  extractText(composer: HTMLElement): string;
  // Rewrites the composer to `text` (redact-in-place, before send).
  setText(composer: HTMLElement, text: string): void;
  // Attaches whatever listeners this site needs to notice a send attempt
  // (Enter keydown, a Send-button click, or both) and calls onSubmit with
  // the ORIGINAL event so the caller can preventDefault() it before the
  // site's own handler runs. Returns a cleanup function — the composer gets
  // remounted by the SPA on navigation, so callers re-invoke this per mount.
  watchSubmit(composer: HTMLElement, onSubmit: (event: Event) => void): () => void;
  // Performs the actual send — used to resubmit once the decision has let the
  // (possibly rewritten) text through. Returns whether the send gesture was
  // actually dispatched. Reporting that matters because the interceptor has
  // ALREADY preventDefault()ed the user's own send by this point: an adapter
  // that quietly finds no send button (selector drift) leaves nothing to send
  // the message and nothing to report it, so the text disappears with no
  // banner. Return false instead and the interceptor tells the user.
  // NOTE for implementers: a programmatic click here re-enters the watchSubmit
  // listeners; the interceptor arms a one-shot bypass before calling this so
  // the re-entrant event passes through instead of looping (see interceptor.ts).
  submit(composer: HTMLElement): boolean;

  // NETWORK HALF

  // Which requests this adapter wants to see. The MAIN-world tap's build-time
  // table is generated from exactly these (src/tap-endpoints.ts), so an adapter
  // that declares none is observed on no traffic at all — which is the honest
  // state for a site whose contract has not been surveyed. The bridge reads the
  // same declarations to decide what a forwarded URL IS.
  readonly endpoints: readonly ProviderEndpoint[];

  // The JSON key paths this adapter depends on, named so the bridge can report
  // which one went missing rather than only that parsing failed. `request`
  // entries are recorded when parseRequest reports its shape unmet; `response`
  // entries are resolved as dotted paths against the summary parseStream
  // produced, and one that reads undefined is a drift signal.
  readonly requiredPaths: {
    readonly request: readonly string[];
    readonly response: readonly string[];
  };

  // The exact strings this adapter's parsers switch on — the `case` labels of
  // parseStream's dispatch, the path segments its endpoints anchor on, the
  // discriminator values parseRequest reads. The capture sanitiser preserves a
  // captured value verbatim only when it matches one of these EXACTLY and the
  // detector does not flag it; nothing here is a pattern, a prefix or a
  // substring. Adding one means updating EXPECTED_PROTOCOL_TOKENS in
  // test/helpers/fixture-bar.ts in the same diff.
  readonly protocolTokens: readonly string[];

  // The outbound message. Never throws for a body it does not recognise —
  // it returns what it found, with requiredPathsSeen false.
  parseRequest(body: string): ParsedRequest;

  // A fresh assembler per exchange. Streams arrive in pieces that do not
  // respect event boundaries, so framing is the assembler's business rather
  // than the bridge's.
  parseStream(): ExchangeAssembler;
}
