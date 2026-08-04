import type { WebSourceTool } from '../native-host/protocol.ts';

// The one seam a new web provider (Gemini, DeepSeek, T3 Chat, …) implements —
// content.ts is written once, against this interface, and never touches a
// specific site's DOM directly. See providers/registry.ts for how a new
// adapter gets wired in.
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
  // (possibly rewritten) text through. NOTE for implementers: a programmatic
  // click here re-enters the watchSubmit listeners; the interceptor arms a
  // one-shot bypass before calling this so the re-entrant event passes
  // through instead of looping (see interceptor.ts).
  submit(composer: HTMLElement): void;
}
