/**
 * Provider resolution for Cursor sessions.
 *
 * Like `provider-copilot.ts` and unlike the other three resolvers, this reads
 * NO environment: Cursor publishes no variable naming the backend a session
 * talks to. A Cursor session reaches whichever model the editor's own model
 * picker selected, through Cursor's endpoint, so this answers `'unknown'`,
 * unconditionally — recording a vendor here would be a fabricated per-session
 * fact that cost attribution would then trust.
 *
 * Cursor does stamp the selected `model` on every hook payload, and the Cursor
 * plugin records it on each capture's metadata. It is not mapped onto a backend
 * here: a `claude-…` model under Cursor is not an Anthropic-direct call, so
 * there is deliberately no `cursorProviderFromModelId`.
 */

/** Provider backend a Cursor session talks to, as far as this build can tell. */
export type CursorProvider = 'unknown';

/** Whatever a Cursor hook can say about its backend, which today is nothing. */
export interface ResolvedCursorProvider {
  provider: CursorProvider;
  /** Never set today; present so the shape matches its siblings. */
  gatewayHost?: string;
}

/** Resolve the provider for a Cursor session: always `'unknown'`. */
export function resolveCursorProvider(): ResolvedCursorProvider {
  return { provider: 'unknown' };
}
