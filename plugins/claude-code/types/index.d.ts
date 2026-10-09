// The state contract of the aka mod (hooks/mod.ts). It adds no noun to `$`; it
// declares the one named value the display rewrite draws from, so a reload of the
// session redraws it. Read it with `$.state.get`, never write it from a render.

/**
 * What the screen shows for one complete vault pointer, resolved once by the
 * `aka` helper and held for the session. Keyed by the pointer text.
 *
 * `badge` is the masked form (`[scrubbed:...]`); null means the pointer is not
 * to be rewritten at all (no vault consent, or inline reveal is off). `revealed`
 * is the complete replacement for a revealed pointer: undefined until a reveal
 * was asked for, null once the vault declined or the mode is masked. `failedAt`
 * (a `$.clock.now()` time) marks a helper that did not answer, so a redraw does
 * not spawn it again until a retry interval has passed.
 */
export type AkaRevealEntry = {
  badge: string | null;
  revealed?: string | null;
  failedAt?: number;
};

declare module 'claude-code' {
  interface PluginState {
    aka: { reveals: Record<string, AkaRevealEntry> };
  }
}
