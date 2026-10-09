// The state contract of the aka mod (hooks/mod.ts). It adds no noun to `$`; it
// declares the one named value the display rewrite subscribes to, so that a
// resolved pointer redraws the messages that show it. Read it with `$.state.get`,
// never write it from a render.

/**
 * `$.state` is readable by every installed plugin, so nothing a vault holds may
 * be written to it. This is a bare counter: the mod bumps it each time a helper
 * run settles, and a render hook reads it only to be drawn again. What the screen
 * shows for a pointer (the badge and any revealed value) is held in the mod's
 * own module memory and never reaches `$.state`.
 */
declare module 'claude-code' {
  interface PluginState {
    aka: { reveals: number };
  }
}
