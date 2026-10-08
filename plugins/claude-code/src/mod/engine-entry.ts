import { getLoadedRules, redact, registerPack, scan } from '@akasecurity/detections/engine';
import { PARSED_PACKS } from 'aka:parsed-packs';

// Entry of hooks/engine.js, the detection engine a Claude Code mod imports. A
// mod runs with no Node, so this file and everything it reaches must stay
// free of node: built-ins, require and import(); build/engine.mjs fails the
// build when the output is not.

/** Registers the bundled packs, parsed with the real Rule schema at build time. */
export function registerBundledPacks(): void {
  for (const pack of PARSED_PACKS) registerPack({ id: pack.packId, rules: pack.rules });
}

export { getLoadedRules, redact, scan };
