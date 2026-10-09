import { getLoadedRules, redact, registerPack, scan } from '@akasecurity/detections/engine';
import type { ActionTaken } from '@akasecurity/schema';
import { PARSED_DATA } from 'aka:parsed-packs';

// Entry of hooks/engine.js, the detection engine a Claude Code mod imports. A
// mod runs with no Node, so this file and everything it reaches must stay
// free of node: built-ins, require and import(); build/engine.mjs fails the
// build when the output is not.

let registered = false;

/** Registers the bundled packs, parsed with the real Rule schema at build time. */
export function registerBundledPacks(): void {
  for (const pack of PARSED_DATA.packs) registerPack({ id: pack.packId, rules: pack.rules });
  registered = true;
}

/**
 * The action a fresh install enforces for a bundled rule, resolved at build time
 * by the same resolver the hooks use. A rule this build does not know is only
 * ever logged.
 */
export function bundledActionFor(ruleId: string): ActionTaken {
  return PARSED_DATA.actions[ruleId] ?? 'log';
}

/**
 * Builds the prompt rewrite over an action source. A finding whose action is
 * `redact` becomes `[REDACTED:<CATEGORY>]`; anything else, and every prompt that
 * holds a `block`, is returned untouched so the UserPromptSubmit command hook
 * keeps its own verdict. Throws on a fault; the caller must let it propagate.
 */
export function createPromptRedactor(
  actionFor: (ruleId: string) => ActionTaken,
): (text: string) => string {
  return (text) => {
    if (!registered) registerBundledPacks();
    const findings = scan(text, undefined, { eventKind: 'prompt' });
    if (findings.length === 0) return text;
    const actions = findings.map((f) => actionFor(f.ruleId));
    if (actions.includes('block')) return text;
    const redacted = findings.filter((_, i) => actions[i] === 'redact');
    return redacted.length === 0 ? text : redact(text, redacted);
  };
}

/** The prompt rewrite under the bundled packs' default policies. */
export const redactPrompt = createPromptRedactor(bundledActionFor);

export { getLoadedRules, redact, scan };
