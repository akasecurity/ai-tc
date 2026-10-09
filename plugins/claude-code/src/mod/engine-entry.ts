import { getLoadedRules, redact, registerPack, scan } from '@akasecurity/detections/engine';
import type { ActionTaken, Rule } from '@akasecurity/schema';
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

const ACTIONS: ReadonlySet<string> = new Set(['warn', 'redact', 'block', 'allow', 'log']);

/**
 * The policy a snapshot file resolves to, as lookups. Built by
 * {@link parseModPolicy}; the shape on disk is the ModPolicySnapshot contract in
 * @akasecurity/schema.
 */
export interface ModPolicy {
  /** The complete effective ruleset; absent means the bundled packs. */
  rules: Rule[] | undefined;
  ruleActions: ReadonlyMap<string, ActionTaken>;
  categoryActions: ReadonlyMap<string, ActionTaken>;
  exceptionRuleIds: ReadonlySet<string>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function actionMap(value: unknown): Map<string, ActionTaken> | null {
  if (!isRecord(value)) return null;
  const out = new Map<string, ActionTaken>();
  for (const [key, action] of Object.entries(value)) {
    if (typeof action !== 'string' || !ACTIONS.has(action)) return null;
    out.set(key, action as ActionTaken);
  }
  return out;
}

/**
 * Reads a snapshot file's text. A structural check only: the file is written by
 * `aka` through the Zod contract, and this runs where zod does not, so it checks
 * the shape the lookups below depend on and nothing more. Returns null for
 * anything it cannot use, and the caller falls back to the bundled defaults.
 */
export function parseModPolicy(text: string): ModPolicy | null {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isRecord(raw) || raw.version !== 1) return null;
  const ruleActions = actionMap(raw.ruleActions);
  const categoryActions = actionMap(raw.categoryActions);
  if (ruleActions === null || categoryActions === null) return null;
  const excepted = raw.exceptionRuleIds;
  if (!Array.isArray(excepted) || !excepted.every((id) => typeof id === 'string')) return null;
  let rules: Rule[] | undefined;
  if (raw.rules !== undefined) {
    if (!Array.isArray(raw.rules)) return null;
    const usable = raw.rules.every(
      (rule: unknown) =>
        isRecord(rule) &&
        typeof rule.id === 'string' &&
        typeof rule.category === 'string' &&
        isRecord(rule.matcher) &&
        typeof rule.matcher.type === 'string',
    );
    if (!usable) return null;
    rules = raw.rules as Rule[];
  }
  return { rules, ruleActions, categoryActions, exceptionRuleIds: new Set(excepted) };
}

/**
 * Rewrites a prompt over an action source. A finding whose action is `redact`
 * becomes `[REDACTED:<CATEGORY>]`; anything else, and every prompt that holds a
 * `block`, is returned untouched so the UserPromptSubmit command hook keeps its
 * own verdict. `rules` replaces the bundled packs as the ruleset when given.
 * A finding of a rule in `excepted` is never redacted here: honouring a grant
 * means matching a keyed fingerprint and consuming a use, which only the hook
 * does. Throws on a fault; the caller must let it propagate.
 */
export function createPromptRedactor(
  actionFor: (ruleId: string, category: string) => ActionTaken,
  options: { rules?: Rule[] | undefined; excepted?: ReadonlySet<string> | undefined } = {},
): (text: string) => string {
  return (text) => {
    if (options.rules === undefined && !registered) registerBundledPacks();
    const findings = scan(text, options.rules, { eventKind: 'prompt' });
    if (findings.length === 0) return text;
    const actions = findings.map((f) => {
      const action = actionFor(f.ruleId, f.category);
      return action === 'redact' && options.excepted?.has(f.ruleId) === true ? 'allow' : action;
    });
    if (actions.includes('block')) return text;
    const redacted = findings.filter((_, i) => actions[i] === 'redact');
    return redacted.length === 0 ? text : redact(text, redacted);
  };
}

/**
 * The prompt rewrite under a user's policy, or under the bundled packs'
 * default policies when there is none. The policy reads as the hook's resolver
 * reads a bundle: a rule's own action, then its category's, then `log`.
 */
export function redactPromptWith(text: string, policy: ModPolicy | null): string {
  if (policy === null) return createPromptRedactor((ruleId) => bundledActionFor(ruleId))(text);
  return createPromptRedactor(
    (ruleId, category) =>
      policy.ruleActions.get(ruleId) ?? policy.categoryActions.get(category) ?? 'log',
    { rules: policy.rules, excepted: policy.exceptionRuleIds },
  )(text);
}

/** The prompt rewrite under the bundled packs' default policies. */
export const redactPrompt = (text: string): string => redactPromptWith(text, null);

export { getLoadedRules, redact, scan };
