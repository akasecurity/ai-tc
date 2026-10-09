import { getLoadedRules, redact, registerPack, scan } from '@akasecurity/detections/engine';
import type { ActionTaken, Rule } from '@akasecurity/schema';
import { PARSED_DATA } from 'aka:parsed-packs';

import type { RegionState } from '../display/regions.ts';
import { advanceRegions } from '../display/regions.ts';
import {
  fieldText,
  inputEventKind,
  inputFilePath,
  scannableInputFields,
} from '../hooks/pre-tool-use-fields.ts';

// Entry of hooks/engine.js, the detection engine a Claude Code mod imports. A
// mod runs with no Node, so this file and everything it reaches must stay
// free of node: built-ins, require and import(); build/engine.mjs fails the
// build when the output is not.

let registered = false;

// The vault pointer's pattern, resolved at build time from the one definition in
// @akasecurity/schema (importing it here would pull zod into the module). A
// prompt that already holds a pointer is scanned with that pointer blanked, as
// the hooks' shield does, so a pointer is never re-tokenized.
let pointerScanner: RegExp | undefined;
function pointerSpans(text: string): { start: number; end: number }[] {
  pointerScanner ??= new RegExp(PARSED_DATA.pointerPattern, 'g');
  return Array.from(text.matchAll(pointerScanner), (m) => ({
    start: m.index,
    end: m.index + m[0].length,
  }));
}

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
 * What a prompt rewrite would do: `text` is the one-way rewrite (the prompt
 * itself when nothing is to be redacted) and `values` the matched values being
 * removed, which the caller checks a rewrite from elsewhere against.
 */
export interface PromptPlan {
  text: string;
  values: string[];
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
export function createPromptPlanner(
  actionFor: (ruleId: string, category: string) => ActionTaken,
  options: { rules?: Rule[] | undefined; excepted?: ReadonlySet<string> | undefined } = {},
): (text: string, eventKind?: 'prompt' | 'response') => PromptPlan {
  return (text, eventKind = 'prompt') => {
    if (options.rules === undefined && !registered) registerBundledPacks();
    const spans = pointerSpans(text);
    let scanned = text;
    for (const s of spans) {
      scanned = scanned.slice(0, s.start) + ' '.repeat(s.end - s.start) + scanned.slice(s.end);
    }
    const findings = scan(scanned, options.rules, { eventKind }).filter(
      (f) => !spans.some((s) => f.span.start < s.end && f.span.end > s.start),
    );
    if (findings.length === 0) return { text, values: [] };
    const actions = findings.map((f) => {
      const action = actionFor(f.ruleId, f.category);
      return action === 'redact' && options.excepted?.has(f.ruleId) === true ? 'allow' : action;
    });
    if (actions.includes('block')) return { text, values: [] };
    const redacted = findings.filter((_, i) => actions[i] === 'redact');
    if (redacted.length === 0) return { text, values: [] };
    return { text: redact(text, redacted), values: redacted.map((f) => f.rawMatch) };
  };
}

/** {@link createPromptPlanner}, reduced to the one-way rewritten text. */
export function createPromptRedactor(
  actionFor: (ruleId: string, category: string) => ActionTaken,
  options: { rules?: Rule[] | undefined; excepted?: ReadonlySet<string> | undefined } = {},
): (text: string) => string {
  const plan = createPromptPlanner(actionFor, options);
  return (text) => plan(text).text;
}

/**
 * The prompt rewrite under a user's policy, or under the bundled packs'
 * default policies when there is none. The policy reads as the hook's resolver
 * reads a bundle: a rule's own action, then its category's, then `log`.
 */
export function planPromptWith(text: string, policy: ModPolicy | null): PromptPlan {
  if (policy === null) return createPromptPlanner((ruleId) => bundledActionFor(ruleId))(text);
  return createPromptPlanner(
    (ruleId, category) =>
      policy.ruleActions.get(ruleId) ?? policy.categoryActions.get(category) ?? 'log',
    { rules: policy.rules, excepted: policy.exceptionRuleIds },
  )(text);
}

/**
 * The rewrite of one text block of a conversation row (an attachment, a memory,
 * a summary), under the same policy as a prompt. Scanned as a `response`, the
 * event kind the helper records it under, so a rule scoped to an event kind
 * applies the same on both sides.
 */
export function planRowWith(text: string, policy: ModPolicy | null): PromptPlan {
  if (policy === null)
    return createPromptPlanner((ruleId) => bundledActionFor(ruleId))(text, 'response');
  return createPromptPlanner(
    (ruleId, category) =>
      policy.ruleActions.get(ruleId) ?? policy.categoryActions.get(category) ?? 'log',
    { rules: policy.rules, excepted: policy.exceptionRuleIds },
  )(text, 'response');
}

/** {@link planPromptWith}, reduced to the one-way rewritten text. */
export function redactPromptWith(text: string, policy: ModPolicy | null): string {
  return planPromptWith(text, policy).text;
}

/** The prompt rewrite under the bundled packs' default policies. */
export const redactPrompt = (text: string): string => redactPromptWith(text, null);

/** What the display rewrite wants for one complete pointer it met. */
export interface PointerWant {
  token: string;
  /** In a code, quote or capped position: only the masked badge may be drawn. */
  shielded: boolean;
}

/**
 * The text a screen shows for `text`: each COMPLETE vault pointer swapped for
 * what `draw` answers (the revealed value, or the masked badge), a pointer `draw`
 * has no answer for (null) left as written. A trailing partial pointer or a
 * garbled one never matches the grammar and stays plain text. The markdown
 * regions are the MessageDisplay hook's own (src/display/regions.ts): a pointer
 * in a fenced block, an inline code span or a quoted line is `shielded`, and so
 * is any past the per-message reveal cap, counted over what `draw` returns when
 * it was handed `shielded: false` and answered `revealed: true`.
 *
 * Pure and synchronous; it spawns and reads nothing, so it is cheap on every
 * redraw. `wanted` lists the pointers `draw` could not answer, for the caller to
 * resolve once each.
 */
export function revealPointers(
  text: string,
  draw: (want: PointerWant) => { text: string; revealed: boolean } | null,
  cap: number = PARSED_DATA.revealCap,
): { text: string; wanted: PointerWant[] } {
  pointerScanner ??= new RegExp(PARSED_DATA.pointerPattern, 'g');
  const state: RegionState = {
    fence: null,
    tickOpen: false,
    lineQuoted: false,
    lineSeen: false,
    lineIndent: 0,
  };
  const wanted: PointerWant[] = [];
  let out = '';
  let pos = 0;
  let revealed = 0;
  for (const match of text.matchAll(pointerScanner)) {
    const literal = text.slice(pos, match.index);
    advanceRegions(state, literal);
    out += literal;
    const token = match[0];
    const shielded = state.fence !== null || state.tickOpen || state.lineQuoted || revealed >= cap;
    const want: PointerWant = { token, shielded };
    const drawn = draw(want);
    let shown = token;
    if (drawn === null) {
      wanted.push(want);
    } else {
      shown = drawn.text;
      if (drawn.revealed) revealed += 1;
    }
    advanceRegions(state, shown);
    out += shown;
    pos = match.index + token.length;
  }
  out += text.slice(pos);
  return { text: out, wanted };
}

/**
 * Whether a tool call holds anything the tool.call mod would act on, so that only
 * such a call is handed to the helper: a vault pointer in a field PreToolUse
 * scans, or a value its policy says to redact or block. The fields are the
 * command hook's own (pre-tool-use-fields.ts), so the two read a call the same
 * way. A call this passes over is not left unchecked: PreToolUse runs after the
 * mod and applies today's rules to it. Throws on a fault; the caller lets it
 * propagate.
 */
export function toolCallNeedsHelper(
  toolName: string,
  toolInput: Record<string, unknown>,
  policy: ModPolicy | null,
): boolean {
  const fields = scannableInputFields(toolName, toolInput);
  if (fields.length === 0) return false;
  if (policy?.rules === undefined && !registered) registerBundledPacks();
  const eventKind = inputEventKind(toolName);
  const filePath = inputFilePath(toolInput);
  const actionFor = (ruleId: string, category: string): ActionTaken =>
    policy === null
      ? bundledActionFor(ruleId)
      : (policy.ruleActions.get(ruleId) ?? policy.categoryActions.get(category) ?? 'log');
  for (const spec of fields) {
    const text = fieldText(spec, toolInput);
    if (text === undefined || text === '') continue;
    if (pointerSpans(text).length > 0) return true;
    const findings = scan(text, policy?.rules, {
      eventKind,
      ...(filePath === undefined ? {} : { filePath }),
    });
    for (const f of findings) {
      const action = actionFor(f.ruleId, f.category);
      if (action !== 'redact' && action !== 'block') continue;
      // A rule with an active exception is the hook's to honour: matching a
      // keyed fingerprint and consuming a use happen only there.
      if (policy?.exceptionRuleIds.has(f.ruleId) === true) continue;
      return true;
    }
  }
  return false;
}

export { getLoadedRules, redact, scan };
