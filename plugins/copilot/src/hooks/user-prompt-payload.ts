// The pure half of the prompt hooks: which text an event carries, and what the
// hook should say about a scan of it. Split out of the entry script so it can
// be unit-tested WITHOUT importing the entry (whose top-level `main()` reads
// stdin and would block test collection forever).
//
// ONE SCRIPT COVERS TWO CLI EVENTS, and they must not be conflated:
//
//  - `userPromptSubmitted` (CLI) / `UserPromptSubmit` (VS Code) carries
//    `prompt`, the text the USER typed.
//  - `userPromptTransformed` (CLI only) carries BOTH: the untransformed
//    `prompt` again, and `transformedPrompt`, which wraps it in scaffolding the
//    user did not write — the recorded sample adds a `<current_datetime>` stamp
//    and a `<system_reminder><sql_tables>…</sql_tables></system_reminder>`
//    block. So `userPromptSubmitted.prompt` is NOT the whole of what reaches
//    the model, which is the reason to record the transformed form at all.
//
// Recording the transformed text as a second `prompt` event would double-count
// every clean prompt, since the user's own words are inside it verbatim. It is
// therefore captured at `persist: 'with-findings'` — it lands only when the
// TRANSFORMATION introduced something the submitted text did not — and it emits
// nothing: the submitted event owns the user-facing message, and a second copy
// of it for the same secret is noise. See `promptPersist` below.

import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { uniqueRuleIds } from '@akasecurity/plugin-sdk';

import { exceptionPointer } from '../exception-guidance.ts';
import type { HookEventName } from './event-name.ts';
import type { HookOutput } from './shared.ts';
import { getString } from './shared.ts';

/** Which of the two prompt events a payload is. */
export type PromptEvent = 'submitted' | 'transformed';

export interface PromptCapture {
  event: PromptEvent;
  /** The text to scan. Never empty — an empty field yields `undefined`. */
  text: string;
}

// Which payload field each event's scannable text lives in. Both dialects
// spell the submitted field `prompt`; `transformedPrompt` is the CLI's alone,
// because VS Code fires no counterpart event.
const PROMPT_FIELD: Partial<Record<HookEventName, { event: PromptEvent; field: string }>> = {
  userPromptSubmitted: { event: 'submitted', field: 'prompt' },
  UserPromptSubmit: { event: 'submitted', field: 'prompt' },
  userPromptTransformed: { event: 'transformed', field: 'transformedPrompt' },
};

/**
 * The text this event carries, or `undefined` when there is nothing to scan.
 *
 * Keyed on the ARGV event name rather than on which fields the payload happens
 * to carry, which is the whole reason it can tell the two apart at all:
 * `userPromptTransformed` carries `prompt` as well, so a reader that looked for
 * `prompt` first would scan the untransformed text twice and never see the
 * scaffolding.
 */
export function readPromptCapture(
  eventName: HookEventName | undefined,
  payload: Record<string, unknown> | null,
): PromptCapture | undefined {
  if (eventName === undefined || payload === null) return undefined;
  const spec = PROMPT_FIELD[eventName];
  if (spec === undefined) return undefined;
  const text = getString(payload, spec.field);
  if (text === undefined || text === '') return undefined;
  return { event: spec.event, text };
}

/**
 * How durably an event's text is recorded.
 *
 * A submitted prompt is always recorded — it is the corpus every prompt surface
 * reads. A transformed one is recorded only when it carries a finding, because
 * the user's own words are already inside it and persisting both would
 * double-count every clean turn.
 */
export function promptPersist(event: PromptEvent): 'always' | 'with-findings' {
  return event === 'submitted' ? 'always' : 'with-findings';
}

/**
 * The message the hook prints for a scan outcome, or `undefined` for silence.
 *
 * **NOTHING HERE STOPS A PROMPT, and the wording must never imply it does.**
 * Neither host has a prompt-stop channel this repository has observed: the
 * CLI's `modifiedPrompt` is documented but unconfirmed from a command hook
 * (`test/fixtures/cli/README.md`, "Not measured"), and VS Code's block channel
 * on `UserPromptSubmit` has not been driven at all
 * (`test/fixtures/vscode-provisional/README.md`). Emitting a block that the
 * host silently ignores is worse than emitting none: the user reads an
 * enforcement claim and the prompt goes to the model anyway.
 *
 * So a `block` or `redact` policy is reported as what actually happened — the
 * value was flagged and recorded, and the prompt went out unchanged — which is
 * a different sentence from the `warn` one and deliberately so. A user whose
 * policy says block must be able to tell that it did not take effect here.
 * `skills/setup/SKILL.md`'s Known limitations carries the same fact.
 *
 * IT TAKES NO DIALECT, unlike `decidePreToolUse`. `systemMessage` is a
 * top-level key both hosts accept and neither has a prompt channel this
 * adapter can shape differently, so there is nothing for a dialect to select
 * between. Taking one and ignoring it would read as a per-host difference that
 * does not exist; when a host grows a real channel, adding the parameter is the
 * edit that surfaces every call site.
 */
export function promptEmitPayload(
  event: PromptEvent,
  result: Pick<CaptureResult, 'action' | 'findings'> & {
    blockedReferences?: readonly BlockedDetectionRef[] | undefined;
  },
): HookOutput | undefined {
  // The transformed event never speaks: the submitted one owns the message,
  // and the user's own words are inside both.
  if (event === 'transformed') return undefined;
  if (result.findings.length === 0) return undefined;

  const ruleIds = uniqueRuleIds(result.findings);
  const pointer = exceptionPointer(result.blockedReferences);

  if (result.action === 'block' || result.action === 'redact') {
    return {
      systemMessage:
        `AKA flagged sensitive content in this prompt (${ruleIds}) and recorded it. ` +
        'This surface has no confirmed way to stop or rewrite a prompt, so it was sent ' +
        `to the model unchanged — remove the value and resend.${pointer}`,
    };
  }
  if (result.action === 'warn') {
    return {
      systemMessage: `AKA flagged sensitive content in this prompt (${ruleIds}) — sent unchanged.${pointer}`,
    };
  }
  return undefined;
}
