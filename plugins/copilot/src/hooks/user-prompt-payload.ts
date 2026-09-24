// The pure half of the prompt hook: which text an event carries, how durably
// it is recorded, and what the hook says about a scan of it. Split out of the
// entry script so it can be unit-tested WITHOUT importing the entry (whose
// top-level `runHookFailOpen(main)` reads stdin and would block collection
// forever). Same split as ./pre-tool-use-decision.ts.
//
// ONE READER COVERS TWO CLI EVENTS, and they must not be conflated:
//
//  - `userPromptSubmitted` (CLI) / `UserPromptSubmit` (VS Code) carries
//    `prompt`, the text the USER typed.
//  - `userPromptTransformed` (CLI only) carries BOTH: the untransformed
//    `prompt` again, verbatim, and `transformedPrompt`, which wraps it in
//    scaffolding the user did not write — the recorded sample adds a
//    `<current_datetime>` stamp and a `<system_reminder><sql_tables>…` block.
//    So `userPromptSubmitted.prompt` is NOT the whole of what reaches the
//    model, which is the reason the transformed form is worth reading at all.
//
// ONLY THE SUBMITTED EVENT IS REGISTERED IN `hooks.json` TODAY. The transformed
// row stays in the table below on purpose, so wiring it later is a manifest
// edit rather than a code change — and because the reason it is unwired is
// exactly the fact this table records: its payload re-carries `prompt`
// verbatim, so registering both double-counts every prompt.
//
// NOTHING HERE ENFORCES. See `promptDecision`.

import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { uniqueRuleIds } from '@akasecurity/plugin-sdk';

import { exceptionPointer } from '../exception-guidance.ts';
import type { Dialect } from './dialect.ts';
import type { HookEvent } from './event-name.ts';
import type { HookOutput } from './shared.ts';
import { getString } from './shared.ts';

/** Which of the two prompt events a payload is. */
export type PromptEvent = 'submitted' | 'transformed';

export interface PromptCapture {
  event: PromptEvent;
  /** The text to scan. Never empty — an empty field yields `undefined`. */
  text: string;
}

// Which payload field each event's scannable text lives in. Both dialects spell
// the submitted field `prompt`; `transformedPrompt` is the CLI's alone, because
// VS Code fires no counterpart event.
const PROMPT_FIELD: Partial<Record<HookEvent, { event: PromptEvent; field: string }>> = {
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
  eventName: HookEvent | undefined,
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
 * What one prompt scan puts on each of the hook's two channels.
 *
 * Same shape and the same reason as `PreToolUseDecision`: the two dialects do
 * not agree that stdout has a message field on this event, so the text comes
 * back as `notice` where it does not and the caller writes it to stderr.
 */
export interface PromptDecision {
  /** The payload for stdout, or null to write nothing. */
  output: HookOutput | null;
  /** Text for stderr, set only where the dialect's stdout cannot carry it. */
  notice?: string;
}

/**
 * What the hook says about a prompt scan.
 *
 * **NOTHING HERE STOPS A PROMPT, and the wording must never imply it does.**
 * Neither host has a prompt-stop channel this repository has observed. The
 * CLI's `userPromptSubmitted.modifiedPrompt` is listed under "Not measured" in
 * `test/fixtures/cli/README.md`; VS Code's block channel is **exit 2**, and
 * ./shared.ts guarantees no path here exits non-zero and none exits 2 — a
 * guarantee `test/hook-output-shapes.test.ts` pins against CLAUDE.md. Emitting
 * a block the host ignores is worse than emitting none: the user reads an
 * enforcement claim and the prompt reaches the model anyway.
 *
 * So the capture is taken with `rewritable: false`, which resolves a `redact`
 * policy to `settings.redactFallback` INSIDE the runtime — where the recorded
 * `findings.actionTaken` and the ledger read the one answer this function then
 * reports. The hook never escalates for itself.
 *
 * A `block` or `redact` is therefore reported as what actually happened: the
 * value was flagged and recorded, and the prompt went out unchanged. That is a
 * different sentence from the `warn` one, deliberately — a user whose policy
 * says block has to be able to tell that it did not take effect here.
 * `skills/setup/SKILL.md`'s Known limitations carries the same fact.
 *
 * The transformed event never speaks: the submitted one owns the message, and
 * the user's own words are inside both, so a second copy for the same secret is
 * noise.
 *
 * IT TAKES THE DIALECT ONLY TO CHOOSE THE CHANNEL, never to change the words.
 * On VS Code `systemMessage` is a documented top-level key; the Copilot CLI's
 * reference documents no message field on this event, so the same object there
 * is a payload the host drops and the user is told nothing at all.
 */
export function promptDecision(
  event: PromptEvent,
  dialect: Dialect,
  result: Pick<CaptureResult, 'action' | 'findings'> & {
    blockedReferences?: readonly BlockedDetectionRef[] | undefined;
  },
): PromptDecision {
  if (event === 'transformed') return { output: null };
  if (result.findings.length === 0) return { output: null };

  const ruleIds = uniqueRuleIds([...result.findings]);
  const pointer = exceptionPointer(result.blockedReferences);

  let message: string | undefined;
  if (result.action === 'block' || result.action === 'redact') {
    message =
      `AKA flagged sensitive content in this prompt (${ruleIds}) and recorded it. ` +
      'This surface has no confirmed way to stop or rewrite a prompt, so it was sent ' +
      `to the model unchanged — remove the value and resend.${pointer}`;
  } else if (result.action === 'warn') {
    message = `AKA flagged sensitive content in this prompt (${ruleIds}) — sent unchanged.${pointer}`;
  }
  if (message === undefined) return { output: null };

  return dialect === 'cli'
    ? { output: null, notice: message }
    : { output: { systemMessage: message } };
}
