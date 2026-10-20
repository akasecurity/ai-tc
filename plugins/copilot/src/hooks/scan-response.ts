// The PostToolUse per-field scan loop and the two channels it reports on,
// extracted from the hook entry so both unit-test without a hook process.
//
// ─── THIS PATH SCANS AND RECORDS. IT DOES NOT ENFORCE. ───────────────────────
//
// Neither host has a result channel this repository has confirmed:
//
//  - **Copilot CLI (and cloud).** `postToolUse.modifiedResult` is DOCUMENTED
//    and listed under "Not measured" in `test/fixtures/cli/README.md` — never
//    observed replacing what the model sees.
//  - **VS Code agent mode.** Its only lever on a result is
//    `{"decision":"block"}`, and a live VS Code 1.141.0 session drove the
//    four events (`test/fixtures/vscode/plugin-load-1.141/`) but never a block
//    or a flagged result.
//
// The tool has ALREADY RUN by the time this event fires, so what is at stake is
// not whether the command executed but whether its output reaches the model.
// Emitting a withhold on an unconfirmed channel would record an enforcement
// that may not have happened: the ledger would say the value never reached the
// model while the host quietly passed the result through. `rewritable: false`
// on every capture here is what stops that — a `redact` policy resolves to
// `settings.redactFallback` inside the RUNTIME, so the emitted message, the
// recorded `findings.actionTaken` and the ledger read one answer, and this
// module never escalates for itself.
//
// So every sentence `responseDecision` builds says what AKA DID — flagged it,
// recorded it — and states plainly that the output reached the model. It must
// never claim a withhold, a redaction, or that anything "never reached" it.
// `../exception-guidance.ts`'s `withheldBanner` and `withheldToolText` are
// deliberately NOT used here for exactly that reason: both assert the flagged
// value never reached the model, which on this host would be false.
//
// Recording a result-rewrite here means first RECORDING that the channel works.
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { uniqueRuleIds } from '@akasecurity/plugin-sdk';

import {
  exceptionPointer,
  unscannedPastWalkLimitsMessage,
  unscannedTooLargeMessage,
  unscannedWorkerUnavailableMessage,
} from '../exception-guidance.ts';
import type { Dialect } from './dialect.ts';
import type { HookOutput } from './shared.ts';
import type { ResponseFields } from './tool-response.ts';

/**
 * What one tool result's scan found.
 *
 * The three finding lists are kept APART rather than merged, because the
 * sentence each produces is different: a `block` and a `redact` are policies
 * that could not be carried out here and have to be reported as such, while a
 * `warn` is a policy that was carried out exactly as configured. One merged
 * list would render them all as the strongest label present.
 */
export interface ResponseScanOutcome {
  /** Findings whose policy resolved to `block` — recorded, never withheld. */
  blockedFindings: { ruleId: string }[];
  /** Findings whose policy resolved to `redact` — recorded, never masked. */
  redactedFindings: { ruleId: string }[];
  /** Findings whose policy resolved to `warn`, which IS what happened. */
  warnedFindings: { ruleId: string }[];
  references: BlockedDetectionRef[];
  /**
   * Every path that was SCANNED, finding or not.
   *
   * Kept so a caller can tell "scanned and found nothing" from "there was
   * nothing to scan" — two states that produce the same silence and mean
   * opposite things about whether this hook is working.
   */
  scannedPaths: string[][];
  toolName: string;
  /**
   * How many fields' scans FINISHED. Kept beside `unscanned` so the message can
   * tell a result nothing was checked in from one that was checked only in part.
   */
  completedScans: number;
  /**
   * True when some of the result was NOT scanned: a field whose bounded scan
   * did not finish (`timedOut`), or text the reader's walk bounds left out
   * (`walkTruncated`). Such a result has no findings from the part nobody
   * checked, and must never read as clean.
   */
  unscanned: boolean;
  /** A field's bounded scan ran out of time (`scanIncomplete: 'timeout'`). */
  timedOut: boolean;
  /**
   * A field's bounded scan found no worker able to run it (`scanIncomplete:
   * 'unavailable'`). Kept apart from `timedOut` because the advice differs: a
   * slow scan is about the size of the result, a missing worker is an install
   * fault no smaller result fixes.
   */
  workerUnavailable: boolean;
  /**
   * The reader's walk bounds left text out (`ResponseFields.truncated`). Kept
   * apart from `timedOut` because the two say different things to the user: one
   * ran out of time, the other never collected the text at all.
   */
  walkTruncated: boolean;
}

/**
 * Scan each field of a tool result through the injected capture.
 *
 * `capture` is a parameter rather than a runtime this module builds, which is
 * what keeps the module pure and drivable without a store.
 */
export async function scanResponseFields(
  toolName: string,
  collected: ResponseFields,
  capture: (text: string) => Promise<CaptureResult>,
): Promise<ResponseScanOutcome> {
  const outcome: ResponseScanOutcome = {
    blockedFindings: [],
    redactedFindings: [],
    warnedFindings: [],
    references: [],
    scannedPaths: [],
    toolName,
    completedScans: 0,
    unscanned: collected.truncated,
    timedOut: false,
    workerUnavailable: false,
    walkTruncated: collected.truncated,
  };

  for (const field of collected.fields) {
    outcome.scannedPaths.push([...field.path]);
    const result = await capture(field.text);
    // Read FIRST. A field too large to scan within the hook's deadline comes
    // back as `block` with NO findings, which the check below would skip as
    // clean. Nothing is refused here — the output has already reached the
    // model — but the field is reported as unscanned rather than as clean.
    if (result.scanIncomplete !== undefined) {
      outcome.unscanned = true;
      if (result.scanIncomplete === 'unavailable') outcome.workerUnavailable = true;
      else outcome.timedOut = true;
      continue;
    }
    outcome.completedScans += 1;
    if (result.findings.length === 0) continue;

    if (result.action === 'block') {
      outcome.blockedFindings.push(...result.findings);
    } else if (result.action === 'redact') {
      outcome.redactedFindings.push(...result.findings);
    } else if (result.action === 'warn') {
      outcome.warnedFindings.push(...result.findings);
    } else {
      // `log` and `allow` record the finding and tell the user nothing: there
      // is no policy outcome to report, so they contribute to no list.
      continue;
    }
    if (result.blockedReferences) outcome.references.push(...result.blockedReferences);
  }

  return outcome;
}

/**
 * What one response scan puts on each of the hook's two channels.
 *
 * Same shape and the same reason as `PreToolUseDecision` and `PromptDecision`:
 * the CLI's `postToolUse` output has no message field, so the text comes back
 * as `notice` for stderr there and rides stdout under VS Code.
 */
export interface ResponseDecision {
  /** The payload for stdout, or null to write nothing. */
  output: HookOutput | null;
  /** Text for stderr, set only where the dialect's stdout cannot carry it. */
  notice?: string;
}

/**
 * The message for a scanned result, or silence.
 *
 * NO `modifiedResult` AND NO `decision: 'block'` — see the module header. The
 * only thing this can return on stdout is VS Code's bare `systemMessage`, which
 * carries no verdict at all.
 *
 * A result some of which was NOT scanned (`outcome.unscanned`) is reported as
 * such, after any findings from the part that was, and never as clean.
 *
 * The sentence is built from what was RESOLVED, so a `warn` (the shipped
 * `redactFallback`, and therefore the common case) reads as the policy working
 * while a `block` or `redact` reads as a policy this surface could not carry
 * out. A user whose policy says block has to be able to tell the difference,
 * which is the whole reason the three lists above are not merged.
 */
export function responseDecision(dialect: Dialect, outcome: ResponseScanOutcome): ResponseDecision {
  const unenforced = [...outcome.blockedFindings, ...outcome.redactedFindings];
  const pointer = exceptionPointer(outcome.references);

  let message: string | undefined;
  if (unenforced.length > 0) {
    const also =
      outcome.warnedFindings.length > 0
        ? ` Also flagged (warn): ${uniqueRuleIds(outcome.warnedFindings)}.`
        : '';
    message =
      `AKA flagged sensitive content in the ${outcome.toolName} result ` +
      `(${uniqueRuleIds(unenforced)}) and recorded it. This surface has no confirmed way ` +
      `to withhold or rewrite a tool result, so the output reached the model ` +
      `unchanged.${also}${pointer}`;
  } else if (outcome.warnedFindings.length > 0) {
    message =
      `AKA flagged sensitive content in the ${outcome.toolName} result ` +
      `(${uniqueRuleIds(outcome.warnedFindings)}) — the output reached the model ` +
      `unchanged.${pointer}`;
  }
  const delivered = 'the output already reached the model unchanged';
  // Scoped to the part that went unchecked whenever any field did finish, or
  // whenever the two causes below split the unchecked fields between them, so
  // a sentence never claims "nothing in it was checked" of the whole result
  // beside findings from, or a different cause for, another part.
  const subject =
    outcome.completedScans > 0 || (outcome.timedOut && outcome.workerUnavailable)
      ? `part of the ${outcome.toolName} result`
      : `${outcome.toolName} result`;
  // Each cause is said once, however many fields it cost.
  if (outcome.timedOut) {
    const unscanned = unscannedTooLargeMessage(subject, delivered);
    message = message === undefined ? unscanned : `${message} ${unscanned}`;
  }
  if (outcome.workerUnavailable) {
    const unscanned = unscannedWorkerUnavailableMessage(subject, delivered);
    message = message === undefined ? unscanned : `${message} ${unscanned}`;
  }
  if (outcome.walkTruncated) {
    const unscanned = unscannedPastWalkLimitsMessage(`${outcome.toolName} result`, delivered);
    message = message === undefined ? unscanned : `${message} ${unscanned}`;
  }
  if (message === undefined) return { output: null };

  return dialect === 'cli'
    ? { output: null, notice: message }
    : { output: { systemMessage: message } };
}
