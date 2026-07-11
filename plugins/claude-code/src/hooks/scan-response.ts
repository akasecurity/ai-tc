// The PostToolUse per-field scan/rewrite loop, extracted from the hook entry
// so it can be unit-tested (hook entry modules run main() on import and hang
// vitest collection). Pure orchestration: the caller owns the runtime and
// hands in a capture function; this module owns which fields get rewritten,
// how findings are bucketed per action, and which ledger refs belong to which
// action — the exact logic that regressions hide in (banner action collapse,
// ref/action mismatches, warn suppression).
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { uniqueRuleIds } from '@akasecurity/plugin-sdk';

import { withheldBanner, withheldToolText } from '../exception-guidance.ts';
import type { ScannableResponseField } from './tool-response.ts';
import { replaceResponseField } from './tool-response.ts';

export interface ResponseScanOutcome {
  /** The response with every flagged field rewritten (=== input when clean). */
  updated: unknown;
  withheldFindings: { ruleId: string }[];
  redactedFindings: { ruleId: string }[];
  warnedFindings: { ruleId: string }[];
  // Ledger refs kept per action: a 'withheld' banner must never carry a
  // merely-redacted value's reference — approving it would except the wrong
  // value (pre-tool-use keeps the same split).
  blockedReferences: BlockedDetectionRef[];
  redactedReferences: BlockedDetectionRef[];
}

export async function scanResponseFields(
  toolName: string,
  response: unknown,
  fields: ScannableResponseField[],
  capture: (text: string) => Promise<CaptureResult>,
): Promise<ResponseScanOutcome> {
  const outcome: ResponseScanOutcome = {
    updated: response,
    withheldFindings: [],
    redactedFindings: [],
    warnedFindings: [],
    blockedReferences: [],
    redactedReferences: [],
  };

  for (const field of fields) {
    const result = await capture(field.text);
    if (result.findings.length === 0) continue;

    if (result.action === 'block') {
      // Can't un-run the tool; withhold the flagged field from the model instead
      outcome.updated = replaceResponseField(
        outcome.updated,
        field.path,
        withheldToolText(toolName, uniqueRuleIds(result.findings), field.path.join('.')),
      );
      outcome.withheldFindings.push(...result.findings);
      if (result.blockedReferences) outcome.blockedReferences.push(...result.blockedReferences);
    } else if (result.action === 'redact' && result.text !== null) {
      outcome.updated = replaceResponseField(outcome.updated, field.path, result.text);
      outcome.redactedFindings.push(...result.findings);
      if (result.blockedReferences) outcome.redactedReferences.push(...result.blockedReferences);
    } else if (result.action === 'warn') {
      outcome.warnedFindings.push(...result.findings);
    }
  }

  return outcome;
}

/**
 * The single JSON object the hook should emit for a scan outcome, or
 * undefined for "no opinion" (nothing flagged). Extracted so the emit
 * decision — action label, per-action rule lines, which ledger ref the
 * banner's approve command carries — is unit-testable (the hook entry runs
 * main() on import and cannot be imported by tests).
 */
export function responseEmitPayload(toolName: string, outcome: ResponseScanOutcome): unknown {
  const { withheldFindings, redactedFindings, warnedFindings } = outcome;
  if (withheldFindings.length > 0 || redactedFindings.length > 0) {
    const action = withheldFindings.length > 0 ? 'withheld' : 'redacted';
    return {
      hookSpecificOutput: {
        hookEventName: 'PostToolUse',
        updatedToolOutput: outcome.updated,
      },
      // The approve pointer stays OUT of the model-visible replacement text:
      // it is the user's audited escape hatch, not something to nudge an
      // agent toward. Ref picked from the action the banner names.
      systemMessage: withheldBanner({
        toolName,
        action,
        withheldRuleIds: withheldFindings.length > 0 ? uniqueRuleIds(withheldFindings) : undefined,
        redactedRuleIds: redactedFindings.length > 0 ? uniqueRuleIds(redactedFindings) : undefined,
        warnedRuleIds: warnedFindings.length > 0 ? uniqueRuleIds(warnedFindings) : undefined,
        blockedRef:
          action === 'withheld' ? outcome.blockedReferences[0] : outcome.redactedReferences[0],
      }),
    };
  }
  if (warnedFindings.length > 0) {
    return {
      systemMessage: `AKA flagged sensitive content in ${toolName} output (${uniqueRuleIds(warnedFindings)}).`,
    };
  }
  return undefined;
}
