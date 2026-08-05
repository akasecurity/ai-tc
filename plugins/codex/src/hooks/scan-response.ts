// The PostToolUse per-field scan/rewrite loop, extracted from the hook entry
// so it can be unit-tested (hook entry modules run main() on import and hang
// vitest collection). `scanResponseFields` is pure orchestration, identical to
// plugins/claude-code/src/hooks/scan-response.ts.
//
// `responseEmitPayload` DIVERGES from the Claude Code sibling in one real,
// load-bearing way: Codex's PostToolUse has no `updatedToolOutput` field to
// splice a partially-redacted value back into the tool result (confirmed —
// Agent Guard's plugin README: Codex "does not expose that Claude field").
// Codex instead offers a coarser, whole-result mechanism: `{"decision":"block",
// "reason":"..."}` on PostToolUse replaces the ENTIRE tool result with `reason`
// and continues the model from there (developers.openai.com/codex/hooks).
// There is no partial field-level splice, so a `redact` outcome — which on
// Claude Code masks matched spans IN PLACE while leaving the rest of the
// output visible — cannot be replicated on Codex without risking the
// unmasked remainder leaking anyway. Rather than silently under-protect,
// `redact` here ESCALATES to the same whole-result withhold as `block` (same
// escalate-on-no-safe-in-place-option pattern PreToolUse already uses for
// redact-on-an-executable-field — see pre-tool-use-decision.ts). `warn`-only
// outcomes are unaffected: the output still reaches the model unmodified,
// same as Claude Code.
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { uniqueRuleIds } from '@akasecurity/plugin-sdk';

import { withheldBanner, withheldToolText } from '../exception-guidance.ts';
import type { ScannableResponseField } from './tool-response.ts';

export interface ResponseScanOutcome {
  withheldFindings: { ruleId: string }[];
  // Collected separately from withheldFindings so the banner/reason can name
  // WHY a redact escalated (`redactedButWithheld`), even though both buckets
  // are withheld the same way on Codex. See module comment.
  redactedButWithheldFindings: { ruleId: string }[];
  warnedFindings: { ruleId: string }[];
  blockedReferences: BlockedDetectionRef[];
  redactedReferences: BlockedDetectionRef[];
  toolName: string;
}

export async function scanResponseFields(
  toolName: string,
  fields: ScannableResponseField[],
  capture: (text: string) => Promise<CaptureResult>,
): Promise<ResponseScanOutcome> {
  const outcome: ResponseScanOutcome = {
    withheldFindings: [],
    redactedButWithheldFindings: [],
    warnedFindings: [],
    blockedReferences: [],
    redactedReferences: [],
    toolName,
  };

  for (const field of fields) {
    const result = await capture(field.text);
    if (result.findings.length === 0) continue;

    if (result.action === 'block') {
      outcome.withheldFindings.push(...result.findings);
      if (result.blockedReferences) outcome.blockedReferences.push(...result.blockedReferences);
    } else if (result.action === 'redact') {
      outcome.redactedButWithheldFindings.push(...result.findings);
      if (result.blockedReferences) outcome.redactedReferences.push(...result.blockedReferences);
    } else if (result.action === 'warn') {
      outcome.warnedFindings.push(...result.findings);
    }
  }

  return outcome;
}

/**
 * The single JSON object the hook should emit for a scan outcome, or
 * undefined for "no opinion" (nothing flagged). A withhold (block OR an
 * escalated redact) uses PostToolUse's `decision:'block'` + `reason` to
 * replace the whole tool result — the closest Codex equivalent to Claude
 * Code's field-level `updatedToolOutput` splice.
 */
export function responseEmitPayload(outcome: ResponseScanOutcome): unknown {
  const { toolName, withheldFindings, redactedButWithheldFindings, warnedFindings } = outcome;
  const allWithheld = [...withheldFindings, ...redactedButWithheldFindings];
  if (allWithheld.length > 0) {
    const withheldRuleIds =
      withheldFindings.length > 0 ? uniqueRuleIds(withheldFindings) : undefined;
    const redactedRuleIds =
      redactedButWithheldFindings.length > 0
        ? uniqueRuleIds(redactedButWithheldFindings)
        : undefined;
    const ref = outcome.blockedReferences[0] ?? outcome.redactedReferences[0];
    return {
      decision: 'block',
      reason: withheldToolText(toolName, uniqueRuleIds(allWithheld)),
      systemMessage: withheldBanner({
        toolName,
        action: 'withheld',
        withheldRuleIds,
        redactedRuleIds,
        warnedRuleIds: warnedFindings.length > 0 ? uniqueRuleIds(warnedFindings) : undefined,
        blockedRef: ref,
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
