// The PostToolUse per-field scan loop and its two output shapes, extracted from
// the hook entry so both unit-test without a hook process.
//
// THE TWO HOSTS HAVE DIFFERENT LEVERS HERE, and the difference is not cosmetic:
//
//  - **Copilot CLI (and cloud)** offers `modifiedResult`, which REPLACES the
//    tool result the model sees. That is enough to express both a redaction
//    (substitute the masked text) and a withhold (substitute the block notice),
//    through one key, so this host keeps true in-place redaction.
//  - **VS Code agent mode** offers no result-rewrite field at all. Its only
//    lever is `{"decision":"block"}` + `additionalContext`, which is
//    whole-result or nothing. So a `redact` outcome ESCALATES to the same
//    whole-result withhold a `block` gets — the same escalate-when-there-is-no-
//    safe-in-place-option pattern `pre-tool-use-decision.ts` uses for a redact
//    on an executable field. Under-protecting silently is the alternative and
//    is worse.
//
// ─── WHAT IS AND IS NOT KNOWN ────────────────────────────────────────────────
//
// `modifiedResult` is DOCUMENTED and has not been observed working
// (`test/fixtures/cli/README.md`, "Not measured" — the CLI's sibling
// `modifiedArgs` IS confirmed by effect, which is the reason to expect this one
// to work and not a substitute for having seen it). Emitting it is still right,
// and it is a different case from the prompt hook's refusal to emit a block:
// if the host honours it the redaction is real, and if it ignores it the
// outcome is exactly what emitting nothing would have been. Nothing is lost by
// trying — but the note must describe what AKA DID rather than what the host
// then did, which is why it reads "returned a masked result" and never "the
// model saw".
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { uniqueRuleIds } from '@akasecurity/plugin-sdk';

import { withheldBanner, withheldToolText } from '../exception-guidance.ts';
import type { Dialect } from './dialect.ts';
import type { HookOutput } from './shared.ts';
import type { ScannableResponseField } from './tool-response.ts';
import { replaceResponseField } from './tool-response.ts';

export interface ResponseScanOutcome {
  withheldFindings: { ruleId: string }[];
  /**
   * Collected separately from `withheldFindings` so a banner can name WHY a
   * redact was escalated on the host that had to escalate it — and so the CLI,
   * which does not escalate, can tell the two apart at all.
   */
  redactedFindings: { ruleId: string }[];
  warnedFindings: { ruleId: string }[];
  blockedReferences: BlockedDetectionRef[];
  redactedReferences: BlockedDetectionRef[];
  /** Per-field masked text, for the host that can substitute it. */
  rewrites: { path: string[]; text: string }[];
  /**
   * Every path that was SCANNED, finding or not.
   *
   * A block leaves no masked text behind, so `rewrites` names nothing for the
   * field it came from — and a withhold that wrote its notice only over the
   * redacted fields would send the blocked one to the model untouched. This is
   * what the withhold overwrites instead.
   */
  scannedPaths: string[][];
  toolName: string;
}

export async function scanResponseFields(
  toolName: string,
  fields: readonly ScannableResponseField[],
  capture: (text: string) => Promise<CaptureResult>,
): Promise<ResponseScanOutcome> {
  const outcome: ResponseScanOutcome = {
    withheldFindings: [],
    redactedFindings: [],
    warnedFindings: [],
    blockedReferences: [],
    redactedReferences: [],
    rewrites: [],
    scannedPaths: [],
    toolName,
  };

  for (const field of fields) {
    outcome.scannedPaths.push([...field.path]);
    const result = await capture(field.text);
    if (result.findings.length === 0) continue;

    if (result.action === 'block') {
      outcome.withheldFindings.push(...result.findings);
      if (result.blockedReferences) outcome.blockedReferences.push(...result.blockedReferences);
    } else if (result.action === 'redact') {
      // A redact carrying no masked text has nothing to substitute. Passing the
      // original through under a "redacted" note would send the raw value and
      // report it as masked, so it joins the withheld bucket instead.
      if (result.text === null) {
        outcome.withheldFindings.push(...result.findings);
        if (result.blockedReferences) outcome.blockedReferences.push(...result.blockedReferences);
      } else {
        outcome.redactedFindings.push(...result.findings);
        if (result.blockedReferences) outcome.redactedReferences.push(...result.blockedReferences);
        outcome.rewrites.push({ path: field.path, text: result.text });
      }
    } else if (result.action === 'warn') {
      outcome.warnedFindings.push(...result.findings);
    }
  }

  return outcome;
}

/**
 * The single JSON object the hook should emit, or `undefined` for "no opinion".
 *
 * `response` is the ORIGINAL tool result, needed on the CLI path because
 * `modifiedResult` replaces the whole object rather than one field — so the
 * substitution is built by cloning the spine along each rewritten path.
 *
 * On the CLI a result that is not an object cannot be rebuilt into a
 * `modifiedResult` (which must be an object), so that case degrades to a note
 * rather than inventing an envelope shape no recording backs. It is not
 * reachable from the one recorded CLI shape, and is handled because a host that
 * simplified its envelope would otherwise silently drop the enforcement.
 */
export function responseEmitPayload(
  dialect: Dialect,
  outcome: ResponseScanOutcome,
  response: unknown,
): HookOutput | undefined {
  const { toolName, withheldFindings, redactedFindings, warnedFindings } = outcome;
  const withheldRuleIds = withheldFindings.length > 0 ? uniqueRuleIds(withheldFindings) : undefined;
  const redactedRuleIds = redactedFindings.length > 0 ? uniqueRuleIds(redactedFindings) : undefined;
  const warnedRuleIds = warnedFindings.length > 0 ? uniqueRuleIds(warnedFindings) : undefined;
  const ref = outcome.blockedReferences[0] ?? outcome.redactedReferences[0];

  if (dialect === 'vscode') {
    // No result-rewrite field on this host: a redact escalates to the same
    // whole-result withhold as a block.
    const allWithheld = [...withheldFindings, ...redactedFindings];
    if (allWithheld.length > 0) {
      return {
        decision: 'block',
        additionalContext: withheldBanner({
          toolName,
          action: 'withheld',
          withheldRuleIds,
          redactedRuleIds,
          warnedRuleIds,
          blockedRef: ref,
        }),
      };
    }
    if (warnedRuleIds !== undefined) {
      return {
        systemMessage: `AKA flagged sensitive content in ${toolName} output (${warnedRuleIds}).`,
      };
    }
    return undefined;
  }

  // CLI / cloud. Both a withhold and a redaction ride `modifiedResult`.
  const rewritable = typeof response === 'object' && response !== null;
  if (withheldRuleIds !== undefined || redactedRuleIds !== undefined) {
    if (!rewritable) {
      // NOT `withheldBanner`: its text states that the flagged value never
      // reached the model, and on this branch nothing was replaced, so it
      // would be a false claim. Say what happened instead.
      const flagged = [withheldRuleIds, redactedRuleIds, warnedRuleIds]
        .filter((ids): ids is string => ids !== undefined)
        .join(', ');
      return {
        systemMessage:
          `AKA flagged sensitive content in ${toolName} output (${flagged}) and recorded it. ` +
          'This result arrived in a shape AKA cannot rewrite, so it reached the model ' +
          `unchanged.${ref ? ` Allow this exact value intentionally: aka exception approve ${ref.reference}` : ''}`,
      };
    }
    // A withhold replaces every scanned path with the block notice; a redaction
    // substitutes the masked text per path. A capture that produced both takes
    // the withhold, because the masked copy of one field says nothing about the
    // field that has to be withheld.
    // Annotated `unknown`: TS narrows `response` to `object` through the
    // `rewritable` alias above, and `replaceResponseField` answers `unknown`.
    let modified: unknown = response;
    if (withheldRuleIds !== undefined) {
      const notice = withheldToolText(toolName, uniqueRuleIds([...withheldFindings]));
      // EVERY scanned path, not only the redacted ones — see `scannedPaths`.
      for (const path of outcome.scannedPaths) {
        modified = replaceResponseField(modified, path, notice);
      }
    } else {
      for (const rewrite of outcome.rewrites) {
        modified = replaceResponseField(modified, rewrite.path, rewrite.text);
      }
    }
    return { modifiedResult: modified as Record<string, unknown> };
  }

  if (warnedRuleIds !== undefined) {
    return {
      systemMessage: `AKA flagged sensitive content in ${toolName} output (${warnedRuleIds}).`,
    };
  }
  return undefined;
}
