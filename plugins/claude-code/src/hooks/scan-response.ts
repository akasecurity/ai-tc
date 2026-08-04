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
import type { RealizedRewrite } from '../protocol/notes.ts';
import type { FieldTokenizer } from './pre-tool-use-decision.ts';
import type { HookOutput } from './shared.ts';
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
  // What the tokenizer actually did across the redact fields — null when
  // nothing was tokenized, so a caller never narrates a rewrite that did not
  // happen.
  realized: RealizedRewrite | null;
}

export async function scanResponseFields(
  toolName: string,
  response: unknown,
  fields: ScannableResponseField[],
  capture: (text: string) => Promise<CaptureResult>,
  tokenizeField?: FieldTokenizer,
): Promise<ResponseScanOutcome> {
  const outcome: ResponseScanOutcome = {
    updated: response,
    withheldFindings: [],
    redactedFindings: [],
    warnedFindings: [],
    blockedReferences: [],
    redactedReferences: [],
    realized: null,
  };
  const realized: RealizedRewrite = { pointers: [], degraded: [] };

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
      // Reversible rewrite when a tokenizer is supplied: exactly the enforced
      // spans become pointers (or one-way placeholders where a span cannot be
      // vaulted). Without one, the runtime's one-way text stands. A pointer
      // already sitting in the output is never re-tokenized — the scan shields
      // pointer spans before detection runs — so this pass is idempotent.
      let rewritten = result.text;
      const enforced = result.enforcedFindings ?? [];
      if (tokenizeField && enforced.length > 0) {
        try {
          const tokenized = await tokenizeField(field.text, enforced);
          rewritten = tokenized.text;
          for (const token of tokenized.pointers) {
            realized.pointers.push({ token, category: pointerCategoryOf(token) });
          }
          realized.degraded.push(...tokenized.degraded);
        } catch {
          // Tokenizer fault: the one-way text already in hand stands.
        }
      }
      outcome.updated = replaceResponseField(outcome.updated, field.path, rewritten);
      outcome.redactedFindings.push(...result.findings);
      if (result.blockedReferences) outcome.redactedReferences.push(...result.blockedReferences);
    } else if (result.action === 'warn') {
      outcome.warnedFindings.push(...result.findings);
    }
  }

  if (realized.pointers.length > 0 || realized.degraded.length > 0) outcome.realized = realized;
  return outcome;
}

// The category segment of a pointer, read back off the wire form — the token
// is self-describing precisely so consumers need no lookup for this.
function pointerCategoryOf(token: string): string {
  const match = /^\[\[aka:([a-z_]+):/.exec(token);
  return match?.[1] ?? 'secret';
}

/**
 * The single JSON object the hook should emit for a scan outcome, or
 * undefined for "no opinion" (nothing flagged). Extracted so the emit
 * decision — action label, per-action rule lines, which ledger ref the
 * banner's approve command carries — is unit-testable (the hook entry runs
 * main() on import and cannot be imported by tests).
 */
export function responseEmitPayload(
  toolName: string,
  outcome: ResponseScanOutcome,
  notes?: { note?: string | null | undefined; disclosure?: string | null | undefined },
): HookOutput | undefined {
  const { withheldFindings, redactedFindings, warnedFindings } = outcome;
  if (withheldFindings.length > 0 || redactedFindings.length > 0) {
    const action = withheldFindings.length > 0 ? 'withheld' : 'redacted';
    const note = notes?.note ?? null;
    return {
      hookSpecificOutput: {
        hookEventName: 'PostToolUse',
        updatedToolOutput: outcome.updated,
        ...(note === null ? {} : { additionalContext: note }),
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
        vaultDisclosure: notes?.disclosure ?? undefined,
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
