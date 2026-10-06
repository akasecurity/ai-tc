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
import type { PathSegment } from './paths.ts';
import type { FieldTokenizer } from './pre-tool-use-decision.ts';
import type { HookOutput } from './shared.ts';
import type { ScannableResponseField } from './tool-response.ts';
import { replaceResponseField, spliceResponseField } from './tool-response.ts';

// The wall-time budget for the field loop, in milliseconds since the hook
// process started (performance.now()'s origin). The hook's own timeout is
// 10 s, and a timed-out hook passes the whole output through unscanned, so
// the loop starts no capture past this point and leaves the remaining fields
// unscanned instead. The margin covers closing the store and writing the
// reply. A capture that has already started is not interrupted.
export const RESPONSE_SCAN_DEADLINE_MS = 7_000;

/** When the field loop must stop starting new captures. */
export interface ScanDeadline {
  /** Absolute time, on the same clock as `now`. */
  at: number;
  now: () => number;
}

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
  // Fields left unscanned because the deadline passed. The caller counts a
  // non-zero value as a fail-open exit.
  unscannedFields: number;
}

export async function scanResponseFields(
  toolName: string,
  response: unknown,
  fields: ScannableResponseField[],
  capture: (text: string) => Promise<CaptureResult>,
  tokenizeField?: FieldTokenizer,
  deadline?: ScanDeadline,
): Promise<ResponseScanOutcome> {
  const outcome: ResponseScanOutcome = {
    updated: response,
    withheldFindings: [],
    redactedFindings: [],
    warnedFindings: [],
    blockedReferences: [],
    redactedReferences: [],
    realized: null,
    unscannedFields: 0,
  };
  const realized: RealizedRewrite = { pointers: [], degraded: [] };

  // Chunk rewrites are collected per path and spliced in once at the end:
  // each chunk's range is an offset into the string as it was scanned, which
  // an earlier chunk's rewrite (a different length) would shift.
  const chunkRewrites = new Map<
    string,
    { path: PathSegment[]; parts: { start: number; end: number; text: string }[] }
  >();
  const rewrite = (field: ScannableResponseField, text: string): void => {
    if (field.range === undefined) {
      outcome.updated = replaceResponseField(outcome.updated, field.path, text);
      return;
    }
    const key = JSON.stringify(field.path);
    const entry = chunkRewrites.get(key) ?? { path: field.path, parts: [] };
    entry.parts.push({ ...field.range, text });
    chunkRewrites.set(key, entry);
  };

  for (const [index, field] of fields.entries()) {
    if (deadline !== undefined && deadline.now() >= deadline.at) {
      outcome.unscannedFields = fields.length - index;
      break;
    }
    const result = await capture(field.text);
    if (result.findings.length === 0) continue;

    if (result.action === 'block') {
      // Can't un-run the tool; withhold the flagged field from the model instead
      rewrite(
        field,
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
          const tokenized = await tokenizeField(
            field.text,
            enforced,
            new Set(result.reversibleFindings ?? []),
          );
          rewritten = tokenized.text;
          for (const token of tokenized.pointers) {
            realized.pointers.push({ token, category: pointerCategoryOf(token) });
          }
          realized.degraded.push(...tokenized.degraded);
        } catch {
          // Tokenizer fault: the one-way text already in hand stands.
        }
      }
      rewrite(field, rewritten);
      outcome.redactedFindings.push(...result.findings);
      if (result.blockedReferences) outcome.redactedReferences.push(...result.blockedReferences);
    } else if (result.action === 'warn') {
      outcome.warnedFindings.push(...result.findings);
    }
  }

  // Chunks were cut from the original string, which every other rewrite
  // leaves alone (a path is either chunked or not), so splicing into
  // `outcome.updated` reads the same text the ranges were taken from.
  for (const { path, parts } of chunkRewrites.values()) {
    outcome.updated = spliceResponseField(outcome.updated, path, parts);
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
