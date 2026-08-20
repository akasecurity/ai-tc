// The pure decision half of the PreToolUse hook: collapse the per-field
// runtime results into the hook's stdout payload. Pure object building (no
// I/O) so it unit-tests without a hook process — hook entry files run main()
// on import and must NEVER be imported by tests (same split as
// exception-guidance.ts).
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';

import { blockMessage, exceptionPointer } from '../exception-guidance.ts';
import type { RealizedRewrite } from '../protocol/notes.ts';
import { replaceAtPath } from './paths.ts';
import type { ScannableField } from './pre-tool-use-fields.ts';

// One scanned field: its spec, the text the runtime scanned, and the runtime's
// decision for it.
export interface ScannedField {
  spec: ScannableField;
  text: string;
  result: CaptureResult;
}

// The reversible rewrite for an enforced redact on a data field: replaces
// exactly the enforced spans with vault pointers (or one-way placeholders when
// a span cannot be vaulted). Absent — no consent, or the vault glue could not
// be built — keeps the runtime's one-way redacted text.
export type FieldTokenizer = (
  text: string,
  findings: CaptureResult['findings'],
  reversible: ReadonlySet<CaptureResult['findings'][number]>,
) => Promise<{ text: string; pointers: string[]; degraded: { category: string }[] }>;

// Woven into the deny message when a redact decision was escalated off an
// executable field, so the block explains why the policy's redact didn't
// rewrite in place.
export const EXECUTABLE_REDACT_NOTE =
  'Masking inside an executable command would silently change what runs, so a redact policy blocks it instead.';

// Woven into the deny message when a redact decision carried no redacted text
// to put in place, so the block explains why the policy's redact could not be
// applied rather than the call going out unmasked.
export const UNREDACTABLE_NOTE =
  'The redacted form of this input was unavailable, so the call is blocked rather than sent unmasked.';

export type PreToolUseOutput =
  | {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse';
        permissionDecision: 'deny';
        permissionDecisionReason: string;
      };
    }
  | {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse';
        permissionDecision: 'allow';
        updatedInput: Record<string, unknown>;
        additionalContext?: string;
      };
      systemMessage: string;
    }
  | { systemMessage: string };

export interface PreToolUseDecision {
  output: PreToolUseOutput;
  // What the tokenizer actually did across every redact field — the pointers
  // that now exist and the spans destroyed one-way. Null when nothing was
  // tokenized (deny, warn-only, or no tokenizer supplied), so a caller never
  // narrates a rewrite that did not happen.
  realized: RealizedRewrite | null;
}

// The category segment of a pointer, read back off the wire form — the token
// is self-describing precisely so consumers need no lookup for this.
function pointerCategory(token: string): string {
  const match = /^\[\[aka:([a-z_]+):/.exec(token);
  return match?.[1] ?? 'secret';
}

export async function decidePreToolUse(
  toolName: string,
  toolInput: Record<string, unknown>,
  scanned: readonly ScannedField[],
  tokenizeField?: FieldTokenizer,
): Promise<PreToolUseDecision | null> {
  // Rules grouped by the *field's* worst action — every rule flagged in a
  // blocked/redacted/warned field, not necessarily the single rule that drove
  // it. Ledger refs collected per action — the deny/redact messages turn these
  // into `aka exception approve` guidance (preview + reference travel
  // together on the ref, from the same row).
  const blockedRules = new Set<string>();
  const warnedRules = new Set<string>();
  const redactedRules = new Set<string>();
  const blockedReferences: BlockedDetectionRef[] = [];
  const redactedReferences: BlockedDetectionRef[] = [];
  // Whether the deny (if any) includes an escalated redact — that deny
  // carries EXECUTABLE_REDACT_NOTE so it explains itself.
  let escalated = false;
  // Whether a redact was denied because no redacted text was available to put
  // in place — that deny carries UNREDACTABLE_NOTE instead.
  let escalatedUnredactable = false;
  let updatedInput: Record<string, unknown> | null = null;
  const realized: RealizedRewrite = { pointers: [], degraded: [] };

  for (const { spec, text, result } of scanned) {
    // NEVER rewrite text that executes: a redact decision on an executable
    // field escalates to a hard deny. Rewriting silently changes semantics
    // (the incident this module exists for); allowing unchanged would
    // silently drop the masking the policy asked for. Deny is the one action
    // that is both visible and at least as strong as the policy — and the
    // runtime already ledgered the redacted values (recordBlockedDetections
    // runs for redact too), so the approve escape hatch stays available.
    const escalate = result.action === 'redact' && spec.executable;
    if (escalate) escalated = true;
    const action = escalate ? 'block' : result.action;

    if (action === 'block') {
      for (const finding of result.findings) blockedRules.add(finding.ruleId);
      if (result.blockedReferences) blockedReferences.push(...result.blockedReferences);
    } else if (action === 'redact') {
      // The rewrite covers exactly the ENFORCED spans — warn-level findings in
      // the same field stay in place, matching what the policy decided.
      //
      // Which of those spans survives as a recoverable pointer is decided PER
      // FINDING, by the archetype its own detection was assigned: Redact & Vault
      // keeps it, plain Redact destroys it. Both are handed to the tokenizer in
      // one call rather than split into two rewrites — the tokenizer replaces
      // every span it is given, so passing only the reversible subset would
      // leave the one-way spans standing in the clear.
      let rewritten = result.text;
      const enforced = result.enforcedFindings ?? [];
      const reversible = new Set(result.reversibleFindings ?? []);
      if (tokenizeField && enforced.length > 0) {
        try {
          const tokenized = await tokenizeField(text, enforced, reversible);
          rewritten = tokenized.text;
          for (const token of tokenized.pointers) {
            realized.pointers.push({ token, category: pointerCategory(token) });
          }
          realized.degraded.push(...tokenized.degraded);
        } catch {
          // A tokenizer fault falls back to the one-way text already in hand —
          // the value is destroyed, never passed through raw.
        }
      }

      // Decided AFTER the rewrite attempt, because a null `result.text` can
      // still yield redacted text through the tokenizer. With no redacted form
      // in hand there is nothing to substitute, and emitting the original under
      // the "AKA redacted" systemMessage would send the raw value and report it
      // as masked — so this denies, like the executable-field escalation above.
      if (rewritten === null) {
        escalatedUnredactable = true;
        for (const finding of result.findings) blockedRules.add(finding.ruleId);
        if (result.blockedReferences) blockedReferences.push(...result.blockedReferences);
      } else {
        for (const finding of result.findings) redactedRules.add(finding.ruleId);
        if (result.blockedReferences) redactedReferences.push(...result.blockedReferences);

        // Rebuilt through the path so a nested leaf (MultiEdit's
        // edits[i].new_string) lands in place with its siblings — and its array
        // spine — intact. Each pass folds into the previous result, so two
        // flagged fields of one payload both survive into the emitted input.
        updatedInput = replaceAtPath(updatedInput ?? toolInput, spec.path, rewritten) as Record<
          string,
          unknown
        >;
      }
    } else if (action === 'warn') {
      for (const finding of result.findings) warnedRules.add(finding.ruleId);
    }
  }

  if (blockedRules.size > 0) {
    return {
      output: {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: blockMessage({
            subject: `${toolName} call`,
            ruleIds: [...blockedRules].join(', '),
            blockedRef: blockedReferences[0],
            note: escalated
              ? EXECUTABLE_REDACT_NOTE
              : escalatedUnredactable
                ? UNREDACTABLE_NOTE
                : undefined,
          }),
        },
      },
      realized: null,
    };
  }

  if (redactedRules.size > 0) {
    const tokenized = realized.pointers.length > 0 || realized.degraded.length > 0;
    return {
      output: {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'allow',
          updatedInput: updatedInput ?? { ...toolInput },
        },
        systemMessage: `AKA redacted sensitive content in ${toolName} input — flagged ${[...redactedRules].join(', ')}.${exceptionPointer(redactedReferences)}`,
      },
      realized: tokenized ? realized : null,
    };
  }

  if (warnedRules.size > 0) {
    return {
      output: {
        systemMessage: `AKA flagged sensitive content in ${toolName} input (${[...warnedRules].join(', ')}).`,
      },
      realized: null,
    };
  }
  return null;
}
