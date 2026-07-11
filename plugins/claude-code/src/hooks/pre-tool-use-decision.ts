// The pure decision half of the PreToolUse hook: collapse the per-field
// runtime results into the hook's stdout payload. Pure object building (no
// I/O) so it unit-tests without a hook process — hook entry files run main()
// on import and must NEVER be imported by tests (same split as
// exception-guidance.ts).
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';

import { blockMessage, exceptionPointer } from '../exception-guidance.ts';

// Which tool_input fields carry user-authored text worth scanning, and whether
// that text EXECUTES. `executable` marks text the host acts on directly (a
// shell command, a URL to fetch): masking inside it doesn't remove the
// sensitive value from what happens — it CHANGES what happens, because the
// spliced-in `[REDACTED:…]` placeholder runs as a different command (a masked
// SQL predicate matches different rows, a masked URL requests a different
// resource; see the incident pinned in pre-tool-use-decision.test.ts).
// Write/Edit content and the WebFetch analysis prompt are data handed onward —
// the masked form IS the intended end state — so in-place redaction is correct
// there and only there.
// TODO: extend per-tool coverage (MultiEdit, NotebookEdit, MCP tools).
export interface ScannableField {
  field: string;
  executable: boolean;
}

export const SCANNABLE_FIELDS: Record<string, readonly ScannableField[]> = {
  Bash: [{ field: 'command', executable: true }],
  Write: [{ field: 'content', executable: false }],
  Edit: [{ field: 'new_string', executable: false }],
  // WebFetch is the classic exfil channel: a secret spliced into the fetched
  // URL leaves the machine before any post-hook can see it. The URL executes
  // (it IS the request), so redact escalates to deny; the prompt is text
  // handed to the fetch-analysis model and redacts in place like Write/Edit.
  WebFetch: [
    { field: 'url', executable: true },
    { field: 'prompt', executable: false },
  ],
};

// One scanned field: its spec plus the runtime's decision for the field text.
export interface ScannedField {
  spec: ScannableField;
  result: CaptureResult;
}

// Woven into the deny message when a redact decision was escalated off an
// executable field, so the block explains why the policy's redact didn't
// rewrite in place.
export const EXECUTABLE_REDACT_NOTE =
  'Masking inside an executable command would silently change what runs, so a redact policy blocks it instead.';

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
      };
      systemMessage: string;
    }
  | { systemMessage: string };

export function decidePreToolUse(
  toolName: string,
  toolInput: Record<string, unknown>,
  scanned: readonly ScannedField[],
): PreToolUseOutput | null {
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
  let updatedInput: Record<string, unknown> | null = null;

  for (const { spec, result } of scanned) {
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
      for (const finding of result.findings) redactedRules.add(finding.ruleId);
      if (result.blockedReferences) redactedReferences.push(...result.blockedReferences);
      updatedInput ??= { ...toolInput };
      if (result.text !== null) updatedInput[spec.field] = result.text;
    } else if (action === 'warn') {
      for (const finding of result.findings) warnedRules.add(finding.ruleId);
    }
  }

  if (blockedRules.size > 0) {
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: blockMessage({
          subject: `${toolName} call`,
          ruleIds: [...blockedRules].join(', '),
          blockedRef: blockedReferences[0],
          note: escalated ? EXECUTABLE_REDACT_NOTE : undefined,
        }),
      },
    };
  }

  if (redactedRules.size > 0) {
    return {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        updatedInput: updatedInput ?? { ...toolInput },
      },
      systemMessage: `AKA redacted sensitive content in ${toolName} input — flagged ${[...redactedRules].join(', ')}.${exceptionPointer(redactedReferences)}`,
    };
  }

  if (warnedRules.size > 0) {
    return {
      systemMessage: `AKA flagged sensitive content in ${toolName} input (${[...warnedRules].join(', ')}).`,
    };
  }
  return null;
}
