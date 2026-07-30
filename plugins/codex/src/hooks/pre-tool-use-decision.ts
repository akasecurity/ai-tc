// The pure decision half of the PreToolUse hook: collapse the per-field
// runtime results into the hook's stdout payload. Pure object building (no
// I/O) so it unit-tests without a hook process — hook entry files run main()
// on import and must NEVER be imported by tests (same split as
// exception-guidance.ts). The decision logic itself is identical to
// plugins/claude-code/src/hooks/pre-tool-use-decision.ts — Codex's PreToolUse
// hook uses the SAME hookSpecificOutput.permissionDecision shape (confirmed
// against developers.openai.com/codex/hooks). Only SCANNABLE_FIELDS differs,
// because Codex's built-in tool names/arguments differ from Claude Code's.
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { pointerTokenScanner } from '@akasecurity/schema';

import { blockMessage, exceptionPointer } from '../exception-guidance.ts';

// Which tool_input fields carry user-authored text worth scanning, and whether
// that text EXECUTES — see the Claude Code sibling module for the full
// rationale (masking an executable field changes what runs, so it escalates
// to deny instead of rewriting in place).
//
// IMPORTANT — Codex-specific caveat: as of the current `codex` CLI, PreToolUse/
// PostToolUse hooks only reliably fire for `Bash` calls; `apply_patch` calls do
// NOT fire them yet (confirmed: github.com/openai/codex/issues/16732 — "Hooks
// only fire for Bash tool"). The `apply_patch` entry below is registered for
// forward compatibility (so this table needs no further change once upstream
// fixes it) but is currently INERT — Codex never invokes this hook for a file
// write, so live redaction/blocking of file-write content is not yet possible
// on Codex. Leaked file content is instead caught after the fact by the
// history backfill scan (../history/scan.ts via the rollout's
// patch_apply_begin/end events), not before it leaves the sandbox. The exact
// `apply_patch` tool_input field name below (`input`) is inferred from Codex's
// own patch-call wire shape (codex-rs/protocol/src/models.rs — CustomToolCall's
// `input: String`) and should be re-verified once the hook actually fires.
export interface ScannableField {
  field: string;
  executable: boolean;
}

export const SCANNABLE_FIELDS: Record<string, readonly ScannableField[]> = {
  Bash: [{ field: 'command', executable: true }],
  apply_patch: [{ field: 'input', executable: false }],
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

// The deny reason when a vault pointer appears in a field that EXECUTES. The
// Codex plugin has no vault wiring, so it never substitutes a pointer back to
// its raw value — but pointers minted elsewhere on the same machine (the
// Claude Code plugin's vault, the wizard's history scrub) can be echoed into a
// Bash command here, and executing one as literal text is never right. Same
// posture as Claude Code's un-consented branch: deny, in every consent state.
export function denyPointerMessage(toolName: string): string {
  return (
    `A vault pointer in a ${toolName} command cannot execute as text, and this plugin ` +
    'never substitutes a pointer back to its raw value. Remove the pointer from the ' +
    'command, or resolve the value yourself with `aka vault show` or the dashboard ' +
    'Vault page and retype what you need.'
  );
}

// The pointer pre-check the hook runs BEFORE the secret scan (and before the
// store is opened): a vault pointer in an executable field denies the whole
// call. Returns null when nothing denies. Pure over its inputs so it
// unit-tests without a hook process.
export function decideInputPointerDeny(
  toolName: string,
  toolInput: Record<string, unknown>,
  fields: readonly ScannableField[],
): Extract<PreToolUseOutput, { hookSpecificOutput: { permissionDecision: 'deny' } }> | null {
  const denies = fields.some((spec) => {
    const value = toolInput[spec.field];
    return spec.executable && typeof value === 'string' && pointerTokenScanner().test(value);
  });
  if (!denies) return null;
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: denyPointerMessage(toolName),
    },
  };
}

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
  const blockedRules = new Set<string>();
  const warnedRules = new Set<string>();
  const redactedRules = new Set<string>();
  const blockedReferences: BlockedDetectionRef[] = [];
  const redactedReferences: BlockedDetectionRef[] = [];
  let escalated = false;
  let updatedInput: Record<string, unknown> | null = null;

  for (const { spec, result } of scanned) {
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
