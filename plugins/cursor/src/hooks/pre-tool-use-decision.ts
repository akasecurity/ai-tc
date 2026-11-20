// What a `preToolUse` scan decides, as a pure function of the per-field
// results, so it unit-tests without a hook process.
//
// Cursor's `preToolUse` takes a deny (`permission: "deny"`) and is documented
// to take an input rewrite (`updated_input`). This adapter uses the deny alone:
// the rewrite has never been driven against a live host, and an ignored
// rewrite would let the audit trail record a redaction that did not happen.
// Every field is therefore captured as unrewritable, and a redact policy
// resolves inside the runtime to the workspace's `redactFallback`.
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { pointerTokenScanner } from '@akasecurity/schema';

import { blockMessage, exceptionPointer, tooLargeToScanMessage } from '../exception-guidance.ts';
import type { PermissionDenyOutput } from './shared.ts';
import { denyOutput } from './shared.ts';

/**
 * A field worth scanning, and whether its text EXECUTES. An executable field
 * is judged by the command-risk rules as well as the secret and PII rules; a
 * field that does not execute is judged by the secret and PII rules alone, so
 * a file that merely mentions a risky command cannot deny the write.
 */
export interface ScannableField {
  field: string;
  executable: boolean;
}

/**
 * Cursor agent tool arguments worth scanning, keyed by `tool_name`.
 *
 * DOC-DERIVED, every row: the tool names are the ones Cursor's hooks reference
 * lists for `preToolUse`, and the argument names are unrecorded. A wrong
 * argument name costs a silent skip rather than a wrong answer, because the
 * loop reads a field that is not there and scans nothing; `Write` lists both
 * spellings its content has been reported under for that reason.
 *
 * MCP tools (`MCP:<name>`) are not rows here: their arguments are free-form,
 * so every string leaf is scanned instead (see `isMcpTool`).
 *
 * `Read`, `Grep`, `Glob`, `Task` and the rest are absent on purpose: none of
 * them carries text the user or the model authored that this adapter can act
 * on before it runs.
 */
export const SCANNABLE_FIELDS: Record<string, readonly ScannableField[]> = {
  Shell: [{ field: 'command', executable: true }],
  Write: [
    { field: 'contents', executable: false },
    { field: 'content', executable: false },
  ],
  StrReplace: [{ field: 'new_string', executable: false }],
  MultiEdit: [{ field: 'new_string', executable: false }],
  EditNotebook: [{ field: 'new_string', executable: false }],
};

/** Whether a tool name is an MCP tool's, whose arguments are walked whole. */
export function isMcpTool(toolName: string): boolean {
  return toolName.startsWith('MCP:') || toolName.startsWith('mcp_');
}

/** One scanned field: its spec plus the runtime's decision for the field text. */
export interface ScannedField {
  spec: ScannableField;
  result: CaptureResult;
}

export const EXECUTABLE_REDACT_NOTE =
  'Masking inside an executable command would silently change what runs, so masking in place was not possible and this workspace’s fallback for that case is to block.';

export const NO_REWRITE_NOTE =
  'This surface has no confirmed way to rewrite a tool call, so the mask was not applied and this workspace’s fallback for that case is to block.';

export const UNREDACTABLE_NOTE =
  'The redacted form of this input was unavailable, so the call is blocked rather than sent unmasked.';

/**
 * The deny reason when a vault pointer appears in a field that EXECUTES. This
 * plugin never substitutes a pointer back to its raw value, and executing one
 * as literal text is never right.
 */
export function denyPointerMessage(toolName: string): string {
  return (
    `A vault pointer in a ${toolName} command cannot execute as text, and this plugin ` +
    'never substitutes a pointer back to its raw value. Remove the pointer from the ' +
    'command, or resolve the value yourself with `aka vault show` or the dashboard ' +
    'Vault page and retype what you need.'
  );
}

/**
 * What one decision puts on each of the hook's two channels: the deny for
 * stdout, or null to write nothing; and a notice for stderr, when there is one.
 */
export interface PreToolUseDecision {
  output: PermissionDenyOutput | null;
  notice?: string;
}

/**
 * The pointer pre-check the hook runs BEFORE the secret scan, and before the
 * store is opened. Returns null when nothing denies.
 */
export function decideInputPointerDeny(
  toolName: string,
  toolInput: Record<string, unknown>,
  fields: readonly ScannableField[],
): PermissionDenyOutput | null {
  const denies = fields.some((spec) => {
    const value = toolInput[spec.field];
    return spec.executable && typeof value === 'string' && pointerTokenScanner().test(value);
  });
  return denies ? denyOutput(denyPointerMessage(toolName)) : null;
}

/**
 * Collapse the per-field results into one decision.
 *
 * `truncated` says the MCP argument walk left text out; that is reported, not
 * denied, because the fields it did read were scanned and a call's arguments
 * past the walk bounds are not a reason to block a tool the user configured.
 */
export function decidePreToolUse(
  toolName: string,
  scanned: readonly ScannedField[],
  truncated = false,
): PreToolUseDecision {
  if (scanned.some(({ result }) => result.scanIncomplete !== undefined)) {
    return { output: denyOutput(tooLargeToScanMessage(`${toolName} call`)) };
  }

  const blockedRules = new Set<string>();
  const warnedRules = new Set<string>();
  const references: BlockedDetectionRef[] = [];
  let note: string | undefined;

  for (const { spec, result } of scanned) {
    // A redact reaching here was not degraded by the runtime (no fallback
    // applied, or its masked form is missing). With no rewrite channel it is
    // carried out as a block rather than let through unmasked.
    const action = result.action === 'redact' ? 'block' : result.action;
    if (action === 'block') {
      for (const finding of result.findings) blockedRules.add(finding.ruleId);
      if (result.blockedReferences) references.push(...result.blockedReferences);
      if (result.redactDegradedTo === 'block') {
        note ??= spec.executable ? EXECUTABLE_REDACT_NOTE : NO_REWRITE_NOTE;
      } else if (result.action === 'redact') {
        note ??= result.text === null ? UNREDACTABLE_NOTE : NO_REWRITE_NOTE;
      }
    } else if (action === 'warn') {
      for (const finding of result.findings) warnedRules.add(finding.ruleId);
    }
  }

  const partial = truncated
    ? ` Part of the ${toolName} arguments was past AKA's scan limits and was not checked.`
    : '';

  if (blockedRules.size > 0) {
    return {
      output: denyOutput(
        blockMessage({
          subject: `${toolName} call`,
          ruleIds: [...blockedRules].join(', '),
          blockedRef: references[0],
          note,
        }),
      ),
    };
  }

  if (warnedRules.size > 0) {
    return {
      output: null,
      notice:
        `AKA flagged sensitive content in ${toolName} input (${[...warnedRules].join(', ')}).` +
        `${exceptionPointer(references)}${partial}`,
    };
  }
  return partial === '' ? { output: null } : { output: null, notice: partial.trim() };
}
