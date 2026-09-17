// The pure decision half of the preToolUse hook: collapse the per-field
// runtime results into the hook's stdout payload. Pure object building (no
// I/O) so it unit-tests without a hook process — hook entry files run main()
// on import and must NEVER be imported by tests (same split as
// exception-guidance.ts).
//
// The decision LOGIC is the Codex sibling's, unchanged. What differs is that
// there are two output dialects and two field tables, because this package
// covers two hosts (see ./dialect.ts):
//
//  - Copilot CLI (and the cloud coding agent) denies with a top-level
//    `{permissionDecision, permissionDecisionReason}` and rewrites with a
//    top-level `{modifiedArgs}`.
//  - VS Code agent mode denies with `hookSpecificOutput.permissionDecision`
//    and rewrites with `hookSpecificOutput.updatedInput`.
//
// The two are never merged. The tool vocabularies do not overlap (`bash`
// against `run_in_terminal`), so a merged table would let a payload from one
// host be looked up under the other host's field names and report success
// having scanned nothing.

import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { pointerTokenScanner } from '@akasecurity/schema';

import { blockMessage, exceptionPointer } from '../exception-guidance.ts';
import type { Dialect } from './dialect.ts';
import type { HookOutput } from './shared.ts';

/**
 * A tool argument worth scanning, and whether that text EXECUTES.
 *
 * Masking an executable field changes what runs, so a redact on one cannot be
 * carried out in place; the runtime resolves it into the configured
 * `redactFallback` instead. See the Claude Code sibling for the full argument.
 */
export interface ScannableField {
  field: string;
  executable: boolean;
}

/**
 * Copilot CLI tool arguments.
 *
 * RECORDED, not inferred: `preToolUse.json` in `test/fixtures/cli/` is a `bash`
 * call whose `toolArgs` carry `command`, `description`, `mode` and
 * `initial_wait`. `command` executes; `description` is model-authored prose
 * that rides alongside it and can be masked in place.
 *
 * `apply_patch` is the CLI's file-write tool (named in the session's own
 * tool-selection log — see the fixtures README's closing note), and its
 * argument names have NOT been recorded: no turn in the captured session made
 * a file write. It is registered here against the argument name the CLI's own
 * patch tool takes so the table needs no further change once a recording
 * exists, and it is INERT until one does — a payload whose field names differ
 * scans nothing rather than scanning the wrong thing.
 *
 * `mode` and `initial_wait` are deliberately absent: neither carries
 * user-authored text.
 */
export const CLI_SCANNABLE_FIELDS: Record<string, readonly ScannableField[]> = {
  bash: [
    { field: 'command', executable: true },
    { field: 'description', executable: false },
  ],
  apply_patch: [{ field: 'input', executable: false }],
};

/**
 * VS Code agent-mode tool inputs.
 *
 * DOC-DERIVED, every row of it. No live VS Code session has produced one of
 * these payloads here; the tool ids and their input key names come from the
 * published compatibility note and are mirrored in
 * `test/fixtures/vscode-provisional/`. Treat each row as unverified until a
 * recording replaces it — `../capabilities.ts` carries that per row as a
 * `verified` column, and `skills/setup/SKILL.md` says so in prose.
 *
 * VS Code parses matchers and then IGNORES them, so the hook is spawned for
 * every tool call on that host. A tool absent from this table is the COMMON
 * case there, not the rare one, which is why the caller's unknown-tool exit
 * happens before the store is opened.
 */
export const VSCODE_SCANNABLE_FIELDS: Record<string, readonly ScannableField[]> = {
  run_in_terminal: [
    { field: 'command', executable: true },
    { field: 'explanation', executable: false },
  ],
  create_file: [{ field: 'content', executable: false }],
  replace_string_in_file: [{ field: 'newString', executable: false }],
  multi_replace_string_in_file: [{ field: 'explanation', executable: false }],
  insert_edit_into_file: [{ field: 'code', executable: false }],
  apply_patch: [{ field: 'input', executable: false }],
  edit_notebook_file: [{ field: 'newCode', executable: false }],
};

/** The field table for a dialect. One lookup, so no caller picks the wrong one. */
export function scannableFields(dialect: Dialect): Record<string, readonly ScannableField[]> {
  return dialect === 'vscode' ? VSCODE_SCANNABLE_FIELDS : CLI_SCANNABLE_FIELDS;
}

/** One scanned field: its spec plus the runtime's decision for the field text. */
export interface ScannedField {
  spec: ScannableField;
  result: CaptureResult;
}

// Woven into the deny message when a redact policy could not be carried out on
// an executable field and the configured fallback resolved to a block, so the
// block explains why the policy's redact didn't rewrite in place. It names the
// fallback as the decision rather than saying redact always blocks, because
// that is a setting: under `monitor` or `warn` the call goes through and no
// deny is emitted for this note to ride on.
export const EXECUTABLE_REDACT_NOTE =
  'Masking inside an executable command would silently change what runs, so masking in place was not possible and this workspace’s fallback for that case is to block.';

// Woven into the deny message when a redact decision carried no redacted text
// to put in place, so the block explains why the policy's redact could not be
// applied rather than the call going out unmasked.
export const UNREDACTABLE_NOTE =
  'The redacted form of this input was unavailable, so the call is blocked rather than sent unmasked.';

/**
 * The deny reason when a vault pointer appears in a field that EXECUTES.
 *
 * This plugin has no vault wiring, so it never substitutes a pointer back to
 * its raw value — but pointers minted elsewhere on the same machine (the Claude
 * Code plugin's vault, the wizard's history scrub) can be echoed into a shell
 * command here, and executing one as literal text is never right.
 */
export function denyPointerMessage(toolName: string): string {
  return (
    `A vault pointer in a ${toolName} command cannot execute as text, and this plugin ` +
    'never substitutes a pointer back to its raw value. Remove the pointer from the ' +
    'command, or resolve the value yourself with `aka vault show` or the dashboard ' +
    'Vault page and retype what you need.'
  );
}

/** A deny, in whichever shape this dialect's host understands. */
export function denyOutput(dialect: Dialect, reason: string): HookOutput {
  return dialect === 'vscode'
    ? {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: reason,
        },
      }
    : { permissionDecision: 'deny', permissionDecisionReason: reason };
}

/**
 * A rewrite, in whichever shape this dialect's host understands.
 *
 * Both hosts take the WHOLE argument object rather than the changed keys: the
 * CLI's `modifiedArgs` replaces the call's arguments, and VS Code validates
 * `updatedInput` against the tool's own input schema, which a partial object
 * would fail. The caller therefore passes a full copy with the redacted fields
 * substituted in, never a diff.
 */
export function rewriteOutput(
  dialect: Dialect,
  updated: Record<string, unknown>,
  systemMessage: string,
): HookOutput {
  return dialect === 'vscode'
    ? {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'allow',
          updatedInput: updated,
        },
        systemMessage,
      }
    : { modifiedArgs: updated };
}

/**
 * The pointer pre-check the hook runs BEFORE the secret scan (and before the
 * store is opened): a vault pointer in an executable field denies the whole
 * call. Returns null when nothing denies. Pure over its inputs so it
 * unit-tests without a hook process.
 */
export function decideInputPointerDeny(
  dialect: Dialect,
  toolName: string,
  toolInput: Record<string, unknown>,
  fields: readonly ScannableField[],
): HookOutput | null {
  const denies = fields.some((spec) => {
    const value = toolInput[spec.field];
    return spec.executable && typeof value === 'string' && pointerTokenScanner().test(value);
  });
  if (!denies) return null;
  return denyOutput(dialect, denyPointerMessage(toolName));
}

export function decidePreToolUse(
  dialect: Dialect,
  toolName: string,
  toolInput: Record<string, unknown>,
  scanned: readonly ScannedField[],
): HookOutput | null {
  const blockedRules = new Set<string>();
  const warnedRules = new Set<string>();
  const redactedRules = new Set<string>();
  const blockedReferences: BlockedDetectionRef[] = [];
  const redactedReferences: BlockedDetectionRef[] = [];
  let escalatedExecutable = false;
  let escalatedUnredactable = false;
  let updatedInput: Record<string, unknown> | null = null;

  for (const { spec, result } of scanned) {
    // Two things this hook cannot carry out, and they are not the same
    // mechanism.
    //
    // Masking an executable field would silently change what runs, so the
    // capture declared that field unrewritable and the RUNTIME already
    // resolved its redact into the configured fallback; `redactDegradedTo`
    // says what it became. Reading that here, rather than re-deriving it, is
    // what keeps the emitted decision and the recorded action equal — and it
    // is the only way to see a fallback of `warn`, which this module cannot
    // infer.
    //
    // Gated on the VALUE, not its presence: `escalatedExecutable` wins the
    // note precedence below, so a presence check would let a `command` field
    // that merely WARNED displace the unredactable note on a deny the
    // `description` field alone caused — wrong on both halves of what it says.
    //
    // A null `text` is different: it is a runtime failure on a field that CAN
    // be rewritten, leaving no redacted form to substitute. Emitting the
    // untouched input under the "AKA redacted" systemMessage would send the
    // raw value and report it as masked, so that one still escalates here.
    if (result.redactDegradedTo === 'block') escalatedExecutable = true;
    const unredactable = result.action === 'redact' && result.text === null;
    if (unredactable) escalatedUnredactable = true;
    const action = unredactable ? 'block' : result.action;

    if (action === 'block') {
      for (const finding of result.findings) blockedRules.add(finding.ruleId);
      if (result.blockedReferences) blockedReferences.push(...result.blockedReferences);
    } else if (action === 'redact') {
      for (const finding of result.findings) redactedRules.add(finding.ruleId);
      if (result.blockedReferences) redactedReferences.push(...result.blockedReferences);
      updatedInput ??= { ...toolInput };
      // Non-null here: a redact carrying no text escalated to block above.
      if (result.text !== null) updatedInput[spec.field] = result.text;
    } else if (action === 'warn') {
      for (const finding of result.findings) warnedRules.add(finding.ruleId);
    }
  }

  if (blockedRules.size > 0) {
    return denyOutput(
      dialect,
      blockMessage({
        subject: `${toolName} call`,
        ruleIds: [...blockedRules].join(', '),
        blockedRef: blockedReferences[0],
        note: escalatedExecutable
          ? EXECUTABLE_REDACT_NOTE
          : escalatedUnredactable
            ? UNREDACTABLE_NOTE
            : undefined,
      }),
    );
  }

  if (redactedRules.size > 0) {
    return rewriteOutput(
      dialect,
      updatedInput ?? { ...toolInput },
      `AKA redacted sensitive content in ${toolName} input — flagged ${[...redactedRules].join(', ')}.${exceptionPointer(redactedReferences)}`,
    );
  }

  if (warnedRules.size > 0) {
    return {
      systemMessage: `AKA flagged sensitive content in ${toolName} input (${[...warnedRules].join(', ')}).`,
    };
  }
  return null;
}
