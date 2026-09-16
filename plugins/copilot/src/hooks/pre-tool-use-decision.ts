// The pure decision half of the pre-tool-use hook: collapse the per-field
// runtime results into the hook's stdout payload. Pure object building (no
// I/O) so it unit-tests without a hook process — hook entry files run main()
// on import and must NEVER be imported by tests (same split as
// exception-guidance.ts).
//
// Two things are specific to this adapter and neither is cosmetic.
//
//  1. TWO FIELD TABLES, NEVER MERGED. The Copilot CLI and VS Code agent mode
//     name their tools differently (`bash` against `run_in_terminal`) and spell
//     their arguments differently, so a merged table would let a VS Code tool
//     name resolve against a CLI field list and scan a field that is not there
//     — silently, because a missing field is simply skipped.
//
//  2. TWO OUTPUT SHAPES. The CLI takes a flat `permissionDecision` and rewrites
//     input through `modifiedArgs`; VS Code nests both under
//     `hookSpecificOutput` and rewrites through `updatedInput`. The dialect is
//     a parameter all the way down rather than a branch at the end, so a
//     payload can never be built in one dialect's shape from the other's table.
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { pointerTokenScanner } from '@akasecurity/schema';

import { blockMessage, exceptionPointer } from '../exception-guidance.ts';
import type { Dialect } from './dialect.ts';

/**
 * A field worth scanning, and whether its text EXECUTES.
 *
 * `executable` is what decides whether a redact can be carried out at all:
 * masking inside a command changes what runs, so the capture declares that
 * field unrewritable and the RUNTIME resolves the redact into the configured
 * fallback. This module reads that resolution; it never re-derives it.
 */
export interface ScannableField {
  field: string;
  executable: boolean;
}

/**
 * Copilot CLI tool arguments worth scanning.
 *
 * Recorded: `bash`'s `toolArgs` carry `command`, `description`, `mode` and
 * `initial_wait` (see `test/fixtures/cli/README.md`). `command` executes;
 * `description` is model-authored prose that rides along with the call and can
 * be rewritten in place. `mode` and `initial_wait` are the tool's own dials and
 * carry no user text, so they are deliberately absent.
 *
 * `apply_patch` is the file-write tool this host names — seen in the session's
 * own tool-selection log, with no payload recorded for it. Its argument name is
 * therefore **unverified**, and a wrong name here costs a silent skip rather
 * than a wrong answer: the loop reads a field that is not there and scans
 * nothing. That is why it is stated here rather than left implicit.
 *
 * `view`, `rg`, `glob`, `read_bash`, `stop_bash`, `list_bash`, `web_fetch`,
 * `skill`, `sql` and `task` are absent on purpose: none of them carries text
 * the user or the model authored that this adapter can act on before it runs.
 */
export const CLI_SCANNABLE_FIELDS: Record<string, readonly ScannableField[]> = {
  bash: [
    { field: 'command', executable: true },
    { field: 'description', executable: false },
  ],
  apply_patch: [{ field: 'input', executable: false }],
};

/**
 * VS Code agent-mode tool inputs worth scanning.
 *
 * **Doc-derived, every row.** The tool ids are VS Code's own
 * (`run_in_terminal`, `create_file`, …) and the key names are their published
 * input schemas; no live session has confirmed either, and the table is written
 * FROM `test/fixtures/vscode-provisional/` rather than the fixtures being
 * written to match it. See that directory's README for the full list of what a
 * recording would settle.
 *
 * It matters more here than on the CLI that an unknown tool is cheap: VS Code
 * parses matchers and **ignores** them, so this hook is spawned for every tool
 * call the agent makes, including `read_file` and every `mcp_*`. The hook's
 * unknown-tool exit therefore runs before the config load and before the store
 * opens.
 */
export const VSCODE_SCANNABLE_FIELDS: Record<string, readonly ScannableField[]> = {
  run_in_terminal: [
    { field: 'command', executable: true },
    { field: 'explanation', executable: false },
  ],
  create_file: [{ field: 'content', executable: false }],
  replace_string_in_file: [{ field: 'newString', executable: false }],
  insert_edit_into_file: [{ field: 'code', executable: false }],
  apply_patch: [{ field: 'input', executable: false }],
};

/** The field table for a dialect. Never a merge of the two. */
export function scannableFieldsFor(dialect: Dialect): Record<string, readonly ScannableField[]> {
  return dialect === 'cli' ? CLI_SCANNABLE_FIELDS : VSCODE_SCANNABLE_FIELDS;
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
 * Code plugin's vault, the wizard's history scrub) can be echoed into a command
 * here, and executing one as literal text is never right.
 */
export function denyPointerMessage(toolName: string): string {
  return (
    `A vault pointer in a ${toolName} command cannot execute as text, and this plugin ` +
    'never substitutes a pointer back to its raw value. Remove the pointer from the ' +
    'command, or resolve the value yourself with `aka vault show` or the dashboard ' +
    'Vault page and retype what you need.'
  );
}

// ─── The two output shapes ───────────────────────────────────────────────────

/** A deny, in whichever shape the dialect takes. */
export function denyOutput(
  dialect: Dialect,
  reason: string,
):
  | {
      permissionDecision: 'deny';
      permissionDecisionReason: string;
    }
  | {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse';
        permissionDecision: 'deny';
        permissionDecisionReason: string;
      };
    } {
  return dialect === 'cli'
    ? { permissionDecision: 'deny', permissionDecisionReason: reason }
    : {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: reason,
        },
      };
}

/**
 * Everything this hook may put on stdout.
 *
 * A subset of `HookOutput` — `emit` narrows to that union, and this narrows
 * further to the shapes one event can legitimately produce. `modifiedResult`,
 * which belongs to `postToolUse`, is structurally unreachable from here.
 */
export type PreToolUseOutput =
  | ReturnType<typeof denyOutput>
  | { modifiedArgs: Record<string, unknown>; systemMessage: string }
  | {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse';
        permissionDecision: 'allow';
        updatedInput: Record<string, unknown>;
      };
      systemMessage: string;
    }
  | { systemMessage: string };

/**
 * The pointer pre-check the hook runs BEFORE the secret scan, and before the
 * store is opened: a vault pointer in an executable field denies the whole
 * call. Returns null when nothing denies. Pure over its inputs.
 */
export function decideInputPointerDeny(
  dialect: Dialect,
  toolName: string,
  toolInput: Record<string, unknown>,
  fields: readonly ScannableField[],
): PreToolUseOutput | null {
  const denies = fields.some((spec) => {
    const value = toolInput[spec.field];
    return spec.executable && typeof value === 'string' && pointerTokenScanner().test(value);
  });
  return denies ? denyOutput(dialect, denyPointerMessage(toolName)) : null;
}

/**
 * Collapse the per-field results into one decision.
 *
 * The redact channel is the one place the dialects genuinely diverge in
 * capability rather than in spelling: the CLI's `modifiedArgs` was **observed**
 * to replace the executed shell command, while VS Code's `updatedInput` is
 * documented, validated against the tool's own input schema, and **last hook
 * wins** — so a user's or repo's own hook returning one discards this. Neither
 * fact changes what is decided here; both are stated where the shape is built.
 */
export function decidePreToolUse(
  dialect: Dialect,
  toolName: string,
  toolInput: Record<string, unknown>,
  scanned: readonly ScannedField[],
): PreToolUseOutput | null {
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
    // note precedence below, so a presence check would let a command field
    // that merely WARNED displace the unredactable note on a deny that another
    // field alone caused — wrong on both halves of what it then says.
    //
    // A null `text` is different: it is a runtime failure on a field that CAN
    // be rewritten, leaving no redacted form to substitute. Emitting the
    // untouched input under the "AKA redacted" systemMessage would send the
    // raw value and report it as masked, so that one escalates here.
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
    const rewritten = updatedInput ?? { ...toolInput };
    const systemMessage = `AKA redacted sensitive content in ${toolName} input — flagged ${[...redactedRules].join(', ')}.${exceptionPointer(redactedReferences)}`;
    // Both dialects carry the WHOLE argument object rather than the changed
    // fields alone. On the CLI `modifiedArgs` replaces the call's arguments; on
    // VS Code `updatedInput` is validated against the tool's own input schema,
    // which a partial object fails.
    return dialect === 'cli'
      ? { modifiedArgs: rewritten, systemMessage }
      : {
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'allow',
            updatedInput: rewritten,
          },
          systemMessage,
        };
  }

  if (warnedRules.size > 0) {
    return {
      systemMessage: `AKA flagged sensitive content in ${toolName} input (${[...warnedRules].join(', ')}).`,
    };
  }
  return null;
}
