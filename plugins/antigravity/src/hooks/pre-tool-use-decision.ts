// The pure decision half of the PreToolUse hook: collapse the per-field
// runtime results into the hook's stdout payload. Pure object building (no
// I/O) so it unit-tests without a hook process — hook entry files run main()
// on import and must NEVER be imported by tests (same split as
// exception-guidance.ts).
//
// TWO THINGS DIFFER FROM THE CLAUDE CODE AND CODEX SIBLINGS.
//
// 1. The output is a FLAT `{ decision }`, not Claude Code's nested
//    `hookSpecificOutput.permissionDecision`. Antigravity's decision vocabulary
//    is allow | deny | ask | force_ask. Only `allow` and `deny` are ever
//    emitted here: `ask`/`force_ask` hand the call to the user's own approval
//    prompt, which is a policy this plugin does not own — a detection that
//    warrants stopping the call stops it, and one that does not gets out of the
//    way.
//
// 2. THERE IS NO FIELD FOR REWRITING TOOL ARGUMENTS. Claude Code's PreToolUse
//    carries `updatedInput`, so a `redact` policy rewrites the argument in
//    place and lets the call run. Antigravity's PreToolUse output is
//    `{ decision, reason, permissionOverrides }` and nothing else, so there is
//    no in-place redaction on this host AT ALL — not just for executable fields
//    the way Codex escalates. Every `redact` decision therefore escalates to a
//    deny with removal-based guidance, and the note below says so, because
//    allowing the call would send the raw value on unchanged.
//
// A `warn` cannot be surfaced on this event either: the output has no
// systemMessage/additionalContext channel, and `reason` accompanies a
// deny/ask. A warned finding is still captured and ledgered — it just carries
// no inline notice in the Antigravity session (see skills/setup/SKILL.md,
// "Known limitations").
import type { BlockedDetectionRef, CaptureResult } from '@akasecurity/plugin-sdk';
import { pointerTokenScanner } from '@akasecurity/schema';

import { blockMessage, exceptionPointer } from '../exception-guidance.ts';

// Which tool args carry user-authored text worth scanning, and whether that
// text EXECUTES. `executable` no longer changes whether a redact escalates
// (every redact escalates here — see the module header); it selects the
// wording of the deny and gates the vault-pointer pre-check, which only ever
// fires on text the host is about to run.
//
// UNVERIFIED AGAINST A LIVE HOST: the arg names below come from Antigravity's
// published tool reference (`run_command` takes `CommandLine`; `write_to_file`
// takes `TargetFile`/`CodeContent`; `replace_file_content` takes
// `TargetFile`/`TargetContent`/`ReplacementContent`) rather than from an
// observed payload — the hook contract documents the envelope but not the
// per-tool arg schemas. A name that turns out to be wrong scans nothing and
// denies nothing: it degrades to allow, never to a false block.
//
// `multi_replace_file_content` is deliberately ABSENT: its args nest the edits
// in a list whose shape is not documented, and a guessed field name on a
// container type would silently scan nothing while reading as covered. File
// content written through it is caught after the fact by the history backfill
// scan (../history/scan.ts), not before it lands.
//
// Read-only tools (`view_file`, `grep_search`, `code_search`) are absent on
// purpose: their args name what to look at, and their RESULTS are what can
// carry a secret — that is PostToolUse's job (see tool-response.ts).
export interface ScannableField {
  field: string;
  executable: boolean;
}

export const SCANNABLE_FIELDS: Record<string, readonly ScannableField[]> = {
  run_command: [{ field: 'CommandLine', executable: true }],
  write_to_file: [{ field: 'CodeContent', executable: false }],
  // Only the text that LANDS on disk. `TargetContent` is the text being
  // replaced — already in the file, and flagging it would fire on exactly the
  // edit that REMOVES a secret.
  replace_file_content: [{ field: 'ReplacementContent', executable: false }],
};

// One scanned field: its spec plus the runtime's decision for the field text.
export interface ScannedField {
  spec: ScannableField;
  result: CaptureResult;
}

// Woven into the deny message when a redact decision was escalated. Unlike the
// Codex sibling this is not limited to executable fields: Antigravity's
// PreToolUse cannot rewrite any argument, so a redact policy always lands here.
export const NO_REWRITE_REDACT_NOTE =
  'Antigravity gives a PreToolUse hook no way to rewrite a tool argument, so a redact policy blocks the call instead of masking in place.';

// The deny reason when a vault pointer appears in a field that EXECUTES. This
// plugin has no vault wiring, so it never substitutes a pointer back to its raw
// value — but pointers minted elsewhere on the same machine (the Claude Code
// plugin's vault, the wizard's history scrub) can be echoed into a command
// here, and executing one as literal text is never right.
export function denyPointerMessage(toolName: string): string {
  return (
    `A vault pointer in a ${toolName} argument cannot execute as text, and this plugin ` +
    'never substitutes a pointer back to its raw value. Remove the pointer from the ' +
    'command, or resolve the value yourself with `aka vault show` or the dashboard ' +
    'Vault page and retype what you need.'
  );
}

/** Antigravity's PreToolUse stdout contract. */
export type PreToolUseDecision = 'allow' | 'deny' | 'ask' | 'force_ask';

export interface PreToolUseOutput {
  decision: PreToolUseDecision;
  reason?: string;
}

/** The payload that lets a call through untouched — also the fail-open payload. */
export const ALLOW: PreToolUseOutput = { decision: 'allow' };

// The pointer pre-check the hook runs BEFORE the secret scan (and before the
// store is opened): a vault pointer in an executable field denies the whole
// call. Returns null when nothing denies. Pure over its inputs so it
// unit-tests without a hook process.
export function decideInputPointerDeny(
  toolName: string,
  args: Record<string, unknown>,
  fields: readonly ScannableField[],
): PreToolUseOutput | null {
  const denies = fields.some((spec) => {
    const value = args[spec.field];
    return spec.executable && typeof value === 'string' && pointerTokenScanner().test(value);
  });
  if (!denies) return null;
  return { decision: 'deny', reason: denyPointerMessage(toolName) };
}

export function decidePreToolUse(
  toolName: string,
  scanned: readonly ScannedField[],
): PreToolUseOutput {
  const blockedRules = new Set<string>();
  const blockedReferences: BlockedDetectionRef[] = [];
  let escalated = false;

  for (const { result } of scanned) {
    // Every redact escalates: there is no argument-rewrite channel on this
    // host, so masking in place is not an option the payload can express.
    if (result.action === 'redact') escalated = true;
    if (result.action !== 'block' && result.action !== 'redact') continue;

    for (const finding of result.findings) blockedRules.add(finding.ruleId);
    if (result.blockedReferences) blockedReferences.push(...result.blockedReferences);
  }

  if (blockedRules.size === 0) return ALLOW;

  return {
    decision: 'deny',
    reason:
      blockMessage({
        subject: `${toolName} call`,
        ruleIds: [...blockedRules].join(', '),
        blockedRef: blockedReferences[0],
        note: escalated ? NO_REWRITE_REDACT_NOTE : undefined,
      }) + exceptionPointer(blockedReferences),
  };
}
