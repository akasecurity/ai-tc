/**
 * PreToolUse — fires before a tool call executes. Same hookSpecificOutput
 * shape as Claude Code's PreToolUse (confirmed against
 * developers.openai.com/codex/hooks): `updatedInput` replaces the tool's
 * arguments for redact-in-place fields; an executable field escalates a
 * redact to a deny instead (see pre-tool-use-decision.ts).
 *
 * Fires for `Bash` and `apply_patch`, also when nested inside a code-mode
 * `exec` (see pre-tool-use-decision.ts's SCANNABLE_FIELDS comment). Each
 * apply_patch call is recorded in the local store whole, masked, at the
 * default persist ('always'), like file writes on the other hosts; see the
 * `kind` comment below and the setup skill's "Known limitations".
 *
 * stdin:  { tool_name, tool_input, session_id, ... }
 * stdout (exit 0):
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
 *     → tool call blocked (also when a field is too large to scan in time)
 *   {"hookSpecificOutput":{...,"permissionDecision":"allow","updatedInput":{...}}}
 *     → tool runs with redacted input
 *   no output → allow unchanged
 *
 * Fail-open: any error → no output, exit 0.
 */
import { createPluginRuntime, dataDir, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { codexToolStamp, threadAccountKey } from './account-stamp.ts';
import { denyIfSessionHeld } from './capture-forward.ts';
import { HOOK_SCAN_DEADLINE_MS, largeInputBound } from './large-input.ts';
import type { ScannedField } from './pre-tool-use-decision.ts';
import {
  decideInputPointerDeny,
  decidePreToolUse,
  SCANNABLE_FIELDS,
} from './pre-tool-use-decision.ts';
import { baseMetadata, countFailOpen, emit, getString, parseJson, readStdin } from './shared.ts';
import { captureStamped } from './stamped-capture.ts';
import {
  claimStoreUnavailableWarning,
  openGateway,
  storeDegradedMessage,
  warnIfStoreRedirected,
} from './store-health.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (!input) return;

  // A session the deployment holds refuses every tool call this hook sees.
  if (await denyIfSessionHeld(dataDir(), input, emit)) return;

  const toolName = getString(input, 'tool_name') ?? '';
  const fields = SCANNABLE_FIELDS[toolName];
  const rawToolInput = input.tool_input;
  if (!fields || typeof rawToolInput !== 'object' || rawToolInput === null) return;

  // A model-echoed vault pointer in text that EXECUTES is decided before the
  // secret scan (and before the store is even opened): this plugin never
  // substitutes pointers, so an ungranted pointer must deny outright rather
  // than run as literal text. Pointers reach Codex from the same machine's
  // vault surfaces (the Claude Code plugin, the wizard's history scrub).
  const pointerDeny = decideInputPointerDeny(
    toolName,
    rawToolInput as Record<string, unknown>,
    fields,
  );
  if (pointerDeny) {
    await emit(pointerDeny);
    return;
  }

  const config = loadConfig();
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, getString(input, 'session_id'));
  const opened = openGateway(config);
  if (opened.gateway === null) {
    if (claimStoreUnavailableWarning(config.dataDir, getString(input, 'session_id'))) {
      await emit({ systemMessage: storeDegradedMessage(config.dbPath, opened.error) });
    }
    return;
  }
  const gateway = opened.gateway;
  // A field at or above the large-input threshold is scanned under a deadline
  // shared by every field of this call, and refused if that scan does not
  // finish (see large-input.ts).
  const runtime = createPluginRuntime(gateway, config.settings, {
    dataDir: config.dataDir,
    largeInput: largeInputBound(HOOK_SCAN_DEADLINE_MS),
  });

  const toolInput = { ...(rawToolInput as Record<string, unknown>) };
  // apply_patch's input is durable content the agent authors, recorded as
  // 'code_change' with the default persist ('always' — the at-rest trail the
  // re-scan resolver reconciles against). Bash commands are text the host acts
  // on, recorded as 'tool_use' at persist 'with-findings': this hook sees
  // every command, and 'always' would copy that whole stream into the store
  // to trail the enforcement decisions that are the point of the kind. Same
  // split as Claude Code's Write/Edit vs Bash.
  const kind = toolName === 'apply_patch' ? 'code_change' : 'tool_use';
  const metadata = baseMetadata(input) ?? {};
  if (toolName) metadata.toolName = toolName;
  // Bash is keyed by the session cwd: it names no file this hook reads. An
  // apply_patch gets no repository key. It is recorded whole (persist 'always')
  // and names its files inside the patch body (`tool_input.command`), which this
  // hook does not parse, so the cwd's key could name a checkout the patch never
  // wrote. A scoped attachment keeps a keyless capture local (the gateway's
  // verdict), so no key is a coverage gap and never a leak. In a work thread, a
  // Bash call outside an enrolled repository and every apply_patch get the
  // thread's agent key instead. Beside the metadata, never inside it.
  const scopeKey = codexToolStamp(
    gateway,
    input,
    toolName,
    threadAccountKey(gateway, {
      dataDir: config.dataDir,
      sessionId: getString(input, 'session_id'),
      transcriptPath: getString(input, 'transcript_path'),
      nowMs: Date.now(),
    }),
  );

  const scanned: ScannedField[] = [];
  try {
    for (const spec of fields) {
      const value = toolInput[spec.field];
      if (typeof value !== 'string' || value === '') continue;

      const result = await captureStamped(
        runtime,
        { kind, sourceTool: SOURCE_TOOL.Codex, text: value, metadata },
        scopeKey,
        {
          ...(kind === 'tool_use' ? { persist: 'with-findings' as const } : {}),
          // Per FIELD: a field that EXECUTES cannot be masked in place, because
          // rewriting a command changes what runs. The stored `apply_patch`
          // field can be, and keeps true redaction. A redact on the executable
          // one degrades to the configured `redactFallback` inside the runtime,
          // where the emitted decision, the recorded action and the ledger all
          // read one answer.
          rewritable: !spec.executable,
        },
      );
      scanned.push({ spec, result });
      // A refused field denies the whole call (decidePreToolUse), so scanning
      // the rest would only spend the time the deadline is there to protect.
      if (result.scanIncomplete !== undefined) break;
    }
  } finally {
    await runtime.close();
  }

  const output = decidePreToolUse(toolName, toolInput, scanned);
  if (output) await emit(output);
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session — but count the exit, so
  // `aka status` can say the hooks have been failing open on this machine.
  countFailOpen();
}
process.exit(0);
