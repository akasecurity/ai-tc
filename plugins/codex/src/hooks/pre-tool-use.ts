/**
 * PreToolUse — fires before a tool call executes. Same hookSpecificOutput
 * shape as Claude Code's PreToolUse (confirmed against
 * developers.openai.com/codex/hooks): `updatedInput` replaces the tool's
 * arguments for redact-in-place fields; an executable field escalates a
 * redact to a deny instead (see pre-tool-use-decision.ts).
 *
 * CAVEAT (see pre-tool-use-decision.ts's SCANNABLE_FIELDS comment): today
 * Codex only reliably fires this hook for `Bash` calls, not `apply_patch` —
 * the `apply_patch` matcher/field entry here is forward-compatible but
 * currently inert.
 *
 * stdin:  { tool_name, tool_input, session_id, ... }
 * stdout (exit 0):
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
 *     → tool call blocked
 *   {"hookSpecificOutput":{...,"permissionDecision":"allow","updatedInput":{...}}}
 *     → tool runs with redacted input
 *   no output → allow unchanged
 *
 * Fail-open: any error → no output, exit 0.
 */
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import type { ScannedField } from './pre-tool-use-decision.ts';
import {
  decideInputPointerDeny,
  decidePreToolUse,
  SCANNABLE_FIELDS,
} from './pre-tool-use-decision.ts';
import { baseMetadata, emit, getString, parseJson, readStdin } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from './store-health.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (!input) return;

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
  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    if (claimStoreUnavailableWarning(config.dataDir, getString(input, 'session_id'))) {
      await emit({ systemMessage: storeUnavailableMessage(config.dbPath) });
    }
    return;
  }
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });

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

  const scanned: ScannedField[] = [];
  try {
    for (const spec of fields) {
      const value = toolInput[spec.field];
      if (typeof value !== 'string' || value === '') continue;

      const result = await runtime.capture(
        { kind, sourceTool: SOURCE_TOOL.Codex, text: value, metadata },
        kind === 'tool_use' ? { persist: 'with-findings' } : {},
      );
      scanned.push({ spec, result });
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
  // Fail-open: never break the user's session
}
process.exit(0);
