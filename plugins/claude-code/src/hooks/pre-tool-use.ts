/**
 * PreToolUse — fires before a tool call executes. The one surface where true
 * redaction works: `updatedInput` replaces the tool's arguments — but only
 * for fields whose text is handed onward as data (Write/Edit/MultiEdit
 * content, the WebFetch and Task prompts). A redact decision on an executable
 * field (Bash `command`, WebFetch `url`, any MCP argument) escalates to deny
 * instead: masking inside it would silently change what runs. See
 * pre-tool-use-fields.ts for the per-tool field map and
 * pre-tool-use-decision.ts for the collapse rules.
 *
 * stdin:  { tool_name, tool_input, session_id, ... }
 * stdout (exit 0):
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
 *     → tool call blocked
 *   {"hookSpecificOutput":{...,"permissionDecision":"allow","updatedInput":{...}}}
 *     → tool runs with redacted input (Write/Edit only)
 *   no output → allow unchanged
 *
 * Fail-open: any error → no output, exit 0.
 */
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';

import { stringAtPath } from './paths.ts';
import type { ScannedField } from './pre-tool-use-decision.ts';
import { decidePreToolUse } from './pre-tool-use-decision.ts';
import { inputEventKind, inputFilePath, scannableInputFields } from './pre-tool-use-fields.ts';
import { baseMetadata, emit, getString, parseJson, readStdin } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
} from './store-health.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (!input) return;

  const toolName = getString(input, 'tool_name') ?? '';
  const rawToolInput = input.tool_input;
  if (typeof rawToolInput !== 'object' || rawToolInput === null) return;

  // Resolved before the store is opened: the matcher is broad enough to spawn
  // this hook for MCP tools whose payload carries no scannable text, and those
  // calls should cost nothing.
  const toolInput = rawToolInput as Record<string, unknown>;
  const fields = scannableInputFields(toolName, toolInput);
  if (fields.length === 0) return;

  const config = loadConfig();
  // A store that cannot open means NOTHING is scanned or enforced for this
  // call. Still allow — fail-open — but say so once per session instead of
  // silently passing everything through.
  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    if (claimStoreUnavailableWarning(config.dataDir, getString(input, 'session_id'))) {
      await emit({ systemMessage: storeUnavailableMessage(config.dbPath) });
    }
    return;
  }
  // One runtime held across the field loop: a per-field open would re-parse the
  // policy bundle and could even evaluate two fields of one payload under
  // different policy snapshots. We own its lifetime here and close it in the
  // `finally` below.
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });

  const kind = inputEventKind(toolName);
  // The tool NAME rides in the metadata (never its arguments — metadata is
  // stored unredacted), so findings on file-less captures (a Bash command, an
  // MCP payload) still carry a display location.
  const metadata = baseMetadata(input) ?? {};
  if (toolName) metadata.toolName = toolName;
  const filePath = inputFilePath(toolInput);
  if (filePath) metadata.filePath = filePath;

  const scanned: ScannedField[] = [];
  try {
    for (const spec of fields) {
      const text = stringAtPath(toolInput, spec.path);
      if (text === undefined || text === '') continue;

      const result = await runtime.capture(
        { kind, sourceTool: 'claude-code', text, metadata },
        // code_change keeps the default 'always': those events are the at-rest
        // trail the re-scan resolver reconciles against, so a benign one still
        // has to exist. tool_use records only what was flagged — this hook sees
        // every Bash command and one call per string leaf of every MCP payload,
        // and 'always' would copy that whole stream into the store to trail the
        // enforcement decisions that are the point of the kind.
        kind === 'tool_use' ? { persist: 'with-findings' } : {},
      );
      scanned.push({ spec, result });
    }
  } finally {
    await runtime.close();
  }

  // Collapse the per-field runtime results into the hook payload (pure module),
  // then flush it. `await` the emit so stdout drains before process.exit — main's
  // hook-flush fix (commit 7eb59e55) applies here too.
  const output = decidePreToolUse(toolName, toolInput, scanned);
  if (output) await emit(output);
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
