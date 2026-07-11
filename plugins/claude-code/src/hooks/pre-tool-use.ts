/**
 * PreToolUse — fires before a tool call executes. The one surface where true
 * redaction works: `updatedInput` replaces the tool's arguments — but only
 * for fields whose text is handed onward as data (Write/Edit content, the
 * WebFetch analysis prompt). A redact decision on an executable field (Bash
 * `command`, WebFetch `url`) escalates to deny instead: masking inside it
 * would silently change what runs (see pre-tool-use-decision.ts for the
 * collapse rules).
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

import type { ScannedField } from './pre-tool-use-decision.ts';
import { decidePreToolUse, SCANNABLE_FIELDS } from './pre-tool-use-decision.ts';
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
  const fields = SCANNABLE_FIELDS[toolName];
  const rawToolInput = input.tool_input;
  if (!fields || typeof rawToolInput !== 'object' || rawToolInput === null) return;

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
  // Unlike post-tool-use (which delegates to handleCapture), this hook drives
  // the runtime directly. handleCapture always calls runtime.capture, which
  // records the event — but Bash must be enforced inline WITHOUT recording, so
  // this hook chooses capture (Write/Edit) vs processText (Bash/WebFetch) per
  // field below, a split handleCapture does not expose. Holding one runtime
  // across the SCANNABLE_FIELDS loop also avoids opening/closing it per field.
  // We own its lifetime here and close it in the `finally` below.
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });

  const toolInput = { ...(rawToolInput as Record<string, unknown>) };
  // Write/Edit author durable content worth recording (kind: code_change).
  // Bash and WebFetch are enforced inline but not recorded — EventKind has no
  // 'tool_use' yet.
  const recordable = toolName === 'Write' || toolName === 'Edit';
  const metadata = baseMetadata(input) ?? {};
  const filePath = getString(toolInput, 'file_path');
  if (filePath) metadata.filePath = filePath;

  const scanned: ScannedField[] = [];
  try {
    for (const spec of fields) {
      const value = toolInput[spec.field];
      if (typeof value !== 'string' || value === '') continue;

      // capture persists (Write/Edit); processText enforces without recording (Bash/WebFetch).
      const result = await (recordable
        ? runtime.capture({ kind: 'code_change', sourceTool: 'claude-code', text: value, metadata })
        : runtime.processText(value));
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
