/**
 * PostToolUse — fires after a tool succeeds. Unlike Claude Code, Codex's
 * PostToolUse cannot rewrite the tool's output in place (no
 * `updatedToolOutput` field) — the strongest available action is
 * `{"decision":"block","reason":"..."}`, which replaces the WHOLE tool
 * result with `reason` and continues the model from there. See
 * scan-response.ts's module comment for why a `redact` outcome escalates to
 * this same whole-result withhold rather than attempting a partial splice.
 *
 * Only `Bash` is scanned today — PostToolUse does not fire for `apply_patch`
 * yet (see pre-tool-use-decision.ts).
 *
 * stdin:  { tool_name, tool_input, tool_response, ... }
 * stdout (exit 0):
 *   {"decision":"block","reason":"...","systemMessage":"..."} → tool result withheld
 *   {"systemMessage":"..."} → warning only
 *   no output → pass through
 *
 * Fail-open: any error → no output, exit 0.
 */
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';

import { responseEmitPayload, scanResponseFields } from './scan-response.ts';
import { baseMetadata, emit, getString, parseJson, readStdin } from './shared.ts';
import { scannableResponseFields } from './tool-response.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (!input) return;

  const rawToolName = getString(input, 'tool_name');
  const toolName = rawToolName ?? 'tool';
  const response = input.tool_response ?? input.tool_output;
  const fields = scannableResponseFields(toolName, response);
  if (fields.length === 0) return;

  const metadata = baseMetadata(input) ?? {};
  // The RAW name only — an absent tool_name must not be recorded as the
  // literal 'tool' placeholder the display fallback uses.
  if (rawToolName) metadata.toolName = rawToolName;
  const rawToolInput = input.tool_input;
  const filePath =
    typeof rawToolInput === 'object' && rawToolInput !== null
      ? getString(rawToolInput as Record<string, unknown>, 'file_path')
      : undefined;
  if (filePath) metadata.filePath = filePath;

  const config = loadConfig();
  const gateway = resolveDataGateway(config);
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });

  let outcome;
  try {
    outcome = await scanResponseFields(toolName, fields, (text) =>
      runtime.capture(
        { kind: 'response', sourceTool: 'codex', text, metadata },
        { persist: 'with-findings' },
      ),
    );
  } finally {
    await runtime.close();
  }

  const payload = responseEmitPayload(outcome);
  if (payload !== undefined) await emit(payload);
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
