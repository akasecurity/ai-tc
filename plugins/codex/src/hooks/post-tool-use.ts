/**
 * PostToolUse — fires after a tool succeeds. Unlike Claude Code, Codex's
 * PostToolUse cannot rewrite the tool's output in place (no
 * `updatedToolOutput` field) — the strongest available action is
 * `{"decision":"block","reason":"..."}`, which replaces the WHOLE tool
 * result with `reason` and continues the model from there. See
 * scan-response.ts's module comment for why a `redact` outcome escalates to
 * this same whole-result withhold rather than attempting a partial splice.
 *
 * Scans `Bash` output, the `apply_patch` result string, the built-in web
 * tool's results (`webrun`) and MCP tool results (`mcp__*`) — see
 * tool-response.ts for each shape.
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
import { SOURCE_TOOL } from '@akasecurity/schema';

import {
  RESPONSE_SCAN_DEADLINE_MS,
  responseEmitPayload,
  scanResponseFields,
} from './scan-response.ts';
import {
  baseMetadata,
  captureScopeKey,
  countFailOpen,
  emit,
  getString,
  parseJson,
  readStdin,
} from './shared.ts';
import { warnIfStoreRedirected } from './store-health.ts';
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
  // Keyed by the file this response names (a relative path is read against the
  // cwd), else by the session's cwd when it names none; beside the metadata,
  // never inside it. See captureScopeKey.
  // An apply_patch result gets NO key, like the patch at PreToolUse: it reports
  // the paths the patch body names, which this hook does not parse.
  const scopeKey = rawToolName === 'apply_patch' ? undefined : captureScopeKey(input, filePath);

  const config = loadConfig();
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, getString(input, 'session_id'));
  const gateway = resolveDataGateway(config);
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });

  let outcome;
  try {
    outcome = await scanResponseFields(
      toolName,
      fields,
      (text) =>
        runtime.capture(
          { kind: 'response', sourceTool: SOURCE_TOOL.Codex, text, metadata, scopeKey },
          { persist: 'with-findings' },
        ),
      { at: RESPONSE_SCAN_DEADLINE_MS, now: () => performance.now() },
    );
  } finally {
    await runtime.close();
  }
  // Out of time before every field was scanned: what was found is still
  // acted on, and the rest passed through, so count it like any fail-open.
  if (outcome.unscannedFields > 0) countFailOpen();

  const payload = responseEmitPayload(outcome);
  if (payload !== undefined) await emit(payload);
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session — but count the exit, so
  // `aka status` can say the hooks have been failing open on this machine.
  countFailOpen();
}
process.exit(0);
