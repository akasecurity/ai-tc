/**
 * PostToolUse — fires after a tool succeeds. The tool already ran, so the
 * job here is to stop sensitive output from entering the model's context:
 * `updatedToolOutput` replaces what the model sees.
 *
 * stdin:  { tool_name, tool_input, tool_response, ... }
 * stdout (exit 0):
 *   {"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":...}}
 *     → model sees the replaced output
 *   {"systemMessage":"..."} → warning only
 *   no output → pass through
 *
 * tool_response arrives in the tool's native shape (Read: file.content, Bash:
 * stdout/stderr, WebFetch: result — see tool-response.ts), and updatedToolOutput
 * must be emitted in that same shape: Claude Code validates it against the
 * tool's output schema and falls back to the original output on mismatch.
 * TODO: extend RESPONSE_TEXT_PATHS as the matcher grows (MCP tools).
 * Fail-open: any error → no output, exit 0.
 */
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import { createPluginRuntime, createVaultGlue, loadConfig } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, SOURCE_TOOL } from '@akasecurity/schema';

import { sessionProtocolMarker } from '../protocol/marker.ts';
import { eventNote, userDisclosure } from '../protocol/notes.ts';
import type { ResponseScanOutcome } from './scan-response.ts';
import { responseEmitPayload, scanResponseFields } from './scan-response.ts';
import { baseMetadata, emit, getString, parseJson, readStdin } from './shared.ts';
import { scannableResponseFields } from './tool-response.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (!input) return;

  const rawToolName = getString(input, 'tool_name');
  const toolName = rawToolName ?? 'tool';
  // Field name differs across Claude Code versions; accept both — and when the
  // preferred field carries no scannable text (e.g. a structured shape this
  // matcher doesn't know), fall back to the other, which the old string-only
  // code scanned whenever tool_response wasn't a usable string.
  let response = input.tool_response ?? input.tool_output;
  let fields = scannableResponseFields(toolName, response);
  if (fields.length === 0 && input.tool_output !== undefined && response !== input.tool_output) {
    response = input.tool_output;
    fields = scannableResponseFields(toolName, response);
  }
  if (fields.length === 0) return;

  // Per-hook metadata layering (see shared.ts): Read carries the file being
  // read on tool_input.file_path — without it, extension-scoped rules never
  // apply to Read output and the recorded event has no file attribution.
  // The tool NAME is stamped too (never its arguments or output — metadata is
  // stored unredacted), so findings on file-less tool output (Bash, WebFetch…)
  // still carry a display location.
  const metadata = baseMetadata(input) ?? {};
  if (rawToolName) metadata.toolName = rawToolName;
  const rawToolInput = input.tool_input;
  const filePath =
    typeof rawToolInput === 'object' && rawToolInput !== null
      ? getString(rawToolInput as Record<string, unknown>, 'file_path')
      : undefined;
  if (filePath) metadata.filePath = filePath;

  // One runtime held across the field loop, like pre-tool-use: a per-field
  // handleCapture would re-open the store, re-parse the policy bundle, and
  // re-trigger sync per field — and could even evaluate two fields of one
  // response under different policy snapshots.
  const config = loadConfig();
  const gateway = resolveDataGateway(config);
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
  // Vaulting (and everything narrated about it) is consent-gated; without the
  // grant this hook behaves exactly as it did before the vault existed.
  const vaultGlue = isVaultConsentValid(config.settings.vaultConsent) ? createVaultGlue() : null;

  let outcome: ResponseScanOutcome;
  try {
    // persist:'with-findings': benign responses record nothing (matching the
    // pre-structured-scan behavior); 'always' would copy every Read file and
    // Bash stream verbatim into the local store on the three hottest tools.
    outcome = await scanResponseFields(
      toolName,
      response,
      fields,
      (text) =>
        runtime.capture(
          { kind: 'response', sourceTool: SOURCE_TOOL.ClaudeCode, text, metadata },
          { persist: 'with-findings' },
        ),
      vaultGlue
        ? (text, findings) =>
            vaultGlue.tokenizeText(text, {
              findings,
              sighting: filePath
                ? { location: filePath, kind: 'file' }
                : { location: `${toolName} output`, kind: 'tool-output' },
            })
        : undefined,
    );
  } finally {
    await runtime.close();
  }

  // The model note + user disclosure ride only on a tokenized outcome; a
  // narration fault drops the notes, never the rewrite.
  let notes: { note?: string | null; disclosure?: string | null } | undefined;
  if (outcome.realized) {
    try {
      const surface = `${toolName} output`;
      const marker = sessionProtocolMarker(config.dataDir, getString(input, 'session_id'));
      notes = {
        note: eventNote({ marker, surface, realized: outcome.realized }),
        disclosure: userDisclosure({ surface, realized: outcome.realized }),
      };
    } catch {
      notes = undefined;
    }
  }

  const payload = responseEmitPayload(toolName, outcome, notes);
  if (payload !== undefined) await emit(payload);
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
