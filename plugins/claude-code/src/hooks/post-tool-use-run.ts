// The PostToolUse pipeline, free of stdio so two callers share it: the command
// hook (post-tool-use.ts, which reads stdin and writes stdout) and the hook
// server (hook-server/handlers.ts, which answers over its socket). One
// implementation is how the two cannot decide a response differently. What the
// hook does and how it behaves are described in post-tool-use.ts.
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { createPluginRuntime, createVaultGlue, loadConfig } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, SOURCE_TOOL } from '@akasecurity/schema';

import type { PointersByText } from '../mod/findings-log.ts';
import { pointersByFinding, recordModFindings, toolFieldAction } from '../mod/findings-log.ts';
import { sessionProtocolMarker } from '../protocol/marker.ts';
import { eventNote, userDisclosure } from '../protocol/notes.ts';
import { resolveHookAccount, stampFor } from './account-stamp.ts';
import { postToolUseForward } from './capture-forward.ts';
import { isMcpTool, MCP_OUTPUT_SESSION_MARKER } from './decoded-content.ts';
import { warnIfHostBelowFloor } from './host-floor-notice.ts';
import { largeInputBound } from './large-input.ts';
import type { ResponseScanOutcome } from './scan-response.ts';
import {
  RESPONSE_SCAN_DEADLINE_MS,
  responseEmitPayload,
  scanResponseFields,
} from './scan-response.ts';
import type { HookOutput } from './shared.ts';
import {
  baseMetadata,
  captureScopeKey,
  countFailOpen,
  getString,
  searchRootScopeKey,
} from './shared.ts';
import { captureStamped } from './stamped-capture.ts';
import { markSession, openGateway, warnIfStoreRedirected } from './store-health.ts';
import { collectResponseFields } from './tool-response.ts';

export async function runPostToolUse(
  input: Record<string, unknown>,
  emit: (output: HookOutput) => Promise<void>,
): Promise<void> {
  const rawToolName = getString(input, 'tool_name');
  const toolName = rawToolName ?? 'tool';
  // Field name differs across Claude Code versions; accept both — and when the
  // preferred field carries no scannable text (e.g. a structured shape this
  // matcher doesn't know), fall back to the other, which the old string-only
  // code scanned whenever tool_response wasn't a usable string.
  let response = input.tool_response ?? input.tool_output;
  let { fields, truncated } = collectResponseFields(toolName, response);
  if (fields.length === 0 && input.tool_output !== undefined && response !== input.tool_output) {
    response = input.tool_output;
    ({ fields, truncated } = collectResponseFields(toolName, response));
  }
  if (fields.length === 0) return;
  const earlySessionId = getString(input, 'session_id');
  if (rawToolName !== undefined && earlySessionId !== undefined && isMcpTool(rawToolName)) {
    markSession(loadConfig().dataDir, MCP_OUTPUT_SESSION_MARKER, earlySessionId);
  }

  // Per-hook metadata layering (see shared.ts): Read carries the file being
  // read on tool_input.file_path — without it, extension-scoped rules never
  // apply to Read output and the recorded event has no file attribution.
  // The tool NAME is stamped too (never its arguments or output — metadata is
  // stored unredacted), so findings on file-less tool output (Bash, WebFetch…)
  // still carry a display location.
  const metadata = baseMetadata(input) ?? {};
  if (rawToolName) metadata.toolName = rawToolName;
  const rawToolInput = input.tool_input;
  const toolInput =
    typeof rawToolInput === 'object' && rawToolInput !== null
      ? (rawToolInput as Record<string, unknown>)
      : undefined;
  const filePath = toolInput === undefined ? undefined : getString(toolInput, 'file_path');
  if (filePath) metadata.filePath = filePath;
  // Keyed by the file the call names (a relative path is read against the cwd),
  // else by the session's cwd when it names none: see captureScopeKey. The file
  // is `file_path`, else `notebook_path`, as at PreToolUse (inputFilePath), so an
  // MCP tool that names a notebook is keyed where the notebook is. Only
  // `file_path` is stamped on the event: the metadata is a wire shape and this
  // hook has only ever carried that one. A Grep names no file but the root it
  // searched (`tool_input.path`, a directory or one file), and its output is what
  // is recorded, so it is keyed by that root the same way: see
  // searchRootScopeKey. Beside the metadata rather than in it: the key is local,
  // the metadata is wire. The capture is stamped with it for the session's
  // account (stampFor).
  const keyedPath =
    filePath ?? (toolInput === undefined ? undefined : getString(toolInput, 'notebook_path'));
  const repoKey =
    rawToolName === 'Grep'
      ? searchRootScopeKey(
          input,
          toolInput === undefined ? undefined : getString(toolInput, 'path'),
        )
      : captureScopeKey(input, keyedPath);

  // One runtime held across the field loop, like pre-tool-use: a per-field
  // handleCapture would re-open the store, re-parse the policy bundle, and
  // re-trigger sync per field — and could even evaluate two fields of one
  // response under different policy snapshots.
  const config = loadConfig();
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, getString(input, 'session_id'));
  // See host-floor-notice.ts: PostToolUse is the other event whose newest
  // transcript record is guaranteed to belong to the running host.
  warnIfHostBelowFloor(config, getString(input, 'session_id'), getString(input, 'transcript_path'));
  const sessionId = getString(input, 'session_id');
  const opened = openGateway(config);
  // Opening the store is part of the hook: a store that will not open fails the
  // call open, as it always has.
  if (opened.gateway === null) throw opened.error;
  const gateway = opened.gateway;
  const scopeKey = stampFor(
    gateway,
    resolveHookAccount(gateway, {
      dataDir: config.dataDir,
      sessionId,
      transcriptPath: getString(input, 'transcript_path'),
      cwd: getString(input, 'cwd'),
    }),
    repoKey,
  );
  // A field at or above the large-input threshold is scanned under what is left
  // of the field loop's own deadline, and withheld if that scan does not finish
  // (see large-input.ts).
  const runtime = createPluginRuntime(gateway, config.settings, {
    dataDir: config.dataDir,
    largeInput: largeInputBound(RESPONSE_SCAN_DEADLINE_MS),
  });
  // Vaulting (and everything narrated about it) is consent-gated; without the
  // grant this hook behaves exactly as it did before the vault existed.
  const vaultGlue = isVaultConsentValid(config.settings.vaultConsent) ? createVaultGlue() : null;

  // Set only when the organization forwards this repository's tool output and
  // this session's mod, which marks it at its tool-result door, is not running.
  const forward = postToolUseForward(config.dataDir, sessionId, repoKey);

  let outcome: ResponseScanOutcome;
  const capturedFields: { text: string; result: CaptureResult }[] = [];
  const vaulted: PointersByText = new Map();
  try {
    // persist:'with-findings': benign responses record nothing (matching the
    // pre-structured-scan behavior); 'always' would copy every Read file and
    // Bash stream verbatim into the local store on the three hottest tools.
    outcome = await scanResponseFields(
      toolName,
      response,
      fields,
      async (text) => {
        const result = await captureStamped(
          runtime,
          { kind: 'response', sourceTool: SOURCE_TOOL.ClaudeCode, text, metadata },
          scopeKey,
          { persist: 'with-findings', ...(forward === undefined ? {} : { forward }) },
        );
        capturedFields.push({ text, result });
        return result;
      },
      vaultGlue
        ? async (text, findings, reversible) => {
            const tokenized = await vaultGlue.tokenizeText(text, {
              findings,
              reversible,
              sighting: filePath
                ? { location: filePath, kind: 'file' }
                : { location: `${toolName} output`, kind: 'tool-output' },
            });
            try {
              vaulted.set(text, pointersByFinding(findings, reversible, tokenized.pointers));
            } catch {
              // A record of the pointers never changes the rewrite.
            }
            return tokenized;
          }
        : undefined,
      { at: RESPONSE_SCAN_DEADLINE_MS, now: () => performance.now() },
    );
  } finally {
    await runtime.close();
  }
  if (sessionId !== undefined) {
    for (const { text, result } of capturedFields) {
      const pointers = vaulted.get(text);
      recordModFindings(config.dataDir, sessionId, {
        sessionId,
        kind: 'response',
        text,
        result,
        where: 'tool-output',
        action: toolFieldAction(result, pointers),
        pointers,
      });
    }
  }
  // Out of time before every field was scanned, or the response bounds cut
  // text out of the fields: what was found is still acted on, and the rest
  // passed through, so count it like any fail-open.
  // A field that was reached but whose bounded scan did not finish is not
  // counted here: it was withheld, not passed (outcome.tooLargeFields).
  if (outcome.unscannedFields > 0 || truncated) countFailOpen();

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
