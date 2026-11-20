/**
 * postToolUse — fires after an agent tool call succeeds, with its output.
 *
 * stdin:  { conversation_id, hook_event_name, tool_name, tool_input,
 *           tool_output, tool_use_id, cwd, duration, … }
 * stdout: nothing, on every path. The tool has already run and this adapter
 *         has no confirmed channel to withhold its output (see
 *         ./scan-response.ts).
 * stderr: what was flagged or left unscanned, and the store warnings.
 *
 * A result with findings is recorded; a clean one is not. This module is the
 * handler and nothing else; `./post-tool-use.ts` is the entry that feeds it.
 */
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { isOwnEvent } from './event-name.ts';
import { hookLargeInputBound } from './large-input.ts';
import { readPayloadEvent, readSessionId, readToolCall } from './payload.ts';
import { responseNotice, scanResponseFields } from './scan-response.ts';
import type { HookHandler } from './shared.ts';
import {
  baseMetadata,
  callKind,
  callScopeKey,
  countFailOpen,
  parseJson,
  writeNotice,
} from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGateway,
  storeDegradedMessage,
  warnIfStoreRedirected,
} from './store-health.ts';
import { scannableFields } from './tool-response.ts';

export const runPostToolUse: HookHandler = async (event, stdin, options = {}) => {
  const input = parseJson(stdin);
  if (!input) return undefined;
  if (!isOwnEvent('postToolUse', event, readPayloadEvent(input))) return undefined;

  const call = readToolCall(input);
  if (call === undefined) return undefined;

  const collected = scannableFields(input.tool_output);
  if (collected.fields.length === 0 && !collected.truncated) return undefined;

  const config = loadConfig(options.akaHome);
  const sessionId = readSessionId(input);
  warnIfStoreRedirected(config, sessionId);
  const { gateway, error } = openGateway(config);
  if (gateway === null) {
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      writeNotice(storeDegradedMessage(config.dbPath, error));
    }
    return undefined;
  }

  const runtime = createPluginRuntime(gateway, config.settings, {
    dataDir: config.dataDir,
    largeInput: hookLargeInputBound(false),
    ...(options.scanWorkerUrl === undefined
      ? {}
      : { scanIsolation: { workerUrl: options.scanWorkerUrl } }),
  });
  const metadata = baseMetadata(input);
  metadata.toolName = call.name;
  const scopeKey = callScopeKey(callKind(call.name), input, call);

  let outcome;
  try {
    outcome = await scanResponseFields(call.name, collected, (text) =>
      runtime.capture(
        { kind: 'response', sourceTool: SOURCE_TOOL.Cursor, text, metadata, scopeKey },
        { persist: 'with-findings', rewritable: false },
      ),
    );
  } finally {
    await runtime.close();
  }

  if (outcome.unscanned) countFailOpen(options.countFailOpen);

  const notice = responseNotice(outcome);
  if (notice !== undefined) writeNotice(notice);
  return undefined;
};
