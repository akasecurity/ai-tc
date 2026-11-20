/**
 * beforeSubmitPrompt — fires when the user sends a prompt, before it reaches
 * the model.
 *
 * stdin:  { conversation_id, hook_event_name, prompt, attachments,
 *           workspace_roots, model, … }
 * stdout: {"continue":false,"user_message":"…"} → the prompt is not sent
 *           (also when it is too large to scan in time)
 *         nothing                               → no opinion
 * stderr: a warn, and the store warnings, once per session where they apply.
 *
 * Every non-empty prompt is recorded, findings or not, because the prompt is
 * the session's own transcript. This module is the handler and nothing else;
 * `./before-submit-prompt.ts` is the entry that feeds it.
 */
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { isOwnEvent } from './event-name.ts';
import { hookLargeInputBound } from './large-input.ts';
import { readPayloadEvent, readSessionId, str } from './payload.ts';
import { promptDecision } from './prompt-decision.ts';
import type { HookHandler } from './shared.ts';
import { baseMetadata, captureScopeKey, parseJson, writeNotice } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGateway,
  storeDegradedMessage,
  warnIfStoreRedirected,
} from './store-health.ts';

export const runBeforeSubmitPrompt: HookHandler = async (event, stdin, options = {}) => {
  const input = parseJson(stdin);
  if (!input) return undefined;
  if (!isOwnEvent('beforeSubmitPrompt', event, readPayloadEvent(input))) return undefined;

  const text = str(input, 'prompt');
  if (text === undefined) return undefined;

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
    largeInput: hookLargeInputBound(true),
    ...(options.scanWorkerUrl === undefined
      ? {}
      : { scanIsolation: { workerUrl: options.scanWorkerUrl } }),
  });
  let result: CaptureResult;
  try {
    result = await runtime.capture(
      {
        kind: 'prompt',
        sourceTool: SOURCE_TOOL.Cursor,
        text,
        metadata: baseMetadata(input),
        scopeKey: captureScopeKey(input),
      },
      { persist: 'always', rewritable: false },
    );
  } finally {
    await runtime.close();
  }

  const decision = promptDecision(result);
  if (decision.notice !== undefined) writeNotice(decision.notice);
  return decision.output ?? undefined;
};
