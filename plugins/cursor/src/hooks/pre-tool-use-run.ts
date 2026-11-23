/**
 * preToolUse — fires before every agent tool call: Shell, file reads and
 * writes, search, and MCP tools.
 *
 * stdin:  { conversation_id, hook_event_name, tool_name, tool_input,
 *           tool_use_id, cwd, workspace_roots, model, … }
 * stdout: {"permission":"deny","user_message":"…","agent_message":"…"} → blocked
 *           (also when a field is too large to scan in time)
 *         nothing                                                 → no opinion
 * stderr: a warn, and the store warnings, once per session where they apply.
 *
 * A clean scan, a monitor policy and a warn all write nothing, which Cursor
 * reads as allowed and hands to its own permission flow. This module is the
 * handler and nothing else; `./pre-tool-use.ts` is the entry that feeds it.
 */
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { isOwnEvent } from './event-name.ts';
import { hookLargeInputBound } from './large-input.ts';
import { readPayloadEvent, readSessionId, readToolCall } from './payload.ts';
import type { FieldText, ScannedField } from './pre-tool-use-decision.ts';
import {
  decideInputPointerDeny,
  decidePreToolUse,
  isMcpTool,
  SCANNABLE_FIELDS,
} from './pre-tool-use-decision.ts';
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
  claimStoreDegradedWarning,
  openGateway,
  storeDegradedMessage,
  warnIfStoreRedirected,
} from './store-health.ts';
import { scannableFields } from './tool-response.ts';

/** The texts to scan for this call, and whether the MCP walk left any out. */
function fieldTexts(
  toolName: string,
  args: Record<string, unknown>,
): { texts: FieldText[]; truncated: boolean } | undefined {
  if (isMcpTool(toolName)) {
    const collected = scannableFields(args, { keys: true });
    return {
      // An MCP server defines its own argument schema, so nothing here can
      // tell a message body from a command the server will run: every leaf and
      // every object key is judged as executable, command-risk rules included.
      texts: collected.fields.map(({ path, text, key }) => ({
        spec: { field: key ? `${path.join('.')} (key)` : path.join('.'), executable: true },
        text,
      })),
      truncated: collected.truncated,
    };
  }
  const fields = SCANNABLE_FIELDS[toolName];
  if (fields === undefined) return undefined;
  const texts: FieldText[] = [];
  for (const spec of fields) {
    const value = args[spec.field];
    if (typeof value === 'string' && value !== '') texts.push({ spec, text: value });
  }
  return { texts, truncated: false };
}

export const runPreToolUse: HookHandler = async (event, stdin, options = {}) => {
  const input = parseJson(stdin);
  if (!input) return undefined;
  if (!isOwnEvent('preToolUse', event, readPayloadEvent(input))) return undefined;

  const call = readToolCall(input);
  if (call === undefined) return undefined;

  // The fast path: a tool with nothing to scan returns before the config load
  // and before the store opens, so it costs a process start and nothing else.
  const collected = fieldTexts(call.name, call.args);
  if (collected === undefined) return undefined;
  if (collected.texts.length === 0 && !collected.truncated) return undefined;

  // A vault pointer in text that EXECUTES — a Shell command or an MCP argument
  // — is decided before the secret scan and before the store is opened, so an
  // unopenable store cannot turn it into a let-through.
  const pointerDeny = decideInputPointerDeny(call.name, collected.texts);
  if (pointerDeny) return pointerDeny;

  const config = loadConfig(options.akaHome);
  const sessionId = readSessionId(input);
  warnIfStoreRedirected(config, sessionId);
  const { gateway, error } = openGateway(config);
  if (gateway === null) {
    // Nothing was scanned, so there is no verdict; an allow here would
    // pre-approve exactly the calls AKA failed to inspect.
    if (claimStoreDegradedWarning(config.dataDir, sessionId, error)) {
      writeNotice(storeDegradedMessage(config.dbPath, error, 'tool call'));
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
  const kind = callKind(call.name);
  const metadata = baseMetadata(input);
  metadata.toolName = call.name;
  const scopeKey = callScopeKey(kind, input, call);

  const scanned: ScannedField[] = [];
  try {
    for (const { spec, text } of collected.texts) {
      const result = await runtime.capture(
        { kind, sourceTool: SOURCE_TOOL.Cursor, text, metadata, scopeKey },
        {
          ...(kind === 'tool_use' ? { persist: 'with-findings' as const } : {}),
          // No field is rewritten on this host (see ./pre-tool-use-decision.ts),
          // so a redact resolves to the configured `redactFallback` inside the
          // runtime, where the emitted decision and the recorded action agree.
          rewritable: false,
          kindScopedRules: spec.executable,
        },
      );
      scanned.push({ spec, result });
      // A refused field denies the whole call, so scanning the rest would only
      // spend the time the deadline is there to protect.
      if (result.scanIncomplete !== undefined) break;
    }
  } finally {
    await runtime.close();
  }

  // Arguments past the walk bounds went unscanned, which the fail-open tally
  // counts so `aka status` does not read this machine as fully scanned.
  if (collected.truncated) countFailOpen(options.countFailOpen);

  const decision = decidePreToolUse(call.name, scanned, collected.truncated);
  if (decision.notice !== undefined) writeNotice(decision.notice);
  return decision.output ?? undefined;
};
