/**
 * postToolUse (Copilot CLI, cloud coding agent) / PostToolUse (VS Code agent
 * mode) — fires after a tool call has executed, carrying its result.
 *
 * event:   the token argv carried.
 * stdin:   CLI    { sessionId, timestamp, cwd, toolName, toolArgs, toolResult }
 *          VSCode { hook_event_name, session_id, cwd, tool_name, tool_input,
 *                   tool_response }
 * output, CLI:     undefined, always — every notice is a progress line
 *                  (see `progressLine` in ./shared.ts), with a stderr copy
 * output, VS Code: { systemMessage } → a note, or undefined
 *
 * **THIS HOOK WITHHOLDS NOTHING AND REWRITES NOTHING.** The tool has already
 * run, so what is at stake is whether its output reaches the model — and
 * neither host offers a channel for that which this repository has confirmed:
 * `postToolUse.modifiedResult` is under "Not measured" in
 * `test/fixtures/cli/README.md`, and a live VS Code 1.141.0 session
 * (`test/fixtures/vscode/plugin-load-1.141/`) drove the four events but never
 * a whole-result block. Emitting a withhold on an unconfirmed channel would
 * record an enforcement that may not have happened.
 *
 * So every capture passes `rewritable: false`, which resolves a `redact` policy
 * to `settings.redactFallback` INSIDE the runtime — where the emitted message,
 * the recorded `findings.actionTaken` and the ledger read one answer. The hook
 * never escalates for itself, and the message it prints says plainly that the
 * output reached the model. See ./scan-response.ts.
 *
 * `persist: 'with-findings'`: this hook sees the result of every tool call the
 * agent makes, and `always` would copy that whole stream into the store to
 * trail decisions that are the point of the kind. A refused field is recorded
 * under it too, with no content and the refusal stamped on the row.
 *
 * Each capture carries the SAME scope key preToolUse stamps for the call
 * (`callScopeKey` over `callKind`), so a call and its result agree on scope —
 * a VS Code single-file write by its own target, every other call by the
 * payload cwd.
 *
 * A FIELD TOO LARGE TO SCAN IN TIME IS NOT REFUSED. The runtime is built with
 * the large-input bound, so a field at or above the threshold is scanned in a
 * worker under the hook's deadline; one that does not finish comes back with
 * `scanIncomplete` set and no findings, and is reported as unscanned rather
 * than as clean. There is nothing to refuse: the output already reached the
 * model.
 *
 * This module is the handler and nothing else: it reads neither argv's event
 * token nor stdin, and never exits. `./post-tool-use.ts` is the entry that
 * feeds it, and `runHookFailOpen` there is what guarantees the exit 0.
 */
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { detectDialect, readSessionId, readToolCall } from './dialect.ts';
import { HOOK_SCAN_DEADLINE_MS, largeInputBound } from './large-input.ts';
import { responseDecision, scanResponseFields } from './scan-response.ts';
import type { HookHandler } from './shared.ts';
import {
  baseMetadata,
  callKind,
  callScopeKey,
  noticeWriter,
  parseJson,
  writeNotice,
} from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from './store-health.ts';
import { responseKey, scannableResponseFields } from './tool-response.ts';

/**
 * The two events this handler is registered for, one per dialect.
 *
 * Checked rather than assumed, for the reason `pre-tool-use-run.ts` gives: a
 * manifest that wired this script elsewhere would have it reading a result off
 * a payload that carries none, and declining for the wrong reason hides the
 * misconfiguration.
 */
const OWN_EVENTS: ReadonlySet<string> = new Set(['postToolUse', 'PostToolUse']);

/**
 * The tool-result handler. `options.akaHome` points the store and settings at
 * another home and `options.scanWorkerUrl` the bounded scan at another worker;
 * the entry passes neither.
 */
export const runPostToolUse: HookHandler = async (event, stdin, options = {}) => {
  if (event !== undefined && !OWN_EVENTS.has(event)) return undefined;

  const input = parseJson(stdin);
  if (!input) return undefined;

  const dialect = detectDialect(input);
  if (dialect === undefined) return undefined;

  // The tool NAME comes from the same reader `preToolUse` uses, so the two
  // events agree about what a call is called. A result with no name attached is
  // a call this build cannot describe, so nothing is said about it.
  const call = readToolCall(dialect, input);
  if (call === undefined) return undefined;

  const collected = scannableResponseFields(dialect, input[responseKey(dialect)]);
  // The fast path. Under VS Code this is the COMMON one — that host parses
  // matchers and ignores them, so this process is spawned for every tool call
  // the agent makes. Returning here exits before `loadConfig` and before the
  // store opens, so a result with no scannable text costs a process start and
  // nothing else. A result the walk bounds cut text out of is not on it: that
  // text went unscanned, and saying nothing would read as clean.
  if (collected.fields.length === 0 && !collected.truncated) return undefined;

  const config = loadConfig(options.akaHome);
  const sessionId = readSessionId(dialect, input);
  // A symlinked store path redirects the corpus without failing anything; say
  // so once per session, on stderr and, on the CLI, as a progress line, which
  // the host strips before reading this hook's output.
  warnIfStoreRedirected(config, sessionId, noticeWriter(dialect));

  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    // Nothing is being scanned or recorded — say so once per session rather
    // than looking protected. On the CLI that has to be a progress line: `systemMessage`
    // is not an output field there, so the same object on stdout is dropped.
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      const message = storeUnavailableMessage(config.dbPath);
      if (dialect === 'vscode') return { systemMessage: message };
      writeNotice(message, dialect);
    }
    return undefined;
  }

  // A field at or above the large-input threshold is scanned in a worker under
  // a deadline shared by every field of this result (see large-input.ts).
  const runtime = createPluginRuntime(gateway, config.settings, {
    dataDir: config.dataDir,
    largeInput: largeInputBound(HOOK_SCAN_DEADLINE_MS, false),
    ...(options.scanWorkerUrl === undefined
      ? {}
      : { scanIsolation: { workerUrl: options.scanWorkerUrl } }),
  });
  const metadata = baseMetadata(dialect, input) ?? {};
  metadata.toolName = call.name;
  const scopeKey = callScopeKey(callKind(dialect, call.name), dialect, input, call);

  let outcome;
  try {
    outcome = await scanResponseFields(call.name, collected, (text) =>
      runtime.capture(
        { kind: 'response', sourceTool: SOURCE_TOOL.Copilot, text, metadata, scopeKey },
        { persist: 'with-findings', rewritable: false },
      ),
    );
  } finally {
    await runtime.close();
  }

  const decision = responseDecision(dialect, outcome);
  // Set only on a dialect whose stdout has no field to carry it, so this never
  // competes with the payload below for the single JSON object stdout takes.
  if (decision.notice !== undefined) writeNotice(decision.notice, dialect);
  return decision.output ?? undefined;
};
