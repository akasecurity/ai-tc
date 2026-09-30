/**
 * postToolUse (Copilot CLI, cloud coding agent) / PostToolUse (VS Code agent
 * mode) — fires after a tool call has executed, carrying its result.
 *
 * argv[2]: the event token. argv[3] (optional): the plugin manifest path.
 * stdin:   CLI    { sessionId, timestamp, cwd, toolName, toolArgs, toolResult }
 *          VSCode { hook_event_name, session_id, cwd, tool_name, tool_input,
 *                   tool_response }
 * stdout (exit 0), CLI:     (nothing, ever — the notice goes to stderr)
 * stdout (exit 0), VS Code: {"systemMessage":"…"} → a note, or nothing
 *
 * **THIS HOOK WITHHOLDS NOTHING AND REWRITES NOTHING.** The tool has already
 * run, so what is at stake is whether its output reaches the model — and
 * neither host offers a channel for that which this repository has confirmed:
 * `postToolUse.modifiedResult` is under "Not measured" in
 * `test/fixtures/cli/README.md`, and no live VS Code session has driven any
 * event in this package. Emitting a withhold on an unconfirmed channel would
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
 * trail decisions that are the point of the kind.
 *
 * `runHookFailOpen` is what guarantees the exit 0; see ./shared.ts for the
 * limit of that guarantee, which is everything that yields.
 */
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { detectDialect, readSessionId, readToolCall } from './dialect.ts';
import { readEventName } from './event-name.ts';
import { responseDecision, scanResponseFields } from './scan-response.ts';
import type { HookOutput } from './shared.ts';
import { baseMetadata, parseJson, readStdin, runHookFailOpen, writeNotice } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from './store-health.ts';
import { responseKey, scannableResponseFields } from './tool-response.ts';

/**
 * The two events this entry is registered for, one per dialect.
 *
 * Checked rather than assumed, for the reason `pre-tool-use.ts` gives: a
 * manifest that wired this script elsewhere would have it reading a result off
 * a payload that carries none, and declining for the wrong reason hides the
 * misconfiguration.
 */
const OWN_EVENTS: ReadonlySet<string> = new Set(['postToolUse', 'PostToolUse']);

async function main(): Promise<HookOutput | undefined> {
  const event = readEventName();
  if (event !== undefined && !OWN_EVENTS.has(event)) return undefined;

  const input = parseJson(await readStdin());
  if (!input) return undefined;

  const dialect = detectDialect(input);
  if (dialect === undefined) return undefined;

  // The tool NAME comes from the same reader `preToolUse` uses, so the two
  // events agree about what a call is called. A result with no name attached is
  // a call this build cannot describe, so nothing is said about it.
  const call = readToolCall(dialect, input);
  if (call === undefined) return undefined;

  const fields = scannableResponseFields(dialect, input[responseKey(dialect)]);
  // The fast path. Under VS Code this is the COMMON one — that host parses
  // matchers and ignores them, so this process is spawned for every tool call
  // the agent makes. Returning here exits before `loadConfig` and before the
  // store opens, so a result with no scannable text costs a process start and
  // nothing else.
  if (fields.length === 0) return undefined;

  const config = loadConfig();
  const sessionId = readSessionId(dialect, input);
  // A symlinked store path redirects the corpus without failing anything; say
  // so once per session on stderr, so this hook's stdout contract is untouched.
  warnIfStoreRedirected(config, sessionId);

  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    // Nothing is being scanned or recorded — say so once per session rather
    // than looking protected. On the CLI that has to be stderr: `systemMessage`
    // is not an output field there, so the same object on stdout is dropped.
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      const message = storeUnavailableMessage(config.dbPath);
      if (dialect === 'vscode') return { systemMessage: message };
      writeNotice(message);
    }
    return undefined;
  }

  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
  const metadata = baseMetadata(dialect, input) ?? {};
  metadata.toolName = call.name;

  let outcome;
  try {
    outcome = await scanResponseFields(call.name, fields, (text) =>
      runtime.capture(
        { kind: 'response', sourceTool: SOURCE_TOOL.Copilot, text, metadata },
        { persist: 'with-findings', rewritable: false },
      ),
    );
  } finally {
    await runtime.close();
  }

  const decision = responseDecision(dialect, outcome);
  // Set only on a dialect whose stdout has no field to carry it, so this never
  // competes with the payload below for the single JSON object stdout takes.
  if (decision.notice !== undefined) writeNotice(decision.notice);
  return decision.output ?? undefined;
}

// No fail-open payload: a body that threw, declined or outran the watchdog has
// scanned nothing, and saying nothing is how a hook declines on both hosts.
await runHookFailOpen(main);
