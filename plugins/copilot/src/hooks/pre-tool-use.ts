/**
 * preToolUse (CLI, cloud) / PreToolUse (VS Code) — fires before a tool call
 * executes.
 *
 * THIS IS THE ONE HOOK IN THIS PACKAGE THAT ALWAYS PRINTS. Copilot CLI reads a
 * `preToolUse` hook that exits non-zero or crashes as a DENY, and its reading
 * of "exit 0 with empty stdout" has not been observed on a live install (see
 * `test/fixtures/cli/README.md`, "Not measured"). Printing an explicit allow is
 * correct under BOTH readings of that unmeasured case, so the whole body runs
 * inside `runHookFailOpen`, which guarantees exactly one JSON object on every
 * path that yields. Its limit — a body that BLOCKS the thread cannot be
 * preempted from the thread — is stated at `runHookFailOpen` itself.
 *
 * argv:   [node, script, '<eventName>']   — the event name is never in the payload
 * stdin:  CLI    { sessionId, cwd, toolName, toolArgs }
 *         VSCode { hook_event_name, session_id?, cwd?, tool_name, tool_input }
 * stdout (exit 0), CLI dialect:
 *   {"permissionDecision":"deny","permissionDecisionReason":"…"}  → blocked
 *   {"modifiedArgs":{…}}                                          → runs redacted
 *   {"permissionDecision":"allow"}                                → unchanged
 * stdout (exit 0), VS Code dialect:
 *   {"hookSpecificOutput":{…,"permissionDecision":"deny",…}}       → blocked
 *   {"hookSpecificOutput":{…,"permissionDecision":"allow","updatedInput":{…}}}
 *   {"hookSpecificOutput":{…,"permissionDecision":"allow","updatedInput":{}}}
 *
 * No path exits non-zero, and no path exits 2.
 */
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { detectDialect, readSessionId, readToolCall } from './dialect.ts';
import type { ScannedField } from './pre-tool-use-decision.ts';
import {
  decideInputPointerDeny,
  decidePreToolUse,
  scannableFields,
} from './pre-tool-use-decision.ts';
import type { HookOutput } from './shared.ts';
import { allowPayload, baseMetadata, parseJson, readStdin, runHookFailOpen } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from './store-health.ts';

// A payload whose dialect cannot be told is decided as the CLI's, because that
// is the host where a wrong guess costs the most: on VS Code an unrecognised
// shape falls back to a documented no-opinion, while on the CLI it is a deny.
const DEFAULT_DIALECT = 'cli' as const;

async function main(): Promise<HookOutput | undefined> {
  const input = parseJson(await readStdin());
  if (!input) return undefined;

  const dialect = detectDialect(input) ?? DEFAULT_DIALECT;
  const call = readToolCall(input, dialect);
  if (!call) return undefined;

  const fields = scannableFields(dialect)[call.name];
  // THE UNKNOWN-TOOL FAST PATH, and it must stay before everything below it.
  // VS Code parses matchers and then ignores them, so this hook is spawned for
  // EVERY tool call on that host — read_file, fetch_webpage, every MCP tool.
  // Returning `undefined` here hands `runHookFailOpen` the explicit allow
  // having opened no store, loaded no config and started no worker.
  if (!fields) return undefined;

  // A model-echoed vault pointer in text that EXECUTES is decided before the
  // secret scan, and before the store is even opened: this plugin never
  // substitutes pointers, so an ungranted pointer must deny outright rather
  // than run as literal text. Pointers reach this host from the same machine's
  // vault surfaces (the Claude Code plugin, the wizard's history scrub).
  const pointerDeny = decideInputPointerDeny(dialect, call.name, call.args, fields);
  if (pointerDeny) return pointerDeny;

  const sessionId = readSessionId(input, dialect);
  const config = loadConfig();
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, sessionId);
  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    // STILL AN EXPLICIT ALLOW, with the note riding beside it rather than
    // replacing it. A bare `{systemMessage}` carries no verdict, and on this
    // event a payload the host has to interpret is exactly what the explicit
    // allow exists to avoid. `undefined` hands the wrapper its own allow, which
    // is the same shape without the note.
    return claimStoreUnavailableWarning(config.dataDir, sessionId)
      ? allowPayload(dialect, storeUnavailableMessage(config.dbPath))
      : undefined;
  }
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });

  const toolInput = { ...call.args };
  // A file write is durable content the agent authors, recorded as
  // 'code_change' with the default persist ('always' — the at-rest trail the
  // re-scan resolver reconciles against). A shell command is text the host acts
  // on, recorded as 'tool_use' at persist 'with-findings': this hook sees every
  // command, and 'always' would copy that whole stream into the store to trail
  // the enforcement decisions that are the point of the kind. Same split as
  // Claude Code's Write/Edit vs Bash.
  const executes = fields.some((spec) => spec.executable);
  const kind = executes ? 'tool_use' : 'code_change';
  const metadata = baseMetadata(input, dialect) ?? {};
  metadata.toolName = call.name;

  const scanned: ScannedField[] = [];
  try {
    for (const spec of fields) {
      const value = toolInput[spec.field];
      if (typeof value !== 'string' || value === '') continue;

      const result = await runtime.capture(
        { kind, sourceTool: SOURCE_TOOL.Copilot, text: value, metadata },
        {
          ...(kind === 'tool_use' ? { persist: 'with-findings' as const } : {}),
          // Per FIELD: a field that EXECUTES cannot be masked in place, because
          // rewriting a command changes what runs. A stored field can be, and
          // keeps true redaction. A redact on the executable one degrades to
          // the configured `redactFallback` inside the runtime, where the
          // emitted decision, the recorded action and the ledger all read one
          // answer — a hook that escalated for itself would record a deny as
          // `redact`.
          rewritable: !spec.executable,
        },
      );
      scanned.push({ spec, result });
    }
  } finally {
    await runtime.close();
  }

  return decidePreToolUse(dialect, call.name, toolInput, scanned) ?? undefined;
}

// Never returns: runHookFailOpen emits exactly one object and exits 0.
// The dialect the fail-open payload is shaped for is read from stdin by main();
// this outer one cannot be, because stdin has not been read yet — so the
// wrapper's own payload is the CLI's, the shape the host that actually denies
// on silence understands. VS Code accepts it as an unrecognised object, which
// on that host is a no-opinion.
await runHookFailOpen(main, allowPayload(DEFAULT_DIALECT));
