/**
 * preToolUse (Copilot CLI, cloud coding agent) / PreToolUse (VS Code agent
 * mode) — fires before a tool call executes.
 *
 * argv[2]: the event token. argv[3] (optional): the plugin manifest path.
 * stdin:   the host's payload, in either dialect (see ./dialect.ts).
 * stdout (exit 0), CLI:
 *   {"permissionDecision":"deny","permissionDecisionReason":"…"}  → blocked
 *   {"modifiedArgs":{…},"systemMessage":"…"}                      → redacted
 *   {"permissionDecision":"allow"}                                → unchanged
 * stdout (exit 0), VS Code:
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":…}}
 *
 * THIS HOOK NEVER PRINTS NOTHING. On the Copilot CLI a crashed or non-zero-
 * exiting `preToolUse` hook is read as a DENY, and whether exit 0 with empty
 * stdout allows or denies is unmeasured — so every path through here, including
 * a throw and a watchdog win, leaves an explicit allow on stdout. That is
 * correct under both readings. `runHookFailOpen` is what guarantees it; see
 * ./shared.ts for the limit of that guarantee, which is everything that yields.
 */
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import type { Dialect } from './dialect.ts';
import { detectDialect, readSessionId, readToolCall } from './dialect.ts';
import { readEventName } from './event-name.ts';
import type { ScannedField } from './pre-tool-use-decision.ts';
import {
  decideInputPointerDeny,
  decidePreToolUse,
  scannableFieldsFor,
} from './pre-tool-use-decision.ts';
import type { HookOutput } from './shared.ts';
import { allowFor, baseMetadata, parseJson, readStdin, runHookFailOpen } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from './store-health.ts';

/**
 * The two events this entry is registered for, one per dialect.
 *
 * Checked rather than assumed: the hook command carries the token, and a
 * manifest that wired this script to some other event would otherwise have it
 * scanning a payload with no tool call in it and reporting an allow — which is
 * the right answer for the wrong reason, and would hide the misconfiguration.
 */
const OWN_EVENTS: ReadonlySet<string> = new Set(['preToolUse', 'PreToolUse']);

/**
 * A `code_change` is durable content the agent authors, recorded with the
 * default persist. A command is text the host acts on, recorded at
 * `with-findings`: this hook sees every command, and `always` would copy that
 * whole stream into the store to trail the enforcement decisions that are the
 * point of the kind.
 */
function kindFor(dialect: Dialect, toolName: string): 'code_change' | 'tool_use' {
  const writers =
    dialect === 'cli'
      ? ['apply_patch']
      : ['create_file', 'replace_string_in_file', 'insert_edit_into_file', 'apply_patch'];
  return writers.includes(toolName) ? 'code_change' : 'tool_use';
}

async function main(): Promise<HookOutput | undefined> {
  const event = readEventName();
  if (event !== undefined && !OWN_EVENTS.has(event)) return undefined;

  const input = parseJson(await readStdin());
  if (!input) return undefined;

  const dialect = detectDialect(input);
  if (dialect === undefined) return undefined;

  const call = readToolCall(dialect, input);
  if (call === undefined) return undefined;

  const fields = scannableFieldsFor(dialect)[call.name];
  // The fast path, and under VS Code the COMMON one: that host parses matchers
  // and ignores them, so this process is spawned for every tool call the agent
  // makes — `read_file`, `fetch_webpage`, every `mcp_*`. Returning here exits
  // before `loadConfig` and before the store opens, so an unknown tool costs a
  // process start and nothing else. `runHookFailOpen` still prints the allow.
  if (!fields) return undefined;

  const config = loadConfig();
  const sessionId = readSessionId(dialect, input);
  // A symlinked store path redirects the corpus without failing anything; say
  // so once per session on stderr, so this hook's stdout contract is untouched.
  warnIfStoreRedirected(config, sessionId);
  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    // The store is gone, so nothing is scanned — but the call still has to be
    // allowed, and on this host that means saying so. The warning rides the
    // allow rather than replacing it.
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      return allowFor(dialect, storeUnavailableMessage(config.dbPath));
    }
    return undefined;
  }

  const toolInput = { ...call.args };

  // A model-echoed vault pointer in text that EXECUTES is decided before the
  // secret scan: this plugin never substitutes pointers, so an ungranted
  // pointer must deny outright rather than run as literal text.
  const pointerDeny = decideInputPointerDeny(dialect, call.name, toolInput, fields);
  if (pointerDeny) return pointerDeny;

  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
  const kind = kindFor(dialect, call.name);
  const metadata = baseMetadata(dialect, input) ?? {};
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
          // rewriting a command changes what runs. A redact on it degrades to
          // the configured `redactFallback` inside the runtime, where the
          // emitted decision, the recorded action and the ledger all read one
          // answer.
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

// The fail-open payload's dialect comes from the EVENT TOKEN, not from the
// payload. It has to: this is the shape written when main() threw, when it
// declined, and when it outran the watchdog — including on a run where stdin
// never parsed and there was no payload to sniff. The token is on argv before
// any of that, and the two vocabularies are disjoint, so it places the shape
// with no I/O at all. An absent or unknown token falls back to the CLI shape;
// see `allowFor` for why that direction is the safe one.
await runHookFailOpen(main, allowFor(readEventName() === 'PreToolUse' ? 'vscode' : 'cli'));
