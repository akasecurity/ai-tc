/**
 * preToolUse (Copilot CLI, cloud coding agent) / PreToolUse (VS Code agent
 * mode) — fires before a tool call executes.
 *
 * event:   the token argv carried.
 * stdin:   the host's payload, in either dialect (see ./dialect.ts).
 * output, CLI:
 *   {"permissionDecision":"deny","permissionDecisionReason":"…"}  → blocked
 *     (also when a field is too large to scan in time, on both dialects)
 *   {"modifiedArgs":{…}}                                          → redacted
 *   undefined                                                     → no opinion
 * output, VS Code:
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":…}}
 *   {"systemMessage":"…"}                                         → warned
 *   undefined                                                     → no opinion
 *
 * THIS HOOK NEVER EXITS NON-ZERO — and that, rather than a payload, is what
 * keeps it fail-open. On the Copilot CLI `preToolUse` is the one fail-closed
 * event, and the channel that fails closed is the EXIT CODE: the hooks
 * reference denies on a non-zero exit other than 2, denies on exit 2, and
 * documents timeouts as fail-open for every event including this one. Empty
 * stdout is in none of those lists — that same reference's `preToolUse`
 * decision table reads "Empty output uses default behavior", which hands the
 * call to the host's own permission flow. So a path that reaches no verdict
 * writes nothing and exits 0, which is CLAUDE.md §1's fail-open unchanged.
 *
 * An explicit allow is reserved for the one place it is a real answer: VS
 * Code's rewrite of a call with no executable field, where the host needs the
 * verdict alongside `updatedInput`.
 * Printing one per clean call on the CLI would instead PRE-APPROVE every call
 * AKA found clean, suppressing the prompts the user's own Copilot settings
 * would have raised — a control plane widening the permissions it was installed
 * to narrow. `CliPermissionDecisionOutput` carries `'deny'` alone so that is a
 * compile error rather than a rule someone has to remember.
 *
 * This module is the handler and nothing else: it reads neither argv's event
 * token nor stdin, and never exits. `./pre-tool-use.ts` is the entry that feeds
 * it, and `runHookFailOpen` there is what guarantees the exit code — see
 * ./shared.ts for the limit of that guarantee, which is everything that yields.
 */
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { detectDialect, readSessionId, readToolCall } from './dialect.ts';
import { HOOK_SCAN_DEADLINE_MS, largeInputBound } from './large-input.ts';
import type { ScannedField } from './pre-tool-use-decision.ts';
import {
  decideInputPointerDeny,
  decidePreToolUse,
  fieldIsRewritable,
  scannableFieldsFor,
} from './pre-tool-use-decision.ts';
import type { HookHandler } from './shared.ts';
import { baseMetadata, callKind, callScopeKey, parseJson, writeNotice } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from './store-health.ts';

/**
 * The two events this handler is registered for, one per dialect.
 *
 * Checked rather than assumed: the hook command carries the token, and a
 * manifest that wired this script to some other event would otherwise have it
 * scanning a payload with no tool call in it and declining — which is the right
 * answer for the wrong reason, and would hide the misconfiguration.
 */
const OWN_EVENTS: ReadonlySet<string> = new Set(['preToolUse', 'PreToolUse']);

/**
 * The tool-call handler. `options.akaHome` points the store and settings at
 * another home and `options.scanWorkerUrl` the bounded scan at another worker;
 * the entry passes neither.
 */
export const runPreToolUse: HookHandler = async (event, stdin, options = {}) => {
  if (event !== undefined && !OWN_EVENTS.has(event)) return undefined;

  const input = parseJson(stdin);
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
  // process start and nothing else, and writes nothing at all.
  if (!fields) return undefined;

  const toolInput = { ...call.args };

  // A model-echoed vault pointer in text that EXECUTES is decided before the
  // secret scan AND before the store is opened: this plugin never substitutes
  // pointers, so an ungranted pointer must deny outright rather than run as
  // literal text, and that decision reads only the call itself, so an
  // unopenable store cannot turn it into a let-through.
  const pointerDeny = decideInputPointerDeny(dialect, call.name, toolInput, fields);
  if (pointerDeny) return pointerDeny;

  const config = loadConfig(options.akaHome);
  const sessionId = readSessionId(dialect, input);
  // A symlinked store path redirects the corpus without failing anything; say
  // so once per session on stderr, so this hook's stdout contract is untouched.
  warnIfStoreRedirected(config, sessionId);
  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    // The store is gone, so nothing was scanned and there is no verdict to
    // reach. Saying so must not become an allow: this is precisely the state in
    // which AKA knows LEAST about the call, so an explicit allow here would
    // pre-approve exactly the calls it failed to inspect. The warning goes to
    // the channel the dialect has for it and stdout keeps its silence.
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      const message = storeUnavailableMessage(config.dbPath);
      if (dialect === 'vscode') return { systemMessage: message };
      writeNotice(message);
    }
    return undefined;
  }

  // A field at or above the large-input threshold is scanned under a deadline
  // shared by every field of this call, and refused if that scan does not
  // finish (see large-input.ts).
  const runtime = createPluginRuntime(gateway, config.settings, {
    dataDir: config.dataDir,
    largeInput: largeInputBound(HOOK_SCAN_DEADLINE_MS, true),
    ...(options.scanWorkerUrl === undefined
      ? {}
      : { scanIsolation: { workerUrl: options.scanWorkerUrl } }),
  });
  const kind = callKind(dialect, call.name);
  const metadata = baseMetadata(dialect, input) ?? {};
  metadata.toolName = call.name;
  // A VS Code single-file write by its own target, a patch or any other
  // code_change by nothing, every other call by the payload cwd only; see
  // callScopeKey. Resolved once, outside the field loop.
  const scopeKey = callScopeKey(kind, dialect, input, call);

  const scanned: ScannedField[] = [];
  try {
    for (const spec of fields) {
      const value = toolInput[spec.field];
      if (typeof value !== 'string' || value === '') continue;

      const result = await runtime.capture(
        { kind, sourceTool: SOURCE_TOOL.Copilot, text: value, metadata, scopeKey },
        {
          ...(kind === 'tool_use' ? { persist: 'with-findings' as const } : {}),
          // Per FIELD: a field that EXECUTES cannot be masked in place, because
          // rewriting a command changes what runs, and on VS Code neither can
          // the prose riding on such a call (see fieldIsRewritable). A redact
          // there degrades to the configured `redactFallback` inside the
          // runtime, where the emitted decision, the recorded action and the
          // ledger all read one answer.
          rewritable: fieldIsRewritable(dialect, spec, fields),
          // Also per FIELD: the command-risk rules judge text that is about to
          // run, so a field that does not execute — the model's description of
          // the call — is scanned without them. Secret and PII rules still run
          // on it, and the capture is still recorded under `kind`.
          kindScopedRules: spec.executable,
        },
      );
      scanned.push({ spec, result });
      // A refused field denies the whole call (decidePreToolUse), so scanning
      // the rest would only spend the time the deadline is there to protect.
      if (result.scanIncomplete !== undefined) break;
    }
  } finally {
    await runtime.close();
  }

  const decision = decidePreToolUse(dialect, call.name, toolInput, scanned);
  // `notice` is set only on a dialect whose stdout has no field to carry it, so
  // this never competes with the payload below for the single JSON object
  // stdout takes.
  if (decision.notice !== undefined) writeNotice(decision.notice);
  return decision.output ?? undefined;
};
