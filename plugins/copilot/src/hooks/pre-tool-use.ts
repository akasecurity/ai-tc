/**
 * preToolUse (Copilot CLI, cloud coding agent) / PreToolUse (VS Code agent
 * mode) — fires before a tool call executes.
 *
 * argv[2]: the event token. argv[3] (optional): the plugin manifest path.
 * stdin:   the host's payload, in either dialect (see ./dialect.ts).
 * stdout (exit 0), CLI:
 *   {"permissionDecision":"deny","permissionDecisionReason":"…"}  → blocked
 *   {"modifiedArgs":{…}}                                          → redacted
 *   (nothing)                                                     → no opinion
 * stdout (exit 0), VS Code:
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":…}}
 *   {"systemMessage":"…"}                                         → warned
 *   (nothing)                                                     → no opinion
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
 * Code's rewrite, where the host needs the verdict alongside `updatedInput`.
 * Printing one per clean call on the CLI would instead PRE-APPROVE every call
 * AKA found clean, suppressing the prompts the user's own Copilot settings
 * would have raised — a control plane widening the permissions it was installed
 * to narrow. `CliPermissionDecisionOutput` carries `'deny'` alone so that is a
 * compile error rather than a rule someone has to remember.
 *
 * `runHookFailOpen` is what guarantees the exit code; see ./shared.ts for the
 * limit of that guarantee, which is everything that yields.
 */
import { isAbsolute } from 'node:path';

import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import type { Dialect, ToolCall } from './dialect.ts';
import { detectDialect, readSessionId, readToolCall } from './dialect.ts';
import { readEventName } from './event-name.ts';
import type { ScannedField } from './pre-tool-use-decision.ts';
import {
  decideInputPointerDeny,
  decidePreToolUse,
  scannableFieldsFor,
} from './pre-tool-use-decision.ts';
import type { HookOutput } from './shared.ts';
import {
  baseMetadata,
  captureScopeKey,
  getString,
  parseJson,
  readStdin,
  runHookFailOpen,
  writeNotice,
} from './shared.ts';
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
 * scanning a payload with no tool call in it and declining — which is the right
 * answer for the wrong reason, and would hide the misconfiguration.
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

/**
 * VS Code's single-file writers, which name the one file they write in a
 * `filePath` input. Doc-derived, like `VSCODE_SCANNABLE_FIELDS`: the fixture
 * README cites `filePath` for `create_file` and `replace_string_in_file`, and
 * records only `code` and `explanation` for `insert_edit_into_file`, the same
 * kind of tool. A wrong guess costs a key, never the capture (see scopeKeyOf).
 *
 * `apply_patch` is not one. On either dialect it names its files inside the
 * patch body (its `input` field), which this hook does not parse. It is
 * recorded whole as a `code_change`, so it gets NO key (see scopeKeyOf).
 */
const VSCODE_FILE_WRITERS: ReadonlySet<string> = new Set([
  'create_file',
  'replace_string_in_file',
  'insert_edit_into_file',
]);

/**
 * The scope key of this call's captures. It rides beside the metadata
 * (`CaptureInput.scopeKey`), never inside it.
 *
 * A VS Code single-file writer is keyed by the file it writes and by nothing
 * else. Its content is recorded whole, so a write into one checkout from a
 * session whose cwd is another must carry the key of the checkout it wrote.
 * When `filePath` is missing or not absolute the call gets NO key rather than
 * the cwd's: the field name is unconfirmed, and no key fails closed where the
 * cwd's could name a checkout the file is not in. The path is not stamped as
 * metadata.filePath, because that would change what these events carry on the
 * wire.
 *
 * An `apply_patch`, on either dialect, gets NO key either. Its files are named
 * inside the patch body, which this hook does not read, and its content is
 * recorded whole. The payload cwd's key would stamp a patch into a personal
 * checkout with an enrolled key. With no key the patch stays local on a scoped
 * attachment, a coverage gap rather than a leak.
 *
 * Every other call names no file this hook reads, and is keyed by the payload
 * cwd alone (see captureScopeKey).
 */
function scopeKeyOf(
  dialect: Dialect,
  input: Record<string, unknown>,
  call: ToolCall,
): string | undefined {
  if (call.name === 'apply_patch') return undefined;
  if (dialect !== 'vscode' || !VSCODE_FILE_WRITERS.has(call.name)) {
    return captureScopeKey(dialect, input);
  }
  const target = getString(call.args, 'filePath');
  return target !== undefined && isAbsolute(target)
    ? captureScopeKey(dialect, input, target)
    : undefined;
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
  // process start and nothing else, and writes nothing at all.
  if (!fields) return undefined;

  const config = loadConfig();
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
  // A VS Code single-file write by its own target, every other call by the
  // payload cwd only; see scopeKeyOf. Resolved once, outside the field loop.
  const scopeKey = scopeKeyOf(dialect, input, call);

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

  const decision = decidePreToolUse(dialect, call.name, toolInput, scanned);
  // `notice` is set only on a dialect whose stdout has no field to carry it, so
  // this never competes with the payload below for the single JSON object
  // stdout takes.
  if (decision.notice !== undefined) writeNotice(decision.notice);
  return decision.output ?? undefined;
}

// No fail-open payload is passed, because there is no payload to write: a body
// that threw, declined, or outran the watchdog has reached no verdict, and on
// both hosts saying nothing is how a hook declines. That also removes the one
// thing the old shape needed the event token for out here — which dialect to
// spell a fail-open allow in — on a path where stdin may never have parsed.
// `runHookFailOpen` still guarantees the exit 0 that this host reads as
// "no deny".
await runHookFailOpen(main);
