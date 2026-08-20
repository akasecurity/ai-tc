/**
 * PreToolUse — fires before a tool call executes.
 *
 * stdin:  { toolCall: { name, args }, stepIdx, conversationId, workspacePaths,
 *           transcriptPath, artifactDirectoryPath }
 * stdout (exit 0):
 *   {"decision":"deny","reason":"..."} → the tool call is blocked
 *   {"decision":"allow"}               → the call runs unchanged
 *
 * There is no `updatedInput` equivalent, so a redact policy DENIES rather than
 * masking in place — see pre-tool-use-decision.ts.
 *
 * FAIL-OPEN ON A FAIL-CLOSED HOST: Antigravity reads a non-zero exit, a killed
 * hook, or an unparseable payload as a `deny` on every tool call. Exiting
 * quietly is therefore not fail-open here the way it is on Claude Code and
 * Codex — `runHookFailOpen` writes an explicit {"decision":"allow"} on every
 * error path, including a throw and the watchdog.
 */
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import type { ScannedField } from './pre-tool-use-decision.ts';
import {
  ALLOW,
  decideInputPointerDeny,
  decidePreToolUse,
  SCANNABLE_FIELDS,
} from './pre-tool-use-decision.ts';
import {
  baseMetadata,
  getString,
  parseJson,
  readStdin,
  readToolCall,
  runHookFailOpen,
} from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
} from './store-health.ts';

async function main(): Promise<unknown> {
  const input = parseJson(await readStdin());
  if (!input) return ALLOW;

  const call = readToolCall(input);
  if (!call) return ALLOW;
  // Object.hasOwn, not a bare index: the tool name is host-supplied, and
  // `__proto__` would otherwise resolve to Object.prototype rather than miss.
  const fields = Object.hasOwn(SCANNABLE_FIELDS, call.name)
    ? SCANNABLE_FIELDS[call.name]
    : undefined;
  if (!fields) return ALLOW;

  // A model-echoed vault pointer in text that EXECUTES is decided before the
  // secret scan (and before the store is even opened): this plugin never
  // substitutes pointers, so an ungranted pointer must deny outright rather
  // than run as literal text. Pointers reach Antigravity from the same
  // machine's vault surfaces (the Claude Code plugin, the wizard's history
  // scrub).
  const pointerDeny = decideInputPointerDeny(call.name, call.args, fields);
  if (pointerDeny) return pointerDeny;

  const config = loadConfig();
  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    // Nothing is scanned or recorded with no store. PreToolUse has no message
    // channel of its own (the payload carries `reason`, which accompanies a
    // deny), so the once-per-session notice goes to stderr rather than being
    // smuggled into an allow the host may not surface.
    if (claimStoreUnavailableWarning(config.dataDir, getString(input, 'conversationId'))) {
      process.stderr.write(`[aka] ${storeUnavailableMessage(config.dbPath)}\n`);
    }
    return ALLOW;
  }
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });

  // A file write is durable content the agent authors, recorded as
  // 'code_change' with the default persist ('always' — the at-rest trail the
  // re-scan resolver reconciles against). A shell command is text the host acts
  // on, recorded as 'tool_use' at persist 'with-findings': this hook sees every
  // command, and 'always' would copy that whole stream into the store to trail
  // the enforcement decisions that are the point of the kind. Same split as
  // Claude Code's Write/Edit vs Bash.
  const kind = call.name === 'run_command' ? 'tool_use' : 'code_change';
  const metadata = baseMetadata(input) ?? {};
  metadata.toolName = call.name;
  // Both file-writing tools name their target the same way, so the finding
  // carries the path it was written to. Absent on run_command.
  const targetFile = getString(call.args, 'TargetFile');
  if (targetFile) metadata.filePath = targetFile;

  const scanned: ScannedField[] = [];
  try {
    for (const spec of fields) {
      const value = call.args[spec.field];
      if (typeof value !== 'string' || value === '') continue;

      const result = await runtime.capture(
        { kind, sourceTool: SOURCE_TOOL.Antigravity, text: value, metadata },
        kind === 'tool_use' ? { persist: 'with-findings' } : {},
      );
      scanned.push({ spec, result });
    }
  } finally {
    await runtime.close();
  }

  return decidePreToolUse(call.name, scanned);
}

await runHookFailOpen(main, ALLOW);
