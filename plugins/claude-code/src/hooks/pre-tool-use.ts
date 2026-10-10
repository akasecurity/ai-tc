/**
 * PreToolUse — fires before a tool call executes. The one surface where true
 * redaction works: `updatedInput` replaces the tool's arguments — but only
 * for fields whose text is handed onward as data (Write/Edit/MultiEdit
 * content, the WebFetch and Task prompts). A redact decision on an executable
 * field (Bash `command`, WebFetch `url`, any MCP argument) escalates to deny
 * instead: masking inside it would silently change what runs. See
 * pre-tool-use-fields.ts for the per-tool field map and
 * pre-tool-use-decision.ts for the collapse rules; the pipeline itself is
 * pre-tool-use-run.ts, which the tool.call mod's helper shares.
 *
 * stdin:  { tool_name, tool_input, session_id, ... }
 * stdout (exit 0):
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
 *     → tool call blocked
 *   {"hookSpecificOutput":{...,"permissionDecision":"allow","updatedInput":{...}}}
 *     → tool runs with redacted input (Write/Edit only)
 *   no output → allow unchanged
 *
 * Fail-open: any error → no output, exit 0.
 */
import { runPreToolUse } from './pre-tool-use-run.ts';
import { countFailOpen, emit, parseJson, readStdin } from './shared.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (input) await runPreToolUse(input, emit, { mode: 'hook' });
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session — but count the exit, so
  // `aka status` can say the hooks have been failing open on this machine.
  countFailOpen();
}
process.exit(0);
