/**
 * PostToolUse — fires after a tool succeeds. The tool already ran, so the
 * job here is to stop sensitive output from entering the model's context:
 * `updatedToolOutput` replaces what the model sees.
 *
 * stdin:  { tool_name, tool_input, tool_response, ... }
 * stdout (exit 0):
 *   {"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":...}}
 *     → model sees the replaced output
 *   {"systemMessage":"..."} → warning only
 *   no output → pass through
 *
 * tool_response arrives in the tool's native shape (Read: file.content, Bash:
 * stdout/stderr, WebFetch: result, Grep: content, WebSearch: results, Agent/Task
 * and mcp__*: text content blocks — see tool-response.ts), and updatedToolOutput
 * must be emitted in that same shape: Claude Code validates it against the
 * tool's output schema and falls back to the original output on mismatch.
 * Fail-open: any error → no output, exit 0.
 */
import { runPostToolUse } from './post-tool-use-run.ts';
import { countFailOpen, emit, parseJson, readStdin } from './shared.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (input) await runPostToolUse(input, emit);
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session — but count the exit, so
  // `aka status` can say the hooks have been failing open on this machine.
  countFailOpen();
}
process.exit(0);
