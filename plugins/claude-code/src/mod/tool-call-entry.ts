/**
 * The helper the tool.call mod runs through `$.process.run`:
 * `node <plugin root>/scripts/mod-tool-call.js`.
 *
 * Dereferencing a granted pointer, checking a grant and recording a finding need
 * the vault key and the store, and the mod has neither. So when the mod sees a
 * tool call that carries a pointer or a value its policy says to redact or block,
 * it hands the call here. This process runs the PreToolUse pipeline on it, the
 * same code the command hook runs (src/hooks/pre-tool-use-run.ts), and answers
 * what that pipeline decided.
 *
 * stdin:  {"v":1,"tool":"Bash","input":{...},"sessionId":"...","cwd":"..."}
 * stdout: {"v":1,"deny":string|null,"input":{...}|null,"context":string|null,"message":string|null}
 * Exit 1 with nothing on stdout means "no decision": the mod passes the call on
 * unchanged and the PreToolUse command hook decides it as it always did.
 *
 * Unless it denied, it leaves a note (src/mod/handoff.ts) naming the input the
 * tool will run with, so the command hook, shown that input next, does not
 * record or decide the call a second time. Nothing is written to stderr.
 */
import { loadConfig } from '@akasecurity/plugin-sdk';

import { runPreToolUse } from '../hooks/pre-tool-use-run.ts';
import type { HookOutput } from '../hooks/shared.ts';
import { countFailOpen, getString, parseJson, readStdin } from '../hooks/shared.ts';
import { recordToolHandoff } from './handoff.ts';
import { answerFromOutputs } from './tool-call-answer.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  const tool = input === null ? undefined : getString(input, 'tool');
  const toolInput = input?.input;
  if (
    input?.v !== 1 ||
    tool === undefined ||
    tool === '' ||
    typeof toolInput !== 'object' ||
    toolInput === null ||
    Array.isArray(toolInput)
  ) {
    process.exit(1);
  }

  const outputs: HookOutput[] = [];
  const run = await runPreToolUse(
    {
      tool_name: tool,
      tool_input: toolInput,
      session_id: getString(input, 'sessionId'),
      cwd: getString(input, 'cwd'),
    },
    (output) => {
      outputs.push(output);
      return Promise.resolve();
    },
    { mode: 'mod' },
  );
  // No store, or nothing in the call to scan: the hook is the one to say so.
  if (run !== 'finished') process.exit(1);

  const answer = answerFromOutputs(outputs);
  if (answer.deny === null) {
    recordToolHandoff(loadConfig().dataDir, tool, answer.input ?? toolInput);
  }
  process.stdout.write(`${JSON.stringify(answer)}\n`);
}

try {
  await main();
} catch {
  // Exit 1 and no output: the mod passes the call on unchanged.
  countFailOpen();
  process.exit(1);
}
process.exit(0);
