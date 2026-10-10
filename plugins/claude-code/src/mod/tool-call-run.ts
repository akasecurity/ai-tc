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
 * record the call a second time or ask for a grant already spent. The hook still
 * looks again at the executable fields (pre-tool-use-run.ts, noteStillHolds); the
 * note names the values this helper let through there. Nothing is written to
 * stderr.
 */
import { loadConfig } from '@akasecurity/plugin-sdk';

import { isSyntheticField } from '../hooks/pre-tool-use-fields.ts';
import { runPreToolUse } from '../hooks/pre-tool-use-run.ts';
import type { HookOutput } from '../hooks/shared.ts';
import { countFailOpen, getString, parseJson } from '../hooks/shared.ts';
import { authorizeValues, recordToolHandoff } from './handoff.ts';
import type { HelperRun } from './helper-run.ts';
import { answerFromOutputs } from './tool-call-answer.ts';

async function toolCall(stdin: string): Promise<HelperRun> {
  const input = parseJson(stdin);
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
    return { code: 1, stdout: '' };
  }

  const outputs: HookOutput[] = [];
  // What was detected in the fields that execute. A call this helper lets through
  // carries those values in the clear (a granted pointer dereferenced, a value an
  // exception covers, a fallback that only warns), and the hook, which cannot see
  // the grants now spent, takes them from the note rather than judging them again.
  const executableValues: string[] = [];
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
    {
      mode: 'mod',
      onScanned: (scanned) => {
        for (const { spec, result } of scanned) {
          if (!spec.executable && !isSyntheticField(spec)) continue;
          for (const finding of result.findings) executableValues.push(finding.rawMatch);
        }
      },
    },
  );
  // No store, or nothing in the call to scan: the hook is the one to say so.
  if (run !== 'finished') return { code: 1, stdout: '' };

  const answer = answerFromOutputs(outputs);
  if (answer.deny === null) {
    const { dataDir } = loadConfig();
    recordToolHandoff(
      dataDir,
      tool,
      answer.input ?? toolInput,
      Date.now(),
      authorizeValues(dataDir, executableValues),
    );
  }
  return { code: 0, stdout: `${JSON.stringify(answer)}\n` };
}

/** The decision for one tool call on stdin. Never throws: a fault is exit 1 and silence. */
export async function runModToolCall(stdin: string): Promise<HelperRun> {
  try {
    return await toolCall(stdin);
  } catch {
    // Exit 1 and no output: the mod passes the call on unchanged.
    countFailOpen();
    return { code: 1, stdout: '' };
  }
}
