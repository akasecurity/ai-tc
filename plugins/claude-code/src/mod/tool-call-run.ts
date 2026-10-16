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
 * stdout: {"v":1,"deny":string|null,"input":{...}|null,"context":string|null,"message":string|null,"findings":[...]}
 *   `message` is null when it says no more than `findings`, which the mod shows.
 * Exit 1 with nothing on stdout means "no decision": the mod passes the call on
 * unchanged and the PreToolUse command hook decides it as it always did.
 *
 * The mod hands this process a session id and a directory and no transcript
 * path, so it locates the session's transcript itself (locateSessionTranscript)
 * and its captures are stamped for the session's account, as the hook's are.
 *
 * Unless it denied, it leaves a note (src/mod/handoff.ts) naming the input the
 * tool will run with, so the command hook, shown that input next, does not
 * record the call a second time or ask for a grant already spent. The hook still
 * looks again at the executable fields (pre-tool-use-run.ts, noteStillHolds); the
 * note names the values this helper let through there. Nothing is written to
 * stderr.
 */
import { loadConfig } from '@akasecurity/plugin-sdk';

import { locateSessionTranscript } from '../hooks/account-stamp.ts';
import type { ScannedField } from '../hooks/pre-tool-use-decision.ts';
import { inputEventKind } from '../hooks/pre-tool-use-fields.ts';
import { runPreToolUse } from '../hooks/pre-tool-use-run.ts';
import type { HookOutput } from '../hooks/shared.ts';
import { countFailOpen, getString, parseJson } from '../hooks/shared.ts';
import type { PointersByText } from './findings-log.ts';
import { recordModFindings, toolFieldAction } from './findings-log.ts';
import { authorizeValues, recordToolHandoff } from './handoff.ts';
import type { HelperRun } from './helper-run.ts';
import { answerFromOutputs, messageForUser } from './tool-call-answer.ts';

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
  // What was detected in the scanned fields. A call this helper lets through
  // carries those values in the clear (a granted pointer dereferenced, a value an
  // exception covers, a fallback that only warns), and the hook, which cannot see
  // the grants now spent, takes them from the note rather than judging them again.
  const letThroughValues: string[] = [];
  let scanned: readonly ScannedField[] = [];
  let vaultedPointers: PointersByText = new Map();
  const sessionId = getString(input, 'sessionId');
  const config = loadConfig();
  const run = await runPreToolUse(
    {
      tool_name: tool,
      tool_input: toolInput,
      session_id: sessionId,
      cwd: getString(input, 'cwd'),
      transcript_path: locateSessionTranscript(config, sessionId),
    },
    (output) => {
      outputs.push(output);
      return Promise.resolve();
    },
    {
      mode: 'mod',
      onScanned: (fields, vaulted) => {
        scanned = fields;
        vaultedPointers = vaulted;
        for (const { result } of fields) {
          for (const finding of result.findings) letThroughValues.push(finding.rawMatch);
        }
      },
    },
  );
  // No store, or nothing in the call to scan: the hook is the one to say so.
  if (run !== 'finished') return { code: 1, stdout: '' };

  const answer = answerFromOutputs(outputs);
  const { dataDir } = config;
  if (sessionId !== undefined) {
    for (const { text, result } of scanned) {
      const pointers = vaultedPointers.get(text);
      answer.findings.push(
        ...recordModFindings(dataDir, sessionId, {
          sessionId,
          kind: inputEventKind(tool),
          text,
          result,
          where: 'tool-input',
          action: toolFieldAction(result, pointers),
          pointers,
        }),
      );
    }
  }
  answer.message = messageForUser(answer.message, answer.findings.length > 0);
  if (answer.deny === null) {
    recordToolHandoff(
      dataDir,
      tool,
      answer.input ?? toolInput,
      Date.now(),
      authorizeValues(dataDir, letThroughValues),
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
