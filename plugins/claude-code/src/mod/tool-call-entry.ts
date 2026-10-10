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
import { readStdin } from '../hooks/shared.ts';
import { runModToolCall } from './tool-call-run.ts';

const { code, stdout } = await runModToolCall(await readStdin());
if (stdout !== '') process.stdout.write(stdout);
process.exit(code);
