// `scripts/mod-tool-call.js`: reads stdin, runs it, writes the answer. The protocol is
// documented in ./tool-call-run.ts.
import { readStdin } from '../hooks/shared.ts';
import { runModToolCall } from './tool-call-run.ts';

const { code, stdout } = await runModToolCall(await readStdin());
if (stdout !== '') process.stdout.write(stdout);
process.exit(code);
