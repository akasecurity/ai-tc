// `scripts/mod-tokenize.js`: reads stdin, runs it, writes the answer. The protocol is
// documented in ./tokenize-run.ts.
import { readStdin } from '../hooks/shared.ts';
import { runModTokenize } from './tokenize-run.ts';

const { code, stdout } = await runModTokenize(await readStdin());
if (stdout !== '') process.stdout.write(stdout);
process.exit(code);
