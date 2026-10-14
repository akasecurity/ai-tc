// `scripts/mod-reveal.js`: reads stdin, runs it, writes the answer. The protocol is
// documented in ./reveal-run.ts.
import { readStdin } from '../hooks/shared.ts';
import { runModReveal } from './reveal-run.ts';

const { code, stdout } = await runModReveal(await readStdin());
if (stdout !== '') process.stdout.write(stdout);
process.exit(code);
