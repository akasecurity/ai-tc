/**
 * Drives `apply.ts` in a CHILD process so a test can read what it wrote to fd 1.
 *
 * The output mode is unobservable in-process, which is why this file exists
 * rather than a spy. In 'inherit' mode the child is handed THIS process's
 * stdout directly, so its bytes never pass through anything JS can intercept;
 * in 'capture' mode they go to a pipe the caller then discards. The difference
 * between "the user watched three commands run" and "the terminal sat silent
 * for two minutes" therefore only exists across a process boundary, and the
 * assertion has to be made from the far side of one.
 *
 * Args: <install|update> <agentId> <inherit|capture>.
 */
import { applyPluginUpdate, installAgentPlugin } from '../../src/apply.ts';

const [op, agentId = '', mode] = process.argv.slice(2);
const apply = op === 'install' ? installAgentPlugin : applyPluginUpdate;
const result = apply(agentId, mode === 'inherit' ? 'inherit' : 'capture');

// A trailing marker, so a case can tell "nothing streamed" from "the runner
// never got that far" — an empty stdout otherwise reads as both.
process.stdout.write(`\n[done] ok=${String(result.ok)}\n`);
