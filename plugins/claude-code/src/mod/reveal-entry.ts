/**
 * The helper the ui.render mod runs through `$.process.run`:
 * `node <plugin root>/scripts/mod-reveal.js`.
 *
 * The mod draws vault pointers as the real value, or as a masked badge, and can
 * open neither the vault nor the settings. It hands the distinct complete
 * pointers it met here, once each, and caches the answers; it never asks again
 * for one it holds.
 *
 * This is the MessageDisplay hook's reveal, minus its delta plumbing: the same
 * consent gate, the same `vaultInlineReveal` mode, the same descriptor lookup
 * for the badge and the same audited resolve (`target: 'human'`,
 * `reason: 'display'`). Whether a pointer may be revealed where it stands (code,
 * quote, per-message cap) is the mod's call; a value is resolved only for an
 * item the mod asks to reveal.
 *
 * stdin:  {"v":1,"items":[{"token":"[[aka:...]]","reveal":true}, ...]}
 * stdout: {"v":1,"mode":"masked"|"full"|"off","items":[{"token","badge","revealed"}]}
 *   `badge` is what a masked pointer shows; `revealed` is the complete
 *   replacement for a revealed one (the value and its category marker), null
 *   unless the mode is full, the item asked for it and the vault answered.
 *   Mode `off` (no valid vault consent, or the setting off) answers no items:
 *   every pointer is left as written.
 * Exit 1 with nothing on stdout means "no answer": the mod shows the pointers
 * unchanged.
 *
 * A revealed value goes to stdout, which the mod draws and holds in its own memory (`$.state` carries only a version
 * counter),
 * and nowhere else. Nothing is written to stderr.
 */
import { readStdin } from '../hooks/shared.ts';
import { runModReveal } from './reveal-run.ts';

const { code, stdout } = await runModReveal(await readStdin());
if (stdout !== '') process.stdout.write(stdout);
process.exit(code);
