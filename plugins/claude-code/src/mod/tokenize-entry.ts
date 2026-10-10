/**
 * The helper the prompt.submit mod runs through `$.process.run`:
 * `node <plugin root>/scripts/mod-tokenize.js`.
 *
 * The vault key must never enter the mod, and the mod has no store. So when the
 * mod finds values its policy says to redact, it hands the prompt here. This
 * process does what the UserPromptSubmit hook would do with it, in the same
 * order and through the same code: it scans the prompt and decides it (policy,
 * exceptions), then rewrites each
 * value the policy said to redact. With a valid vault consent that is a vault
 * pointer for a value whose detection keeps it and `[REDACTED:<CATEGORY>]` for
 * one it destroys; without consent every value is the one-way marker.
 *
 * stdin:  {"v":1,"text":"<prompt>","sessionId":"...","cwd":"..."}
 *         or, for a conversation row the session.append backstop found a value
 *         in, {"v":1,"row":{"door":"attachment"},"text":"<block>",...}. A row is
 *         recorded as a `response` (only when it has findings, like PostToolUse),
 *         never as a prompt, leaves no prompt handoff, and carries no model note.
 * stdout: {"v":1,"text":"<rewritten prompt>","note":"<model note>"|null}
 * Exit 1 with nothing on stdout means "no rewrite": the mod then lets the
 * prompt through unchanged and the command hook decides it as it always did.
 *
 * The prompt's event and findings (all in today's shape) are recorded only when
 * a rewrite is returned, as the very last step before it is written: a helper
 * that declines, or is killed first by the mod's timeout, leaves nothing in the
 * store and the command hook records the prompt itself.
 *
 * The raw value never leaves this process except inside the vault. Nothing is
 * written to stderr.
 */
import { readStdin } from '../hooks/shared.ts';
import { runModTokenize } from './tokenize-run.ts';

const { code, stdout } = await runModTokenize(await readStdin());
if (stdout !== '') process.stdout.write(stdout);
process.exit(code);
