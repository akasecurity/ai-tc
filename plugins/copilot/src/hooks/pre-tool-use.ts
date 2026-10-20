/**
 * preToolUse (Copilot CLI, cloud coding agent) / PreToolUse (VS Code agent
 * mode) — the entry script the hooks manifest names.
 *
 * argv[2]: the event token. argv[3] (optional): the plugin manifest path.
 * stdin:   the host's payload, in either dialect (see ./dialect.ts).
 *
 * Stdio glue only. What the hook does, and what it writes to stdout, lives in
 * ./pre-tool-use-run.ts, which a test drives in-process; `runHookFailOpen`
 * (inside `runHookEntry`) is what guarantees the exit 0 — see ./shared.ts for
 * the limit of that guarantee, which is everything that yields.
 */
import { runPreToolUse } from './pre-tool-use-run.ts';
import { runHookEntry } from './shared.ts';

// No fail-open payload is passed, because there is no payload to write: a body
// that threw, declined, or outran the watchdog has reached no verdict, and on
// both hosts saying nothing is how a hook declines. `runHookFailOpen` still
// guarantees the exit 0 that this host reads as "no deny".
await runHookEntry(runPreToolUse);
