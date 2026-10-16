/**
 * userPromptSubmitted (Copilot CLI, cloud coding agent) / UserPromptSubmit
 * (VS Code agent mode) — the entry script the hooks manifest names.
 *
 * argv[2]: the event token. argv[3] (optional): the plugin manifest path.
 * stdin:   the prompt payload, in either dialect.
 * stdout (exit 0), CLI:     (nothing, ever — the notice goes to stderr)
 * stdout (exit 0), VS Code: {"systemMessage":"…"} → a note, or nothing
 *
 * Stdio glue only. What the hook does lives in ./user-prompt-submit-run.ts,
 * which a test drives in-process; `runHookFailOpen` (inside `runHookEntry`) is
 * what guarantees the exit 0 — see ./shared.ts for the limit of that guarantee,
 * which is everything that yields.
 */
import { runHookEntry } from './shared.ts';
import { runUserPromptSubmit } from './user-prompt-submit-run.ts';

// No fail-open payload: a body that threw, declined or outran the watchdog has
// scanned nothing, and saying nothing is how a hook declines on both hosts.
await runHookEntry(runUserPromptSubmit);
