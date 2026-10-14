/**
 * sessionStart (Copilot CLI, cloud coding agent) / SessionStart (VS Code agent
 * mode) — the entry script the hooks manifest names.
 *
 * argv[2]: the event token. argv[3] (optional): the plugin manifest path.
 *          The event rides slot TWO on this host, so the manifest is displaced
 *          one place right; see `MANIFEST_ARGV_INDEX` in ../build-info.ts.
 * stdin:   the session-start payload, in either dialect.
 * stdout:  NOTHING, on every path, on both dialects.
 *
 * Stdio glue only. What the hook does lives in ./session-start-run.ts, which a
 * test drives in-process; `runHookFailOpen` (inside `runHookEntry`) is what
 * guarantees the exit 0 — see ./shared.ts for the limit of that guarantee,
 * which is everything that yields.
 */
import { runSessionStart } from './session-start-run.ts';
import { runHookEntry } from './shared.ts';

// No fail-open payload, and nothing to emit on the happy path either: this hook
// reaches no verdict, so every path through it writes nothing and exits 0.
await runHookEntry(runSessionStart);
