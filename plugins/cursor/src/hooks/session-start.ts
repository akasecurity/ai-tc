// Entry script `hooks.json` names. Stdio glue only: the handler lives in
// ./session-start-run.ts, which a test drives in-process, and `runHookFailOpen` (inside
// `runHookEntry`) guarantees the exit 0.
import { runSessionStart } from './session-start-run.ts';
import { runHookEntry } from './shared.ts';

await runHookEntry(runSessionStart);
