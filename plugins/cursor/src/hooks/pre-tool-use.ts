// Entry script `hooks.json` names. Stdio glue only: the handler lives in
// ./pre-tool-use-run.ts, which a test drives in-process, and `runHookFailOpen` (inside
// `runHookEntry`) guarantees the exit 0.
import { runPreToolUse } from './pre-tool-use-run.ts';
import { runHookEntry } from './shared.ts';

await runHookEntry(runPreToolUse);
