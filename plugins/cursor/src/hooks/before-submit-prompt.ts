// Entry script `hooks.json` names. Stdio glue only: the handler lives in
// ./before-submit-prompt-run.ts, which a test drives in-process, and `runHookFailOpen` (inside
// `runHookEntry`) guarantees the exit 0.
import { runBeforeSubmitPrompt } from './before-submit-prompt-run.ts';
import { runHookEntry } from './shared.ts';

await runHookEntry(runBeforeSubmitPrompt);
