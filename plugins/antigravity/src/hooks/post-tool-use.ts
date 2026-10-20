/**
 * PostToolUse — fires after a tool completes.
 *
 * stdin:  { toolCall: { name, args }, stepIdx, error?, conversationId,
 *           workspacePaths, transcriptPath, artifactDirectoryPath }
 * stdout: {} — the only payload this event accepts.
 *
 * THIS EVENT CANNOT SCAN A TOOL RESULT, because Antigravity does not send one.
 * Claude Code's PostToolUse carries `tool_response` (and `updatedToolOutput` to
 * rewrite it); Codex's carries `tool_response` and can at least withhold the
 * whole result with `{"decision":"block"}`. Antigravity's payload carries the
 * tool CALL again plus `stepIdx` and an optional `error` string — the result
 * itself never reaches the hook, and the documented return value is an empty
 * object. So there is no live response enforcement on this host at all, and
 * this adapter does not pretend otherwise: it registers no response scan and
 * ships no tool-response field table (the Codex sibling's tool-response.ts /
 * scan-response.ts have no counterpart here).
 *
 * Tool output is not scanned after the fact either. This hook fires the same
 * detached reconcile worker the Stop hook drives (../reconcile.ts →
 * ../history/usage.ts `reconcileSessionTail`), which reconciles the transcript
 * tail into usage and tool-call records and never reads tool output for
 * findings; even where it parses a tool call it keeps only the output's size.
 * On this host the transcript parser (../history/transcripts.ts) matches no
 * tool I/O at all: tool calls ride inline on a record as `{name, args}` with no
 * begin/end pair. Scanning tool output on Antigravity needs a tool-result
 * parser there first. Firing the trigger here as well as on Stop keeps the
 * reconciled tail current mid-turn on a long multi-tool turn. It costs nothing
 * on the hot path:
 * `triggerReconcile` is throttled to one pass per 30s per session and the
 * child is detached + unref, so a burst of tool calls produces at most one
 * background pass plus the one worker that runs when the window closes.
 *
 * Fail-open on a fail-closed host: `runHookFailOpen` always writes `{}` and
 * exits 0 — see shared.ts.
 */
import { loadConfig } from '@akasecurity/plugin-sdk';

import { triggerReconcile } from '../history/reconcile-trigger.ts';
import { parseJson, readStdin, runHookFailOpen } from './shared.ts';
import { parseReconcileTrigger } from './stop-payload.ts';
import { warnIfStoreRedirected } from './store-health.ts';

const CARRY_ON = {};

async function main(): Promise<unknown> {
  const trigger = parseReconcileTrigger(parseJson(await readStdin()));
  if (trigger === undefined) return CARRY_ON;
  const config = loadConfig();
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, trigger.sessionId);
  triggerReconcile(config.dataDir, trigger.sessionId, trigger.transcriptPath);
  return CARRY_ON;
}

await runHookFailOpen(main, CARRY_ON);
