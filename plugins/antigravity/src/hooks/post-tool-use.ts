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
 * What tool output IS still scanned, and how: the transcript at
 * `transcriptPath` records the results, so they are scanned AFTER THE FACT by
 * the same reconcile worker the Stop hook drives (../history/scan.ts). Firing
 * that trigger here as well as on Stop is the whole job of this hook — it moves
 * detection of a secret in tool output from end-of-turn to mid-turn on a long
 * multi-tool turn. It costs nothing on the hot path: `triggerReconcile` is
 * throttled to one spawn per 30s per session and the child is detached + unref,
 * so a burst of tool calls produces at most one background pass.
 *
 * Fail-open on a fail-closed host: `runHookFailOpen` always writes `{}` and
 * exits 0 — see shared.ts.
 */
import { loadConfig } from '@akasecurity/plugin-sdk';

import { triggerReconcile } from '../history/reconcile-trigger.ts';
import { parseJson, readStdin, runHookFailOpen } from './shared.ts';
import { parseReconcileTrigger } from './stop-payload.ts';

const CARRY_ON = {};

async function main(): Promise<unknown> {
  const trigger = parseReconcileTrigger(parseJson(await readStdin()));
  if (trigger === undefined) return CARRY_ON;
  const config = loadConfig();
  triggerReconcile(config.dataDir, trigger.sessionId, trigger.transcriptPath);
  return CARRY_ON;
}

await runHookFailOpen(main, CARRY_ON);
