/**
 * Stop — fires when the execution loop terminates. The live token-usage
 * capture trigger.
 *
 * stdin: { executionNum, terminationReason, error?, fullyIdle, conversationId,
 *          workspacePaths, transcriptPath, artifactDirectoryPath }
 * stdout: {} — carry on and let the loop terminate.
 *
 * The one decision this event CAN express is `{"decision":"continue"}`, which
 * re-enters the loop instead of stopping. This hook never emits it: refusing to
 * let a session end is not a detection outcome, and a bug that emitted it would
 * spin the agent forever.
 *
 * This hook does NOT reconcile inline — it only TRIGGERS the background worker
 * so it adds zero latency to the turn. It reads `conversationId` +
 * `transcriptPath` STRAIGHT from the payload (no path reconstruction),
 * throttle-checks, and if not throttled spawns `scripts/reconcile.js` detached
 * + unref, forwarding both via argv, then returns immediately.
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
  if (trigger === undefined) return CARRY_ON; // nothing to reconcile
  const config = loadConfig();
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, trigger.sessionId);
  triggerReconcile(config.dataDir, trigger.sessionId, trigger.transcriptPath);
  return CARRY_ON;
}

await runHookFailOpen(main, CARRY_ON);
