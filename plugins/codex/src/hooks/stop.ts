/**
 * Stop — fires once when the assistant finishes a turn. The live token-usage
 * capture trigger. Identical wiring to plugins/claude-code/src/hooks/stop.ts —
 * Codex's Stop payload carries the same session_id + transcript_path fields.
 *
 * stdin: { session_id, transcript_path, cwd, hook_event_name, ... }
 *
 * It also records the model this turn ran on, which is what lets
 * UserPromptSubmit refuse a prohibited one on the next turn. See
 * ./model-guard.ts for why that is a turn late on this host.
 *
 * This hook does NOT reconcile inline — it only TRIGGERS the background worker so it
 * adds zero latency to the turn. It reads `session_id` + `transcript_path` STRAIGHT
 * from the payload (no path reconstruction), throttle-checks, and if not throttled
 * spawns `scripts/reconcile.js` detached + unref, forwarding both via argv, then
 * returns immediately. Fully fail-open: any error → no output, exit 0.
 */
import {
  codexModelFromRecord,
  loadConfig,
  modelFromTranscriptTail,
  recordSessionModel,
} from '@akasecurity/plugin-sdk';

import { triggerReconcile } from '../history/reconcile-trigger.ts';
import { parseJson, readStdin } from './shared.ts';
import { parseStopPayload } from './stop-payload.ts';
import { warnIfStoreRedirected } from './store-health.ts';

async function main(): Promise<void> {
  const trigger = parseStopPayload(parseJson(await readStdin()));
  if (trigger === undefined) return; // nothing to reconcile
  const config = loadConfig();
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, trigger.sessionId);
  // Record the model this turn ran on, so the NEXT UserPromptSubmit can refuse
  // a prohibited one without re-reading the rollout. Stop is the right place on
  // this host and effectively the only one: Codex has no model-switch event and
  // no SessionStart model, and Stop is where a transcript path is guaranteed to
  // be in hand. The consequence is that enforcement here is always a turn
  // behind — the first turn of a session runs unrefused, because nothing has
  // been recorded yet.
  //
  // Off the reconcile trigger's path deliberately: this is a bounded tail read
  // and a small write, while `triggerReconcile` only spawns. Doing it here keeps
  // the model current even when the reconcile throttle suppresses the spawn.
  recordSessionModel(
    config.dataDir,
    trigger.sessionId,
    modelFromTranscriptTail(trigger.transcriptPath, codexModelFromRecord),
  );
  triggerReconcile(config.dataDir, trigger.sessionId, trigger.transcriptPath);
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
