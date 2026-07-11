/**
 * Stop — fires once when the assistant finishes a response (the clean once-per-turn
 * boundary; covers pure-text turns that PostToolUse misses). The live token-usage
 * capture trigger.
 *
 * stdin: { session_id, transcript_path, cwd, hook_event_name, stop_hook_active }
 *
 * This hook does NOT reconcile inline — it only TRIGGERS the background worker so it
 * adds zero latency to the turn. It reads `session_id` + `transcript_path` STRAIGHT
 * from the payload (no path reconstruction), throttle-checks, and if not throttled
 * spawns `scripts/reconcile.js` detached + unref, forwarding both via argv, then
 * returns immediately. Fully fail-open: any error → no output, exit 0.
 */
import { loadConfig } from '@akasecurity/plugin-sdk';

import { triggerReconcile } from '../history/reconcile-trigger.ts';
import { parseJson, readStdin } from './shared.ts';
import { parseStopPayload } from './stop-payload.ts';

async function main(): Promise<void> {
  const trigger = parseStopPayload(parseJson(await readStdin()));
  if (trigger === undefined) return; // nothing to reconcile
  const config = loadConfig();
  // Throttled, detached spawn — the hook never waits on the reconcile.
  triggerReconcile(config.dataDir, trigger.sessionId, trigger.transcriptPath);
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
