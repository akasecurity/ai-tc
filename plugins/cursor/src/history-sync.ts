/**
 * The detached history-drain child.
 *
 * Spawned by SessionStart (see `triggerHistorySync`), at most every five minutes
 * and only on a machine that is attached, holds a credential for that
 * deployment, and whose user granted sending the activity recorded before it
 * attached. It sends a slice of that backlog and marks what was accepted;
 * nothing on a hook path awaits this process, and no hook ever sends any of it.
 *
 *   node scripts/history-sync.js
 *
 * Fully fail-open, and it never throws: `runHistorySyncPass` records progress
 * for `aka status` to render and swallows everything else. Always exits 0.
 */
import { runHistorySyncPass } from '@akasecurity/plugin-runtime';

try {
  await runHistorySyncPass();
} catch {
  // Nothing to report to — this process is detached with stdio ignored.
}
process.exit(0);
