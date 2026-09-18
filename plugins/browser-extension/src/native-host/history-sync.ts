/**
 * The detached history-drain child for the native host.
 *
 * The host calls `handleSessionStart`, which drains the activity recorded
 * before an attach on a machine whose user granted sending it — and the
 * trigger resolves this script as a SIBLING of the running one, so it lands in
 * this same outDir beside host.js.
 *
 *   node native-host/history-sync.js
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
