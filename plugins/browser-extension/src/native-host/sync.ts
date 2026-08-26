/**
 * The detached policy-sync child for the native host.
 *
 * The host calls `handleSessionStart`, which triggers a policy pull on an
 * attached machine — and the trigger resolves this script as a SIBLING of the
 * running one, so it has to land in this same outDir beside host.js. Without it
 * the spawn fails with ENOENT on a later tick, `spawnDetached` swallows that by
 * design, and the throttle marker has already advanced: the organization's
 * policy would never be pulled on this harness, on any schedule, with nothing
 * recording the gap.
 *
 *   node native-host/sync.js
 *
 * Fully fail-open, and it never throws. Always exits 0.
 */
import { runAttachedSync } from '@akasecurity/plugin-runtime';

try {
  await runAttachedSync();
} catch {
  // Nothing to report to — this process is detached with stdio ignored.
}
process.exit(0);
