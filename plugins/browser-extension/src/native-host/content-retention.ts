/**
 * The detached body-expiry child for the native host.
 *
 * The host calls `handleSessionStart`, which clears captured bodies past the
 * retention horizon on a machine whose user switched body expiry on — and the
 * trigger resolves this script as a SIBLING of the running one, so it lands in
 * this same outDir beside host.js.
 *
 *   node native-host/content-retention.js
 *
 * Fully fail-open, and it never throws: `runContentRetentionPass` returns a
 * report and swallows everything else. Always exits 0.
 */
import { runContentRetentionPass } from '@akasecurity/plugin-runtime';

try {
  runContentRetentionPass();
} catch {
  // Nothing to report to — this process is detached with stdio ignored.
}
process.exit(0);
