/**
 * The detached body-expiry child.
 *
 * Spawned by SessionStart (see `triggerContentRetention`), at most hourly and
 * only on a machine whose user switched body expiry on. It clears
 * `audit_events.content` past the retention horizon — the prompt, reply, tool
 * output or scanned file text a capture recorded — and touches neither the
 * event row, nor its findings, nor anything the dashboard aggregates.
 *
 *   node scripts/content-retention.js
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
