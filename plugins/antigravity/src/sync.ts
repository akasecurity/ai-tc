/**
 * The detached policy-sync child.
 *
 * Spawned by SessionStart (see `triggerPolicySync`), at most every fifteen
 * minutes and only on a machine whose settings name a control plane and which
 * holds a credential for it. It pulls the organization's policy bundle into the
 * on-disk cache that the hook path reads; nothing on a hook path awaits this
 * process, and no hook ever makes the request itself.
 *
 *   node scripts/sync.js
 *
 * Fully fail-open, and it never throws: `runAttachedSync` records an outcome
 * for `/aka:status` to render and swallows everything else. Always exits 0.
 */
import { runAttachedSync } from '@akasecurity/plugin-runtime';

try {
  await runAttachedSync();
} catch {
  // Nothing to report to — this process is detached with stdio ignored.
}
process.exit(0);
