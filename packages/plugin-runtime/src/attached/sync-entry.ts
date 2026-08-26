import { dataDir, defaultDataDir, settingsDir } from '@akasecurity/persistence';

import { runPolicySync } from './policy-sync.ts';
import { writeSyncState } from './sync-state.ts';

/**
 * The detached child's whole program.
 *
 * Each harness ships a two-line `sync` entry that imports this and calls it, so
 * the policy pull is written once here rather than three times in three plugin
 * trees. `triggerPolicySync` is what spawns those entries.
 *
 * NEVER THROWS. This runs with no parent watching — stdio is ignored and the
 * process is detached — so a rejection would be an unhandled rejection whose
 * only effect is a non-zero exit nobody reads. What a failure produces instead
 * is a recorded outcome, which is what `/aka:status` renders.
 *
 * A null result means NO ATTEMPT WAS MADE (the machine is not attached, or its
 * credential does not match the deployment its settings name), and nothing is
 * written for it. That is distinct from every recorded outcome, each of which
 * describes something a control plane did or failed to do — writing one here
 * would have status report a plane this machine never called, and would
 * re-create a file a detach had just removed.
 */
export async function runAttachedSync(base: string = defaultDataDir()): Promise<void> {
  try {
    const result = await runPolicySync({
      base,
      settingsDir: settingsDir(base),
      dataDir: dataDir(base),
    });
    if (result !== null) writeSyncState(dataDir(base), result);
  } catch {
    // Nothing to report to and nowhere to report it.
  }
}
