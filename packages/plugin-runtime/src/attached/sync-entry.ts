import { dataDir, defaultDataDir, settingsDir } from '@akasecurity/persistence';

import type { CommandScan } from './command-sync.ts';
import { runCommandSync } from './command-sync.ts';
import type { PolicySyncOutcome } from './policy-sync.ts';
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
 *
 * `deps.scan` adds the device-command channel to the same child. It is optional
 * because not every host can service a command: the browser extension's native
 * host ships no scanner, and a host that cannot scan must not poll — a command
 * it received and could never run would sit outstanding on an operator's roster
 * until it expired, which reads exactly like a machine that is switched off.
 */
export async function runAttachedSync(
  base: string = defaultDataDir(),
  deps: { scan?: CommandScan | undefined } = {},
): Promise<void> {
  let policyOutcome: PolicySyncOutcome | null = null;
  try {
    const result = await runPolicySync({
      base,
      settingsDir: settingsDir(base),
      dataDir: dataDir(base),
    });
    if (result !== null) {
      policyOutcome = result.outcome;
      writeSyncState(dataDir(base), result);
    }
  } catch {
    // Nothing to report to and nowhere to report it.
  }

  // The credential this process holds was just refused, and re-presenting it on
  // another route in the same second cannot go differently: `unauthorized` is a
  // 401, the credential itself no longer accepted, which is not a property of
  // any one route. Skipping saves a round trip that is certain to fail — and
  // the user is not left uninformed by it, because the pull that learned this
  // has already written the outcome `/aka:status` renders.
  //
  // `forbidden` is deliberately NOT included. A 403 can mean "this key is
  // scoped away from THIS route" (see `failure.ts`), and the policy bundle is a
  // read with no write-role guard while the command channel is a different
  // route — so a 403 there is not proof of a 403 here, and declining to even
  // ask would be this device deciding on the deployment's behalf.
  if (policyOutcome === 'unauthorized') return;

  // AFTER the policy pull, and in its own try. Ordered that way because the
  // scan the command triggers reads the policy the pull just cached, so a
  // command serviced first would scan against the previous ruleset.
  //
  // Separately caught rather than sharing the block above: a policy pull that
  // threw must not also silently cancel the command channel, and a command that
  // fails must not lose the sync state the pull already wrote. Two independent
  // jobs sharing one child, not one job in two halves.
  try {
    await runCommandSync({ base, settingsDir: settingsDir(base), scan: deps.scan });
  } catch {
    // Same contract: nothing is waiting on this process. `runCommandSync` is
    // documented never to throw, so reaching here is a bug rather than an
    // expected path — and the response to a bug in a detached child is still to
    // exit quietly rather than to take the sync down with it.
  }
}
