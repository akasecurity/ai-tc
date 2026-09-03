// The device half of the device-command channel: what an attached machine does
// when its deployment has asked it to do something.
//
// Runs in the DETACHED CHILD only, immediately after the policy pull and in the
// same process — never on a hook path, and never inline in a session. The
// cadence is the policy sync's own fifteen-minute throttle, deliberately
// unchanged: a command is picked up at the next session entry, and nothing here
// makes that instant. No surface in this repository renders a device-command
// yet, so an operator's only view of one is whatever the control plane shows;
// anything claiming a re-scan is immediate would be claiming it on this
// module's behalf, and this module cannot deliver it.
import { readControlPlaneCredentialFile, readWorkspaceSettings } from '@akasecurity/persistence';
import type { PluginConfig, SourceTool } from '@akasecurity/plugin-sdk';
import { createRemoteClient } from '@akasecurity/remote';
import type { DeviceCommand, DeviceCommandFailureReason } from '@akasecurity/schema';
import { isAttached } from '@akasecurity/schema';

import { withTimeout } from './with-timeout.ts';

/**
 * Bound for one poll/scan/ack cycle — the same reasoning as
 * `SYNC_REQUEST_TIMEOUT_MS`, and for the same reason it is not the 2 s hook
 * bound: nothing is waiting on this process.
 *
 * The two REQUESTS get this bound each. The scan between them deliberately does
 * not: it is local filesystem work whose duration is the size of the user's
 * checkout, and cutting it off mid-way would leave the ledger advanced for
 * files whose findings were never written. A scan that takes a long time is a
 * big repository, not a fault.
 */
export const COMMAND_REQUEST_TIMEOUT_MS = 30_000;

/**
 * What one cycle did. `null` from `runCommandSync` means NO ATTEMPT — the same
 * distinction `runPolicySync` draws, and for the same reason: it must not be
 * confused with a cycle that ran and found nothing.
 *
 *   `none`        polled, and the deployment had nothing pending. The ordinary
 *                 answer, and the one this runs into on almost every sync.
 *   `reported`    scanned and acked. The command is done for this device.
 *   `failed`      scanned or forwarded unsuccessfully, and said so with a
 *                 closed reason. Also terminal for this device — the ack is
 *                 what takes it off the roster's outstanding column.
 *   `unreachable` the poll itself did not answer. Nothing was scanned and
 *                 nothing was acked; the next sync tries again.
 */
export type CommandSyncOutcome = 'none' | 'reported' | 'failed' | 'unreachable';

/**
 * The scan this module is allowed to run.
 *
 * INJECTED, and that is a dependency-graph fact before it is a testing
 * convenience: `@akasecurity/scanner` already depends on this package, so
 * importing it here would close a cycle. The three plugin `sync` entries that
 * ship a scanner pass it in.
 *
 * It also keeps the capability honest. A host with no scanner — the browser
 * extension's native host — passes nothing, and this module then does not poll
 * at all rather than polling and leaving a command it can never service sitting
 * outstanding until it expires.
 *
 * The signature takes NO scope. That is the point: the caller supplies the
 * ability to scan, and this module supplies the scope, which is fixed
 * device-side and cannot be influenced by anything on the wire.
 */
export type CommandScan = () => Promise<{ projects: number }>;

export interface RunCommandSyncDeps {
  /** The ~/.aka root, for reading settings. */
  base: string;
  settingsDir: string;
  /** Absent on a host that cannot scan; see `CommandScan`. */
  scan?: CommandScan | undefined;
}

/**
 * The reason a thrown scan reports, as a constant rather than a mapping.
 *
 * The thrown error is DISCARDED, deliberately and without being read: the
 * closed enum is the whole reason no device-supplied text can reach an
 * operator's screen through this channel, and a function that inspected the
 * error would be where a message eventually got attached to the ack. There is
 * no catch-all member for the same reason.
 */
const SCAN_THREW: DeviceCommandFailureReason = 'scan_failed';

/**
 * A scan that ran and found nothing to forward.
 *
 * NOT `reported` with a count of zero. The two are different facts and an
 * operator acts on them differently — "this machine has no projects here" is a
 * configuration observation, while "reported: 0 projects" reads as a scan that
 * ran over a checkout and found nothing worth sending. The roster gives this
 * member its own neutral treatment rather than the failure styling, which is
 * only possible if the device distinguishes them in the first place.
 */
const SCAN_FOUND_NOTHING: DeviceCommandFailureReason = 'no_projects';

/**
 * Poll, service, ack — once.
 *
 * NEVER THROWS. This is called from the detached child, which has no parent
 * watching, and the whole channel is a convenience: a machine that cannot
 * service a command must fall back to being a machine that scans on its own
 * schedule, never to a broken session or a crashed sync.
 *
 * ACK-ON-FAILURE IS LOAD-BEARING, not politeness. A device that scans and fails
 * silently is indistinguishable on the roster from one that is switched off,
 * and the operator waits 24 hours for a command to expire before learning
 * anything. Acking a failure is what turns "we never heard from it" into "it
 * tried and here is the closed reason".
 */
export async function runCommandSync(deps: RunCommandSyncDeps): Promise<CommandSyncOutcome | null> {
  // Nothing to service, and nothing to ask. A host with no scanner must not
  // poll: a command it received and could never run would sit outstanding on
  // the roster until it expired, which reads to an operator exactly like a
  // machine that is off.
  if (deps.scan === undefined) return null;

  // BOTH HALVES, the same rule as runPolicySync: the descriptor names the
  // deployment, the credential authenticates to it, and either alone is not an
  // attachment. A credential minted for another endpoint counts as absent.
  const settings = readWorkspaceSettings(deps.base);
  const connection = isAttached(settings) ? settings.controlPlane : undefined;
  const state =
    connection === undefined
      ? undefined
      : readControlPlaneCredentialFile(deps.settingsDir, connection);
  if (connection === undefined || !state?.usable) return null;

  const client = createRemoteClient({
    endpoint: connection.endpoint,
    apiKey: state.credential.apiKey,
    timeoutMs: COMMAND_REQUEST_TIMEOUT_MS,
  });

  let command: DeviceCommand | null;
  try {
    command = await withTimeout(client.pollCommand(), COMMAND_REQUEST_TIMEOUT_MS);
  } catch {
    // Includes a deployment that answered with a command this build refuses to
    // parse — one carrying a path, say. Nothing is scanned and nothing is
    // acked, which is the correct response to an instruction that failed its
    // own contract: the command stays outstanding and a human sees that.
    return 'unreachable';
  }
  if (command === null) return 'none';

  // The scope is chosen HERE, from nothing the command said. `command` is
  // consulted for its id and nothing else — it carries no path, and
  // `DeviceCommand.strict()` is what keeps that true rather than customary.
  let projects = 0;
  let reason: DeviceCommandFailureReason | null = null;
  try {
    projects = (await deps.scan()).projects;
    if (projects === 0) reason = SCAN_FOUND_NOTHING;
  } catch {
    reason = SCAN_THREW;
  }

  try {
    await withTimeout(
      reason === null
        ? client.ackCommand(command.id, { outcome: 'reported', projectsScanned: projects })
        : client.ackCommand(command.id, {
            outcome: 'failed',
            reason,
            projectsScanned: projects,
          }),
      COMMAND_REQUEST_TIMEOUT_MS,
    );
  } catch {
    // The work happened; only the report did not. Reported as `unreachable`
    // rather than as the scan's own outcome, because from the deployment's side
    // this device is still outstanding — claiming `reported` here would make
    // this module's return value disagree with the roster it exists to feed.
    return 'unreachable';
  }

  return reason === null ? 'reported' : 'failed';
}

/**
 * The scan scope a serviced command uses, as a description rather than a value:
 * every search root is chosen device-side.
 *
 * ONE WORKTREE, and deliberately the NARROWER of the two modes the interactive
 * scan offers. `scanWorktree` is what `/aka:scan` runs with no flags: it scans
 * the directory it is given and does not go looking for others. The wider mode
 * — `scanAllRepos`, reached interactively only by typing `--discover`, which
 * `commands/scan.md` titles "Multi-repo scan (opt-in)" — walks four levels down
 * and returns every repository it finds under the root. A server-issued command
 * gets the mode a human gets by default, never the one a human has to ask for.
 *
 * That distinction is the whole scope argument, so it is worth being exact
 * about what the wider mode would have meant here. `discoverGitRepos` defaults
 * `maxDepth` to 4, so a session started in `~/clients` would sweep every
 * checkout under it and forward all of their findings on one command — three
 * customers' repositories reported to one deployment. The scan root is chosen
 * device-side either way and the wire can still name nothing, but "the wire
 * cannot name the root" is a bound on WHICH directory, never on how much sits
 * under it. Only the mode bounds that.
 *
 * The detached child inherits its working directory from the session that
 * spawned it, so the scanned worktree is the project the user was actually in —
 * and a session started in a package subdirectory of a monorepo scans that
 * directory rather than reporting no projects, which is what the discovery walk
 * would have done, since it only ever descends.
 *
 * `--root ~` stays the explicit, human-typed, machine-wide opt-in, and a
 * command has no way to ask for it: there is no path on the wire to ask WITH.
 */
export const COMMAND_SCAN_SCOPE = 'the session working directory' as const;

/**
 * The shape of `scanWorktree`, spelled structurally.
 *
 * Structural rather than imported, because importing `@akasecurity/scanner`
 * here is the dependency cycle `CommandScan` describes. Narrow on purpose: it
 * names only what this adapter passes and reads, so a scanner signature change
 * that matters shows up as a type error at the three call sites rather than
 * being absorbed by an `any`.
 *
 * `rootDir` is REQUIRED here even though the scanner defaults it, so the scope
 * is visibly chosen at the one call site that reasons about it rather than
 * inherited from a default that could move in another package.
 */
export type WorktreeScan = (
  config: PluginConfig,
  opts: { sourceTool: SourceTool; rootDir: string },
) => Promise<{ scanned: number }>;

/**
 * Build the injected scan from a host's scanner.
 *
 * A thin adapter, but it exists so the SCOPE is written ONCE, here, next to the
 * reasoning above — three copies of a security-relevant default across three
 * plugin trees is three places for it to drift, and the one that drifts quietly
 * is the one that widens.
 */
export function commandScanFor(
  config: PluginConfig,
  scanWorktree: WorktreeScan,
  sourceTool: SourceTool,
): CommandScan {
  return async () => {
    const summary = await scanWorktree(config, {
      sourceTool,
      // Never the home directory implicitly, and never anything the wire named.
      rootDir: process.cwd(),
    });
    // 0 or 1: this mode scans exactly one worktree, so the count answers "was
    // there anything here to scan", not "how many projects were found". A
    // worktree with no scannable file is the `no_projects` outcome rather than
    // a report of zero, which is a distinction an operator acts on.
    return { projects: summary.scanned > 0 ? 1 : 0 };
  };
}
