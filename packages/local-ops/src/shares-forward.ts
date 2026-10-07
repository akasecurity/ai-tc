import { existsSync } from 'node:fs';
import { join } from 'node:path';

import {
  canonicalRepoUrl,
  readControlPlaneCredential,
  readWorkspaceSettings,
  scopeKeyOfProjectKey,
  settingsDir,
  toEgressIngestRequest,
} from '@akasecurity/persistence';
import { resolveRepoIdentity } from '@akasecurity/plugin-sdk';
import type {
  AttachedCredentialAny,
  EgressIngestRequest,
  RecordProjectEgressInput,
  RemoteFailureKind,
  ScopeVerdict,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  attachmentModeOf,
  controlPlaneName,
  isAttached,
  resolveScope,
  scopeVerdict,
} from '@akasecurity/schema';

// Forwarding the Data Shares register a scan just recorded, for the surfaces
// that record one: is this machine attached, does it hold a credential for the
// deployment its settings name, may THIS register leave the machine (a scoped
// attachment forwards only a project that is enrolled for that deployment, along
// with every repository nested in it), and did the send land — with an answer
// specific enough that whoever ran the scan can act on it.
//
// THE TRANSPORT IS A PARAMETER. This package opens no socket and imports no
// client; the sender's shape is declared here structurally so the decision
// sequence can live in one place while each surface keeps its own deadline and
// its own error rendering. That is also what makes the sequence testable
// without a server: every branch below is reachable with a function.
//
// It is deliberately NOT the forward the plugin's hooks use. That one runs
// inside a session with nobody to report to, so it is budgeted in milliseconds
// and guarded by a cross-process breaker that a run of failures opens for
// everyone. A scan is a person waiting at a prompt: it can afford a real
// deadline, it has somewhere to print the outcome, and a scan on a train with
// no signal must not silence the session forwarding that machine does
// afterwards. So nothing here reads or writes that breaker's state.

/** Where to send, and what to present. Assembled from settings + the credential file. */
export interface SharesForwardConnection {
  endpoint: string;
  apiKey: string;
}

/** What one send did. A failure is named, never thrown. */
export type SharesForwardSendResult = { ok: true } | { ok: false; kind: RemoteFailureKind };

/** The transport, supplied by the caller. This package opens no socket. */
export type SharesForwardSender = (
  connection: SharesForwardConnection,
  request: EgressIngestRequest,
) => Promise<SharesForwardSendResult>;

/**
 * Why a register did or did not reach the deployment.
 *
 * `endpoint` is the deployment's DISPLAY name — the administrator's label when
 * one was supplied, else the URL. Never anything read out of the credential
 * file: this value is printed, and the credential is not printable.
 *
 * `not-attached` carries no endpoint because there is none to name, and it is
 * the outcome a standalone machine reaches — the surfaces render nothing for
 * it, which is what keeps an unattached machine's output exactly as it was.
 *
 * `disabled` says WHY nothing was sent: the caller opted this run out, or the
 * Data Shares switch is off — read live, because the record this input came
 * from and this send are two steps, and the switch can move between them.
 *
 * `not-enrolled` is a SCOPED attachment declining to send. The machine
 * forwards only repositories enrolled for this deployment, and this project's
 * is not one of them — or it has no remote to enroll by, which is true of
 * every path-keyed project — or a repository nested inside the project (a
 * submodule, a clone kept in the checkout), whose call sites the walk folded
 * into this register, is not. Nothing was sent, by design rather than by
 * fault, so it reads as information, not as a failure to fix.
 */
export type SharesForwardOutcome =
  | { status: 'not-attached' }
  | { status: 'disabled'; endpoint: string; reason: 'opt-out' | 'data-shares-off' }
  | { status: 'no-credential'; endpoint: string }
  | { status: 'not-enrolled'; endpoint: string }
  | { status: 'forwarded'; endpoint: string; callSites: number }
  | { status: 'failed'; endpoint: string; kind: RemoteFailureKind };

/**
 * One sentence per failure kind, for whoever ran the scan.
 *
 * The one copy both surfaces render from, kept beside the outcome union it
 * describes so a kind added to the vocabulary is missing a sentence in exactly
 * one place. Each names the thing a person can do; `forbidden` names the one
 * case with a self-service fix (a key minted before this route's capability
 * existed is refused until re-minted, and re-attaching mints one).
 */
export const FORWARD_FAILURE_LINES: Record<RemoteFailureKind, string> = {
  unauthorized: 'key rejected; re-attach with a valid plugin key',
  forbidden:
    'key is valid but not permitted for Data Shares ingest; a key minted before Data Shares ' +
    'ingest existed needs a re-attach, otherwise ask your org admin',
  'route-absent': 'the deployment predates Data Shares ingest; upgrade it, then re-run the scan',
  'invalid-request': 'this build assembled a request the contract refuses; please report it',
  rejected:
    'the deployment refused the request body; this build and the deployment are out of step — ' +
    'upgrade one of them',
  unreachable: 'control plane unreachable (timeout or server error); the next scan retries',
};

export interface SharesForwardDeps {
  send: SharesForwardSender;
  /** Default true. False is an explicit opt-out for this run, not a policy. */
  enabled?: boolean;
  /**
   * Every directory below the scan target that the caller's walk listed and
   * that holds a `.git` entry: `ScanPathResult.nestedRepositories`, passed as
   * the walk reported it. The walk folds those repositories' files into this
   * project's register, so a SCOPED attachment forwards the register only when
   * each of them is enrolled as well (see `nestedVerdict`). Pass an empty list
   * when the walk found none. If it is absent, nothing vouches for what the
   * register carries, and a scoped attachment keeps it local. A machine-wide
   * attachment never reads it.
   */
  nestedRepositories?: readonly string[] | undefined;
}

/**
 * Whether this attachment lets `projectKey`'s register leave the machine.
 *
 * The verdict every forward path shares (`resolveScope`, then `scopeVerdict`),
 * fed from the three things that decide it:
 *   - the MODE, recorded on the credential. A machine-wide attachment forwards
 *     everything, as it always has, and never derives the key, so nothing
 *     about the key can change what it does.
 *   - the SCOPE, from the settings this call already read, so an enroll that
 *     landed a moment ago counts. It counts only for `endpoint`, the URL this
 *     machine is attached to, never its display name.
 *   - the project's KEY: the canonical `host/owner/repo` of a `git:` project
 *     key. A `path:` key, and a `git:` key that fell back to a worktree path
 *     because the repository has no remote, have none — a location on one
 *     machine is not something a scope can name — so they never forward from
 *     a scoped machine.
 *
 * FAIL-CLOSED. Anything that throws here reads as `local`: the register stays
 * on the machine and the outcome says so, rather than the caller's catch
 * reporting an outage for a send that was never going to happen.
 */
function projectVerdict(
  settings: WorkspaceSettings,
  endpoint: string,
  credential: AttachedCredentialAny,
  projectKey: string,
): ScopeVerdict {
  try {
    const resolved = resolveScope({
      mode: attachmentModeOf(credential),
      scope: settings.attachmentScope,
      endpoint,
    });
    return scopeVerdict(
      resolved,
      resolved.mode === 'scoped' ? scopeKeyOfProjectKey(projectKey) : undefined,
    );
  } catch {
    return 'local';
  }
}

/**
 * Whether every repository nested in the scanned project may be forwarded with
 * it: `'forward'` or `'local'`, never a throw.
 *
 * A walk folds a nested clone's or submodule's files into the project it is
 * walking, so the register this forward would send carries their call sites
 * under the project's key. On a scoped attachment it is sent only when each of
 * those repositories is enrolled as well. One with no remote never is.
 *
 * Absent, the list is `'local'`: nobody has said what the register carries. A
 * walk that found nothing passes an empty list.
 *
 * Machine-wide, it answers before reading the list, so a machine attachment
 * looks at no repository and sends what it always has.
 */
function nestedVerdict(
  settings: WorkspaceSettings,
  endpoint: string,
  credential: AttachedCredentialAny,
  nestedRepositories: readonly string[] | undefined,
): ScopeVerdict {
  try {
    const mode = attachmentModeOf(credential);
    if (mode === 'machine') return 'forward';
    if (nestedRepositories === undefined) return 'local';
    const resolved = resolveScope({ mode, scope: settings.attachmentScope, endpoint });
    for (const dir of nestedRepositories) {
      if (scopeVerdict(resolved, nestedRepositoryKey(dir)) === 'local') return 'local';
    }
    return 'forward';
  } catch {
    return 'local';
  }
}

/**
 * The scope key of the repository rooted exactly at `dir`, or undefined.
 *
 * It is derived the way this pipeline keys a project: the repository
 * identity's remote, canonicalized. `egress-record.ts` keys a project
 * `git:<identity.url>`, and the project verdict canonicalizes that. That is
 * also the key the plugin's resolver stamps on that repository's own
 * captures:
 * - origin, else the first remote;
 * - a submodule's own remote;
 * - a linked worktree's main checkout.
 *
 * A repository with no remote has no key: its identity falls back to a local
 * path, which never canonicalizes.
 *
 * `dir` must still hold its `.git`. Without one, the identity resolver climbs
 * to the repository AROUND it, and a nested directory whose `.git` vanished
 * since the walk would be judged by the enclosing project's key.
 *
 * It reads the repository afresh on every call rather than through the
 * plugin's per-directory memo. This runs in the dashboard's long-lived server,
 * where a remembered remote could outlive an edit to it.
 */
function nestedRepositoryKey(dir: string): string | undefined {
  if (!existsSync(join(dir, '.git'))) return undefined;
  const identity = resolveRepoIdentity(dir);
  return identity === undefined ? undefined : canonicalRepoUrl(identity.url);
}

/**
 * Forward one project's just-recorded register to the deployment the `base`
 * home is attached to.
 *
 * NEVER THROWS. A scan's value is the local write, which has already happened
 * by the time this runs; nothing here may cost the caller its result or its
 * exit code. A failure before the endpoint is known is reported as
 * `not-attached` (there is no deployment to name), and one after it as
 * `failed`/`unreachable` (something was going to be sent and was not).
 *
 * `base` is the `~/.aka` home to read, never a resolved default, so a scan
 * pointed at a sandbox home reads THAT home's attachment and credential and
 * cannot forward on the strength of the caller's real one.
 */
export async function forwardProjectEgress(
  base: string,
  input: RecordProjectEgressInput,
  deps: SharesForwardDeps,
): Promise<SharesForwardOutcome> {
  let endpointName: string | null = null;
  try {
    const settings = readWorkspaceSettings(base);
    const connection = settings.controlPlane;
    // Both halves or nothing: a `runMode` with no descriptor names no
    // deployment, and a descriptor without the mode is not an attachment.
    if (!isAttached(settings) || connection === undefined) return { status: 'not-attached' };

    const endpoint = controlPlaneName(connection);
    endpointName = endpoint;

    if (deps.enabled === false) return { status: 'disabled', endpoint, reason: 'opt-out' };

    // The kill-switch, re-read here rather than trusted from the record that
    // produced `input`: a person or a managed overlay flipping it off between
    // the local write and this send still stops the send.
    if (!settings.dataSharesInPlace) {
      return { status: 'disabled', endpoint, reason: 'data-shares-off' };
    }

    // The credential is checked against the descriptor, so a file minted for
    // another deployment is not usable here — presenting it would be handing a
    // bearer token to an endpoint it was never issued for.
    const credential = readControlPlaneCredential(settingsDir(base), connection);
    if (credential === null) return { status: 'no-credential', endpoint };

    // The scope, AFTER the credential and BEFORE the projection. After, because
    // the attachment's mode is recorded on the credential and there is no mode
    // to read without one — a missing credential stays `no-credential`, the
    // state with something to do about it. Before, because a register this
    // machine keeps local must not even be assembled into a request.
    //
    // The project's own key first, so a project already out of scope never
    // has its nested repositories read.
    if (projectVerdict(settings, connection.endpoint, credential, input.projectKey) === 'local') {
      return { status: 'not-enrolled', endpoint };
    }
    // Then every repository its walk found nested in it: one register, so one
    // verdict. A machine-wide attachment answers before the list is read. On a
    // scoped one, the list is read inside this guard, never as a call argument
    // outside it: a list that throws while being read is then not-enrolled,
    // like one that throws while being walked, and never reaches the outer
    // catch as an unreachable deployment.
    let nested: ScopeVerdict;
    try {
      nested =
        attachmentModeOf(credential) === 'machine'
          ? 'forward'
          : nestedVerdict(settings, connection.endpoint, credential, deps.nestedRepositories);
    } catch {
      nested = 'local';
    }
    if (nested === 'local') return { status: 'not-enrolled', endpoint };

    // The projection is the privacy boundary: source snippets out, the project
    // key digested, the per-project cap applied. Sending `input` itself is the
    // mistake this line exists to make impossible to write by accident.
    const request = toEgressIngestRequest(input);
    const result = await deps.send(
      { endpoint: connection.endpoint, apiKey: credential.apiKey },
      request,
    );
    return result.ok
      ? { status: 'forwarded', endpoint, callSites: request.hits.length }
      : { status: 'failed', endpoint, kind: result.kind };
  } catch {
    // A sender that throws instead of answering, or a settings read that came
    // apart. Either way nothing arrived, and 'try again' is the honest verdict.
    return endpointName === null
      ? { status: 'not-attached' }
      : { status: 'failed', endpoint: endpointName, kind: 'unreachable' };
  }
}
