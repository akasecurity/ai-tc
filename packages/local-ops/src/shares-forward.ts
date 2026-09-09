import {
  readControlPlaneCredential,
  readWorkspaceSettings,
  settingsDir,
  toEgressIngestRequest,
} from '@akasecurity/persistence';
import type {
  EgressIngestRequest,
  RecordProjectEgressInput,
  RemoteFailureKind,
} from '@akasecurity/schema';
import { controlPlaneName, isAttached } from '@akasecurity/schema';

// Forwarding the Data Shares register a scan just recorded, for the surfaces
// that record one: is this machine attached, does it hold a credential for the
// deployment its settings name, and did the send land — with an answer specific
// enough that whoever ran the scan can act on it.
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
 */
export type SharesForwardOutcome =
  | { status: 'not-attached' }
  | { status: 'disabled'; endpoint: string }
  | { status: 'no-credential'; endpoint: string }
  | { status: 'forwarded'; endpoint: string; callSites: number }
  | { status: 'failed'; endpoint: string; kind: RemoteFailureKind };

export interface SharesForwardDeps {
  send: SharesForwardSender;
  /** Default true. False is an explicit opt-out for this run, not a policy. */
  enabled?: boolean;
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

    if (deps.enabled === false) return { status: 'disabled', endpoint };

    // The credential is checked against the descriptor, so a file minted for
    // another deployment is not usable here — presenting it would be handing a
    // bearer token to an endpoint it was never issued for.
    const credential = readControlPlaneCredential(settingsDir(base), connection);
    if (credential === null) return { status: 'no-credential', endpoint };

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
