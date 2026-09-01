import { readControlPlaneCredentialFile, readWorkspaceSettings } from '@akasecurity/persistence';
import { createRemoteClient } from '@akasecurity/remote';
import type { AttachedCredential, ControlPlaneConnection } from '@akasecurity/schema';
import { isAttached } from '@akasecurity/schema';

import { classifyFailure } from './failure.ts';
import { createPolicyStore, type PolicyStore } from './policy-store.ts';
import { withTimeout } from './with-timeout.ts';

/**
 * Bound for the bundle download — NOT `REQUEST_TIMEOUT_MS`.
 *
 * That 2 s constant exists so a HOOK process is never stalled, and every call on
 * the hook path races against it. This code does not run on the hook path: it
 * runs in a detached child that has already outlived the session, where nothing
 * is waiting and the only cost of patience is a background process.
 *
 * Reusing the 2 s bound here would be actively harmful rather than merely
 * conservative. DNS + TLS + the whole body must fit inside it, and an organization
 * bundle carrying an installed-pack rule snapshot is easily a few hundred KB —
 * so on a slow link every attempt rejects, nothing is ever cached, and because
 * the cache never warms the cold path bypasses the throttle and forks a child on
 * every single session, forever. A short timeout there converts a slow network
 * into an unbounded spawn loop.
 */
export const SYNC_REQUEST_TIMEOUT_MS = 30_000;

/**
 * The organization policy pull. Runs in the DETACHED CHILD only — never on a hook
 * path, which reads `policy-cache.json` from disk and never touches the network
 * (G2).
 *
 * This module builds its own client rather than reusing the gateway's
 * `AttachedClient`. That interface declares exactly the four ingest writes, and
 * it is the seam that keeps the hook path off the network: putting a bundle
 * fetch on it would make "the gateway can reach the control plane for reads" true
 * again, which is the property local-first exists to remove. The cost is one
 * extra `createClient` in a process that is about to exit anyway.
 */

/**
 * What a sync attempt did, coarsely. `runPolicySync` returns `void` to its
 * caller (nothing awaits it), so this enum is how a failure becomes visible at
 * all — it is persisted and rendered by `renderAttachedStatus`.
 *
 * Deliberately coarse, and deliberately NOT the error message: the raw string
 * from a failed request can contain the URL, headers, or a body echo, and this
 * record is written next to — but not into — state a human is shown. Six
 * outcomes are enough to act on:
 *
 *   `ok`            fetched and cached a new bundle.
 *   `not-modified`  the cache was already current (304); the validator advanced.
 *   `unauthorized`  the key itself was rejected (401). TERMINAL for this device —
 *                   a revoked key will be rejected again in fifteen minutes and
 *                   every fifteen minutes after that, so this is one of the two
 *                   arms a human has to see rather than a retry loop to hide.
 *   `forbidden`     the key was accepted and REFUSED (403) — a suspended account
 *                   or member, or a key scoped away from this route. Terminal in
 *                   the same way, and split from `unauthorized` because the
 *                   remediation is not the same one: re-attaching mints a
 *                   credential that is refused identically, so the only fix is
 *                   an administrator's. See REFUSAL_LINES in status.ts.
 *   `unreachable`   transport failure or timeout. Expected on a laptop; the
 *                   next session tries again.
 *   `invalid-bundle` the control plane answered, but not with a bundle this build can
 *                   parse. A version-skew signal, not a network one.
 */
export type PolicySyncOutcome =
  'ok' | 'not-modified' | 'unauthorized' | 'forbidden' | 'unreachable' | 'invalid-bundle';

/** One attempt's result, as persisted for `status`. Never holds the raw error. */
export interface PolicySyncResult {
  outcome: PolicySyncOutcome;
  /** Epoch-ms the attempt finished. */
  atMs: number;
}

/**
 * Whether the plane answered with something this build cannot read.
 *
 * Read STRUCTURALLY off the error's `name`, never by matching its message. The
 * regex this replaced (`/invalid|parse|expected/i`) matched NONE of the strings
 * the transport actually raises, so every version skew rendered as
 * `unreachable` — pointing a user at their network for a plane that answered
 * promptly and correctly at the HTTP layer. Matching on wording is the coupling
 * ./failure.ts refuses for the status path, and it fails the same way here.
 *
 * `instanceof` is avoided for the reason given there too: this code is bundled
 * into every hook script while the transport is a separate package.
 */
function isInvalidBundle(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    (err as { name?: unknown }).name === 'RemoteResponseInvalid'
  );
}

export interface PullPolicyBundleDeps {
  /** Which deployment, from settings. */
  connection: ControlPlaneConnection;
  /** The credential for THAT deployment — already endpoint-matched. */
  credential: AttachedCredential;
  store: PolicyStore;
}

/**
 * One conditional pull, cache-aware.
 *
 * CONDITIONAL, always. An unconditional GET would re-download and re-parse a
 * bundle the device already holds on every scheduled run — a poll turned into a
 * transfer — and a client that treated the 304 as an error would throw on the
 * very first cache hit, where this module's fail-open contract would swallow it
 * while the throttle marker still advanced. The sync would then silently never
 * make progress.
 *
 * On 304 the bundle is rewritten UNCHANGED with the returned validator. That
 * looks redundant and is not: it advances `fetchedAtMs` (so a device that keeps
 * confirming freshness does not read as stale) and it carries the etag forward.
 * Dropping the etag here regresses into the alternating full-download/304 loop
 * the client's own tests exist to prevent.
 */
export async function pullPolicyBundle(deps: PullPolicyBundleDeps): Promise<PolicySyncOutcome> {
  const client = createRemoteClient({
    endpoint: deps.connection.endpoint,
    apiKey: deps.credential.apiKey,
    // The transport's own default is 10s, which would fire 20s before the race
    // below and make SYNC_REQUEST_TIMEOUT_MS unreachable — the bound this
    // module argues for at length would never have been in force. See that
    // constant for why a pull needs the longer one.
    timeoutMs: SYNC_REQUEST_TIMEOUT_MS,
  });

  const cached = await deps.store.read();
  const result = await withTimeout(client.getPolicyBundle(cached?.etag), SYNC_REQUEST_TIMEOUT_MS);

  if (!result.changed) {
    // Nothing to re-parse — the cached bundle IS the current one. With no cache
    // to refresh (a 304 against an empty cache should be impossible, but a
    // proxy can produce one) there is nothing to write and nothing to report.
    if (cached) await deps.store.write(cached.bundle, result.etag);
    return 'not-modified';
  }

  // NOT re-validated here. `result.bundle` is `PolicyBundle.safeParse` OUTPUT
  // — the transport parses every 2xx body with this exact schema — so a second
  // `safeParse` over it always succeeds and its failure arm was unreachable
  // code standing in for a check that had already happened.
  //
  // What that arm was FOR is still needed and is now real: a bundle this build
  // cannot read must become the `invalid-bundle` OUTCOME a human sees in
  // status, not a bare rejection. The transport raises `RemoteResponseInvalid`
  // for exactly that, `isInvalidBundle` recognises it structurally, and the
  // catch in `runPolicySync` maps it. Writing an unreadable bundle would poison
  // the cache permanently — `policy-store.read()` returns null on a parse
  // failure, so the machine would read as having no organization policy FOREVER
  // while this reported `ok`, and the 304 arm would replay the etag that
  // produced it — and it is the transport's parse that now prevents that.
  await deps.store.write(result.bundle, result.etag);
  return 'ok';
}

export interface RunPolicySyncDeps {
  /** The ~/.aka root, for reading settings. */
  base: string;
  settingsDir: string;
  dataDir: string;
  now?: () => number;
}

/**
 * The detached child's whole job: pull once, classify the outcome, never throw.
 *
 * Returns the result rather than `void`, because the caller that needs it is
 * the sync entry, which persists it for `status` to render. Nothing on a hook
 * path awaits this.
 *
 * `null` means NO ATTEMPT WAS MADE, which is distinct from every outcome in the
 * enum: each of those describes something a control plane did or failed to do, and the
 * caller persists them for `renderAttachedStatus` to render. There is no outcome
 * for "there was nothing to sync against", and reusing `unreachable` for it
 * would have status report a control plane that was never contacted. The caller writes
 * nothing when this is null.
 */
export async function runPolicySync(deps: RunPolicySyncDeps): Promise<PolicySyncResult | null> {
  const now = deps.now ?? (() => Date.now());
  // BOTH HALVES, or there is nothing to sync against: the descriptor names the
  // deployment and the credential authenticates to it, and either alone is not
  // an attachment. `readControlPlaneCredentialFile` is given the descriptor so
  // a credential minted for a different endpoint counts as absent here rather
  // than being presented to a host it was not minted for.
  const settings = readWorkspaceSettings(deps.base);
  const connection = isAttached(settings) ? settings.controlPlane : undefined;
  const state =
    connection === undefined
      ? undefined
      : // The WIDE read: `pullPolicyBundle` presents the credential. Runs in
        // the plugin's own process, never in a browser.
        readControlPlaneCredentialFile(deps.settingsDir, connection);
  // Detached between the spawn and here — nothing to do, and NOT AN ERROR, so
  // nothing is recorded either. The narrow ordering that makes this matter:
  // SessionStart spawns the child, the user runs detach, `removeControlPlaneCredential`
  // deletes `attached-sync-state.json`, and only THEN does the child reach this
  // line. Writing an outcome here would re-create the file the detach just
  // removed, and a later re-attach would open on a phantom "control plane unreachable
  // at last attempt" describing a control plane this device never called. That is the
  // same staleness `removeControlPlaneCredential` deletes the file to prevent.
  if (connection === undefined || !state?.usable) return null;

  try {
    const outcome = await pullPolicyBundle({
      connection,
      credential: state.credential,
      store: createPolicyStore(deps.dataDir),
    });
    return { outcome, atMs: now() };
  } catch (err) {
    // Credential verdicts FIRST, and off the STATUS rather than the message. A
    // status recovered by matching an error's text is joined to the transport
    // by nothing but wording, so a reword there would degrade the one outcome a
    // human must act on into the one they are meant to ignore, with nothing
    // failing to say so. The transport carries the status structurally, and the
    // forward path classifies with the same function, so the two halves of
    // attached mode cannot reach different verdicts about one refusal.
    const failure = classifyFailure(err);
    if (failure !== 'unreachable') return { outcome: failure, atMs: now() };
    if (isInvalidBundle(err)) return { outcome: 'invalid-bundle', atMs: now() };
    return { outcome: 'unreachable', atMs: now() };
  }
}
