import { hostname } from 'node:os';

import {
  bindingHashOf,
  codingScopeExtras,
  readBoundAttachedIdentity,
  readControlPlaneCredential,
  recordValidatedWorkAccount,
} from '@akasecurity/persistence';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { createRemoteClient } from '@akasecurity/remote';
import type { AttachedIdentity, ResolvedAttachmentScope } from '@akasecurity/schema';
import {
  attachmentModeOf,
  isAttached,
  isAttachmentScopeValid,
  isWebAccountKey,
  parseAttachmentScope,
  resolveScope,
  workSubscriptionsOn,
} from '@akasecurity/schema';

import type { AccountScope, AccountScopeContext } from '../account-scope.ts';
import { createAccountScope } from '../account-scope.ts';
import { StandaloneDataGateway } from '../standalone-gateway.ts';
import { createForwardPolicy } from './forward-policy.ts';
import { AttachedDataGateway } from './gateway.ts';
import { createPluginBlock, type PluginBuildInfo } from './plugin-block.ts';
import { createPolicyStore } from './policy-store.ts';
import { writePostureReportState } from './posture-report-state.ts';
import { createPostureReporter } from './posture-reporter.ts';
import { readStorePosture } from './posture-snapshot.ts';
import { createPostureStore } from './posture-store.ts';
import { deploymentNameForTerminal } from './status.ts';

/**
 * What a resolving caller knows about itself, threaded to every gateway
 * factory. ONE named shape on purpose: it is spelled at each hop of the
 * resolution chain (`resolveDataGateway` → `DataGatewayFactory` → here), and a
 * member added to only some of those hops would compile while silently
 * dropping the field at whichever hop was missed.
 *
 * `recordedBy` names the calling binary (`plugin@<v>`) for the standalone
 * gateway's inventory stamp. `pluginBuild` is the calling artifact's package
 * identity for the attached posture self-report; `| undefined` is explicit so
 * a caller can pass a best-effort read's miss verbatim rather than spelling a
 * conditional spread at every site.
 */
export interface GatewayMeta {
  recordedBy?: string;
  pluginBuild?: PluginBuildInfo | undefined;
}

/**
 * Build the gateway a machine's own configuration asks for.
 *
 * THE LOCAL GATEWAY IS BUILT FIRST AND UNCONDITIONALLY, because attached mode
 * is a decorator over it rather than an alternative to it. Every write lands
 * locally whether or not anything is forwarded, so the local store stays the
 * read model and the enforcement engine on every machine — and the degraded
 * path below has its answer already constructed, with no credential having
 * reached a client that was never built.
 *
 * BOTH HALVES OF AN ATTACHMENT, OR STANDALONE. The settings descriptor names
 * which deployment (`isAttached` requires the mode AND the descriptor), and the
 * credential authenticates to it. Either alone is not an attachment: a
 * descriptor with no credential dials nothing, and a credential whose endpoint
 * does not match the descriptor is refused rather than presented to a host it
 * was not minted for — see `readControlPlaneCredentialFile`.
 *
 * FAIL-OPEN THROUGHOUT. Absent, malformed, untrusted or mismatched credential,
 * an endpoint this build will not send to, or any error at all while wiring the
 * decorator: the machine gets the local gateway and behaves exactly as a
 * standalone one. A session is never broken by a configuration problem, which
 * is the whole contract this package is shaped around.
 */
export function resolveGatewayForConfig(config: PluginConfig, meta?: GatewayMeta): DataGateway {
  const local = new StandaloneDataGateway(config.dataDir, bundledDetections(), meta);

  try {
    if (!isAttached(config.settings)) return local;
    const connection = config.settings.controlPlane;
    if (connection === undefined) return local;

    // The transport's door: one value, no reasons, nothing to branch on. A
    // gateway that could not build a client falls back to the local one either
    // way, so the reason is of no use here — and asking for the credential by
    // name is what keeps the narrow state the default everywhere else.
    const credential = readControlPlaneCredential(config.settingsDir, connection);
    if (credential === null) return local;

    // WHAT THIS GATEWAY MAY FORWARD, resolved once, here, from the two halves of
    // the attachment this function already holds. The MODE comes from the
    // credential: a machine credential carries none, and means machine. The
    // enrolled keys come from the settings this config was loaded with, and are
    // valid only for the endpoint the connection names. Resolved per gateway
    // and never cached, so an enrollment change reaches the next resolve.
    //
    // A scoped attachment's scope also holds the coding-agent keys derived from
    // the identity record bound to this credential (`codingScopeExtras`): one per
    // work account the device recognised, while work subscriptions are on, and
    // one per account enrolled by hand for coding sessions. A machine attachment
    // reads no identity record. The account scope, when the identity record
    // holds, is built over the same keys.
    //
    // Inside the `try` on purpose: a throw while resolving lands in the catch
    // below and returns the LOCAL gateway, which forwards nothing. That is the
    // safe direction for a scoping fault, and no client has been built yet.
    const mode = attachmentModeOf(credential);
    const resolved = resolveScope(
      { mode, scope: config.settings.attachmentScope, endpoint: connection.endpoint },
      mode === 'machine' ? [] : codingScopeExtras(config.dataDir, config.settings, credential),
    );
    // The gateway's own copy of the keys. `admit` adds to it, for this process
    // only, the account a hook has just validated, and every verdict reads it.
    const keys = new Set(resolved.keys);
    const attachment: ResolvedAttachmentScope = { mode: resolved.mode, keys };
    const account =
      resolved.mode === 'scoped'
        ? accountScopeFor(config, connection.endpoint, credential, keys)
        : undefined;

    const client = createRemoteClient({
      endpoint: connection.endpoint,
      apiKey: credential.apiKey,
    });
    const store = createPolicyStore(config.dataDir);
    // settingsDir, not dataDir: the device identity has to outlive a wipe of
    // the directory it measures, or every wipe would look like a new machine
    // and the one signal that detects a wipe would be the thing it destroys.
    const postureStore = createPostureStore(config.settingsDir, config.dataDir);

    // Held in a local so the posture reporter can share the SAME breaker the
    // gateway's writes use. Two policies over one dataDir would each keep their
    // own view of a plane that is either up or down for both.
    const forward = createForwardPolicy({ dir: config.dataDir });

    return new AttachedDataGateway({
      local,
      client,
      dataDir: config.dataDir,
      readCachedBundle: () => store.read().then((cached) => cached?.bundle ?? null),
      forward,
      attachment,
      ...(account === undefined ? {} : { account }),
      // What the session-start line names the deployment, read from the
      // connection this gateway forwards to, never from the credential.
      deploymentName: deploymentNameForTerminal(connection),
      posture: createPostureReporter({
        // THROUGH THE BREAKER, and wrapped HERE rather than around
        // `PostureReporter.send`. The reporter swallows every error by
        // contract, so a wrap outside it would hand `forward.run` a resolved
        // promise for a send that failed — recording a SUCCESS, clearing
        // `consecutiveFailures` and `lastFailure`, and telling `aka status` the
        // forward recovered when nothing did. Wrapping the raw client call puts
        // the breaker above the swallow, where it can see the truth.
        //
        // What it buys: once the breaker is open — the plane already confirmed
        // down by the gateway's own writes — this stops paying a request
        // timeout per throttle interval to re-learn it.
        //
        // And what `run` resolves with is handed back whole: the breaker has
        // classified the failure once, and the posture line in `aka status`
        // names the same cause the forward line does, from the same enum.
        report: (snapshot) => forward.run(() => client.reportStorePosture(snapshot)),
        // Beside the breaker's own file in dataDir, and cleared with it on
        // detach — an outcome describes a deployment, not the machine.
        recordOutcome: (outcome, atMs) => {
          writePostureReportState(config.dataDir, { outcome, atMs });
        },
        store: postureStore,
        readStore: () => readStorePosture(config.dbPath),
        hostname: () => hostname(),
        now: () => Date.now(),
        // The mode THIS gateway enforces, from the attachment resolved above,
        // so the report cannot name a mode the forward paths are not using.
        attachmentMode: attachment.mode,
        // The reporting build's identity, when the caller knows it (the plugin
        // adapters do; an embedder or a test may not). Composed with the SAME
        // policy store the sync child writes, so the block names the bundle
        // actually in force. The dependency key is omitted when no build is
        // known, and the reporter's optional call (`deps.pluginBlock?.()`)
        // then adds no block.
        ...(meta?.pluginBuild === undefined
          ? {}
          : { pluginBlock: createPluginBlock(meta.pluginBuild, store) }),
      }),
    });
  } catch {
    // A misconfigured attachment degrades to local recording rather than
    // breaking the session. `local` is already built and is exactly what this
    // returns, so no credential reached a client that was not constructed.
    return local;
  }
}

/** The credential the factory reads, as `readControlPlaneCredential` returns it. */
type HeldCredential = NonNullable<ReturnType<typeof readControlPlaneCredential>>;

/**
 * What a scoped attachment's identity record says for the credential in force:
 * the record, its binding hash, and what a hook validates against. Undefined when
 * no record holds for this credential: without one there is no attached user and
 * no scope tag, so no coding-agent key to stamp.
 */
function boundAccountOf(
  config: PluginConfig,
  endpoint: string,
  credential: HeldCredential,
):
  | {
      readonly record: AttachedIdentity;
      readonly bindingHash: string;
      readonly context: AccountScopeContext;
    }
  | undefined {
  const record = readBoundAttachedIdentity(config.dataDir, endpoint, credential);
  if (record === undefined) return undefined;
  const scope = config.settings.attachmentScope;
  const stored = isAttachmentScopeValid(scope, endpoint) ? parseAttachmentScope(scope) : undefined;
  return {
    record,
    bindingHash: bindingHashOf(record.endpoint, record.credentialDigest, record.attachedUserDigest),
    context: {
      attachedUserDigest: record.attachedUserDigest,
      workSubscriptionsOn: workSubscriptionsOn(scope),
      learned: record.workAccounts,
      manual: (stored?.entries ?? [])
        .filter((entry) => entry.kind === 'account' && entry.codingAgents === true)
        .map((entry) => entry.identity),
    },
  };
}

/**
 * The account scope of a scoped attachment, over `keys`, or undefined when no
 * identity record holds. It carries what a hook validates against, and writes a
 * learned account with this gateway's own credential, which no hook holds.
 */
function accountScopeFor(
  config: PluginConfig,
  endpoint: string,
  credential: HeldCredential,
  keys: Set<string>,
): AccountScope | undefined {
  const bound = boundAccountOf(config, endpoint, credential);
  if (bound === undefined) return undefined;
  const { record, bindingHash, context } = bound;
  return createAccountScope({
    keys,
    scopeTag: record.scopeTag,
    bindingHash,
    context,
    learn: (accountKey) =>
      context.workSubscriptionsOn && isWebAccountKey(accountKey)
        ? recordValidatedWorkAccount(config.dataDir, { endpoint, credential, key: accountKey })
        : 'refused',
  });
}

/**
 * The account context and binding hash a hook validates a session against, read
 * without opening a gateway, for a hook that runs before it opens one (session
 * start's observation, Stop's). The same credential and identity record the
 * factory reads; undefined unless this machine is attached scoped and the record
 * holds. Total.
 */
export function readAccountScope(
  config: PluginConfig,
): { readonly context: AccountScopeContext; readonly bindingHash: string } | undefined {
  try {
    if (!isAttached(config.settings)) return undefined;
    const connection = config.settings.controlPlane;
    if (connection === undefined) return undefined;
    const credential = readControlPlaneCredential(config.settingsDir, connection);
    if (credential === null || attachmentModeOf(credential) !== 'scoped') return undefined;
    const bound = boundAccountOf(config, connection.endpoint, credential);
    return bound === undefined
      ? undefined
      : { context: bound.context, bindingHash: bound.bindingHash };
  } catch {
    return undefined;
  }
}
