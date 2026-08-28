import { hostname } from 'node:os';

import { readControlPlaneCredentialState } from '@akasecurity/persistence';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { createRemoteClient } from '@akasecurity/remote';
import { isAttached } from '@akasecurity/schema';

import { StandaloneDataGateway } from '../standalone-gateway.ts';
import { createForwardPolicy } from './forward-policy.ts';
import { AttachedDataGateway } from './gateway.ts';
import { createPluginBlock, type PluginBuildInfo } from './plugin-block.ts';
import { createPolicyStore } from './policy-store.ts';
import { createPostureReporter } from './posture-reporter.ts';
import { readStorePosture } from './posture-snapshot.ts';
import { createPostureStore } from './posture-store.ts';

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
 * was not minted for — see `readControlPlaneCredentialState`.
 *
 * FAIL-OPEN THROUGHOUT. Absent, malformed, untrusted or mismatched credential,
 * an endpoint this build will not send to, or any error at all while wiring the
 * decorator: the machine gets the local gateway and behaves exactly as a
 * standalone one. A session is never broken by a configuration problem, which
 * is the whole contract this package is shaped around.
 */
export function resolveGatewayForConfig(
  config: PluginConfig,
  meta?: { recordedBy?: string; pluginBuild?: PluginBuildInfo },
): DataGateway {
  const local = new StandaloneDataGateway(config.dataDir, bundledDetections(), meta);

  try {
    if (!isAttached(config.settings)) return local;
    const connection = config.settings.controlPlane;
    if (connection === undefined) return local;

    const state = readControlPlaneCredentialState(config.settingsDir, connection);
    if (!state.usable) return local;

    const client = createRemoteClient({
      endpoint: connection.endpoint,
      apiKey: state.credential.apiKey,
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
        report: (snapshot) =>
          forward.run(() => client.reportStorePosture(snapshot)).then(() => undefined),
        store: postureStore,
        readStore: () => readStorePosture(config.dbPath),
        hostname: () => hostname(),
        now: () => Date.now(),
        // The reporting build's identity, when the caller knows it (the plugin
        // adapters do; an embedder or a test may not). Composed with the SAME
        // policy store the sync child writes, so the block names the bundle
        // actually in force. Key omitted rather than set undefined — the
        // reporter keys on presence.
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
