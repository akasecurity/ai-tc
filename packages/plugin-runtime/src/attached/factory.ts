import { hostname } from 'node:os';

import { readControlPlaneCredentialState } from '@akasecurity/persistence';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { createRemoteClient } from '@akasecurity/remote';
import { isAttached } from '@akasecurity/schema';

import { StandaloneDataGateway } from '../standalone-gateway.ts';
import { createForwardPolicy } from './forward-policy.ts';
import { AttachedDataGateway } from './gateway.ts';
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
  meta?: { recordedBy?: string },
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

    return new AttachedDataGateway({
      local,
      client,
      readCachedBundle: () => store.read().then((cached) => cached?.bundle ?? null),
      forward: createForwardPolicy({ dir: config.dataDir }),
      posture: createPostureReporter({
        report: (snapshot) => client.reportStorePosture(snapshot),
        store: postureStore,
        readStore: () => readStorePosture(config.dbPath),
        hostname: () => hostname(),
        now: () => Date.now(),
      }),
    });
  } catch {
    // A misconfigured attachment degrades to local recording rather than
    // breaking the session. `local` is already built and is exactly what this
    // returns, so no credential reached a client that was not constructed.
    return local;
  }
}
