import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';

import type { GatewayMeta } from './attached/factory.ts';
import { resolveGatewayForConfig } from './attached/factory.ts';
import { StandaloneDataGateway } from './standalone-gateway.ts';

/**
 * Build a data gateway from the plugin config. Every surface records into the
 * on-disk SQLite store; a machine whose settings name a control plane, and
 * which holds a credential for that plane, additionally forwards what the
 * organization is entitled to see.
 *
 * The gateway is resolved through a factory so an embedder or a test can
 * substitute its own implementation of `DataGateway` without this package
 * taking on that dependency. There are two seams and they compose:
 *
 *   - the `gatewayFactory` argument is the PER-CALL seam — one call site
 *     resolves differently, everything else is untouched;
 *   - `setDefaultGatewayFactory` is the PER-PROCESS seam, for a caller that
 *     runs before any resolving code and has no argument to thread through it.
 *
 * The argument default is read on every call rather than captured when this
 * module is evaluated, so a setter that runs later still takes effect. The
 * DataGateway interface is the contract both sides share.
 *
 * `meta.recordedBy` (optional) names the calling binary (`plugin@<v>`) so the
 * standalone gateway's inventory recording can stamp the available_packs
 * mirror. Only SessionStart knows the plugin version (the manifest path rides
 * its argv alone), and a new binary generation always starts with a new
 * session, so stamping from there covers every generation change.
 *
 * `meta.pluginBuild` (optional) is the calling artifact's package identity for
 * the attached posture self-report — see the factory's posture wiring. Unlike
 * `recordedBy` it is wanted from EVERY caller that can reach
 * `ensureInventory` on an attached machine (the reconcilers as well as
 * SessionStart): whichever of them wins the hourly throttle sends the report,
 * and a report without the block nulls the control plane's plugin columns.
 */
export type DataGatewayFactory = (config: PluginConfig, meta?: GatewayMeta) => DataGateway;

export const standaloneGatewayFactory: DataGatewayFactory = (config, meta) =>
  new StandaloneDataGateway(config.dataDir, bundledDetections(), meta);

/**
 * The default: read the machine's own configuration and build what it asks for.
 *
 * A standalone machine — every machine that has never attached — gets exactly
 * `standaloneGatewayFactory`'s answer, built the same way from the same
 * arguments. The check that separates them is a `statSync` and a small JSON
 * parse, and it happens once per resolve rather than once per write.
 *
 * `standaloneGatewayFactory` stays exported and stays the reset target for
 * `setDefaultGatewayFactory`: a test that wants the local gateway unconditionally
 * asks for it by name rather than by arranging for a file to be absent.
 */
export const configuredGatewayFactory: DataGatewayFactory = (config, meta) =>
  resolveGatewayForConfig(config, meta);

let defaultGatewayFactory: DataGatewayFactory = configuredGatewayFactory;

/**
 * Set the factory `resolveDataGateway` falls back to for the rest of this
 * process, and return a thunk that puts back whatever was set before.
 *
 * Unwind through the thunk, not through a second no-argument call. The
 * no-argument form resets to the STANDALONE default rather than to the
 * previous factory, so with two registrants — an embedder setting its gateway
 * at process start, then a test or a nested helper substituting over it — a
 * reset discards the embedder's registration and every later
 * `resolveDataGateway` silently opens the on-disk SQLite store instead. The
 * embedder is by definition the caller that ran before any resolving code, so
 * it has no call site left to notice the takeover from. The thunk restores the
 * previous factory, so nested substitutions unwind exactly.
 *
 * Passing nothing still resets to the CONFIGURED default — what the machine's
 * own settings ask for — which is what a top-level test teardown wants, and the
 * reason the parameter is optional. A caller that specifically wants the local
 * gateway regardless of configuration passes `standaloneGatewayFactory`.
 */
export function setDefaultGatewayFactory(factory?: DataGatewayFactory): () => void {
  const previous = defaultGatewayFactory;
  defaultGatewayFactory = factory ?? configuredGatewayFactory;
  return () => {
    defaultGatewayFactory = previous;
  };
}

export function resolveDataGateway(
  config: PluginConfig,
  meta?: GatewayMeta,
  gatewayFactory: DataGatewayFactory = defaultGatewayFactory,
): DataGateway {
  return gatewayFactory(config, meta);
}
