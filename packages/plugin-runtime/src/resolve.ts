import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';

import { StandaloneDataGateway } from './standalone-gateway.ts';

/**
 * Build a data gateway from the plugin config. The local-first surface always
 * records into the on-disk SQLite store via the StandaloneDataGateway.
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
 */
export type DataGatewayFactory = (
  config: PluginConfig,
  meta?: { recordedBy?: string },
) => DataGateway;

export const standaloneGatewayFactory: DataGatewayFactory = (config, meta) =>
  new StandaloneDataGateway(config.dataDir, bundledDetections(), meta);

let defaultGatewayFactory: DataGatewayFactory = standaloneGatewayFactory;

/**
 * Set the factory `resolveDataGateway` falls back to for the rest of this
 * process. Passing nothing restores the standalone default, which is what a
 * test's teardown does — and the reason the parameter is optional.
 */
export function setDefaultGatewayFactory(factory?: DataGatewayFactory): void {
  defaultGatewayFactory = factory ?? standaloneGatewayFactory;
}

export function resolveDataGateway(
  config: PluginConfig,
  meta?: { recordedBy?: string },
  gatewayFactory: DataGatewayFactory = defaultGatewayFactory,
): DataGateway {
  return gatewayFactory(config, meta);
}
