import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';

import { StandaloneDataGateway } from './standalone-gateway.ts';

/**
 * Build a data gateway from the plugin config. The local-first surface always
 * records into the on-disk SQLite store via the StandaloneDataGateway.
 *
 * `gatewayFactory` is the extension seam: it defaults to the standalone factory,
 * and a downstream build can inject an alternate gateway (e.g. one that
 * records somewhere else) without this package taking on that dependency. The DataGateway
 * interface is the contract both sides share.
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

const standaloneGatewayFactory: DataGatewayFactory = (config, meta) =>
  new StandaloneDataGateway(config.dataDir, bundledDetections(), meta);

export function resolveDataGateway(
  config: PluginConfig,
  meta?: { recordedBy?: string },
  gatewayFactory: DataGatewayFactory = standaloneGatewayFactory,
): DataGateway {
  return gatewayFactory(config, meta);
}
