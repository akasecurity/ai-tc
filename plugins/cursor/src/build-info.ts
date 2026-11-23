import { type PluginBuildInfo, readManifestBuild } from '@akasecurity/plugin-runtime';

import { PLUGIN_PACKAGE } from './identity.ts';

export { PLUGIN_PACKAGE };

// Cursor reads no plugin manifest of its own, so the package's own
// `package.json` is the manifest: the built scripts sit in `scripts/`, one
// level below it, in the published tarball.
const MANIFEST_URL = new URL('../package.json', import.meta.url);

/** This build's package identity, or undefined when the manifest is unreadable. */
export function pluginBuild(): PluginBuildInfo | undefined {
  return readManifestBuild(MANIFEST_URL, PLUGIN_PACKAGE);
}
