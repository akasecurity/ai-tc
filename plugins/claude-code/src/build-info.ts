import { fileURLToPath } from 'node:url';

import { type PluginBuildInfo, readManifestBuild } from '@akasecurity/plugin-runtime';

/** The npm package this plugin ships as — the identity its posture reports carry. */
export const PLUGIN_PACKAGE = '@akasecurity/ai-tc-claude-code';

// The manifest sits one level above this module in BOTH layouts it runs from:
// the installed plugin executes scripts/<entry>.js beside .claude-plugin/, and
// the repo runs src/ beside it too, so one relative path resolves the
// installed manifest from either. Resolved against import.meta.url, never the
// process cwd — hooks and detached children run from arbitrary directories.
const MANIFEST_URL = new URL('../.claude-plugin/plugin.json', import.meta.url);

/**
 * The directory this plugin runs from — the one holding `.claude-plugin/`, in
 * both layouts MANIFEST_URL covers. Installed from a marketplace, it is the
 * version directory the host unpacked the plugin into, which is how the
 * posture block finds the host's install record for it. Both of this plugin's
 * posture paths pass it — pluginBuild() below and the SessionStart hook's own
 * build literal — so neither reports the installed version as null while the
 * other reports it.
 */
export const INSTALL_ROOT = fileURLToPath(new URL('../', MANIFEST_URL));

/**
 * The build identity every attached posture report carries (see
 * `resolveDataGateway`'s `meta.pluginBuild`). One fs read per process — the
 * shared reader memoises per manifest URL — and best-effort: an unreadable or
 * versionless manifest yields undefined, and the report goes out without a
 * plugin block rather than failing anything.
 */
export function pluginBuild(): PluginBuildInfo | undefined {
  const build = readManifestBuild(MANIFEST_URL, PLUGIN_PACKAGE);
  return build === undefined ? undefined : { ...build, installRoot: INSTALL_ROOT };
}
