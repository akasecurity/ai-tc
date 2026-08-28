import { readFileSync } from 'node:fs';

import type { PluginBuildInfo } from '@akasecurity/plugin-runtime';

/** The npm package this plugin ships as — the identity its posture reports carry. */
export const PLUGIN_PACKAGE = '@akasecurity/ai-tc-antigravity';

// The manifest sits one level above this module in BOTH layouts it runs from:
// the installed plugin executes scripts/<entry>.js beside the root plugin.json
// (Antigravity reads its manifest from the plugin root), and the repo runs
// src/ beside it too, so one relative path resolves the installed manifest
// from either. Resolved against import.meta.url, never the process cwd —
// hooks and detached children run from arbitrary directories.
const MANIFEST_URL = new URL('../plugin.json', import.meta.url);

/**
 * The build identity every attached posture report carries (see
 * `resolveDataGateway`'s `meta.pluginBuild`). Best-effort: an unreadable or
 * versionless manifest yields undefined and the report goes out without a
 * plugin block rather than failing anything.
 */
export function pluginBuild(): PluginBuildInfo | undefined {
  try {
    const manifest = JSON.parse(readFileSync(MANIFEST_URL, 'utf8')) as { version?: unknown };
    if (typeof manifest.version !== 'string' || manifest.version.length === 0) return undefined;
    return { package: PLUGIN_PACKAGE, version: manifest.version };
  } catch {
    return undefined;
  }
}
