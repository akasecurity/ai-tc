import { readFileSync } from 'node:fs';

import { type PluginBuildInfo, readManifestBuild } from '@akasecurity/plugin-runtime';

/** The npm package this plugin ships as — the identity its posture reports carry. */
export const PLUGIN_PACKAGE = '@akasecurity/ai-tc-copilot';

// The manifest sits one level above this module in BOTH layouts it runs from:
// the installed plugin executes scripts/<entry>.js beside the root plugin.json
// (Copilot reads a flat root manifest, as Antigravity does), and the repo runs
// src/ beside it too, so one relative path resolves the installed manifest from
// either. Resolved against import.meta.url, never the process cwd — hooks and
// detached children run from arbitrary directories.
const MANIFEST_URL = new URL('../plugin.json', import.meta.url);

/**
 * The argv index the hook command passes the plugin manifest path at.
 *
 * It is 3 here and 2 in every sibling plugin, and the difference is not
 * cosmetic. Seven of this host's eight recorded payloads carry no event name
 * (see `test/fixtures/cli/README.md`), so the event token rides `argv[2]` and
 * the manifest is displaced one place right. Copy a sibling's hook without
 * moving it and `harnessVersionFromArgv` reads the EVENT NAME as a manifest
 * path, fails the `readFileSync`, and silently records no harness version —
 * an omission nothing else in the tree would report.
 */
export const MANIFEST_ARGV_INDEX = 3;

/**
 * The build identity every attached posture report carries (see
 * `resolveDataGateway`'s `meta.pluginBuild`). One fs read per process — the
 * shared reader memoises per manifest URL — and best-effort: an unreadable or
 * versionless manifest yields undefined, and the report goes out without a
 * plugin block rather than failing anything.
 */
export function pluginBuild(): PluginBuildInfo | undefined {
  return readManifestBuild(MANIFEST_URL, PLUGIN_PACKAGE);
}

/**
 * The plugin's own version, read from the manifest path the hook command passes
 * on argv. Best-effort: an unreadable or old manifest just omits the version,
 * and the harness dimension still resolves on the tool id.
 *
 * `argv` is a parameter so the offset is drivable from a test on any host; the
 * default is the real one.
 */
export function harnessVersionFromArgv(argv: readonly string[] = process.argv): string | undefined {
  const manifestPath = argv[MANIFEST_ARGV_INDEX];
  if (!manifestPath) return undefined;
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { version?: unknown };
    return typeof manifest.version === 'string' ? manifest.version : undefined;
  } catch {
    return undefined;
  }
}
