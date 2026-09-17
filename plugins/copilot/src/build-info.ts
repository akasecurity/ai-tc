import { pathToFileURL } from 'node:url';

import { type PluginBuildInfo, readManifestBuild } from '@akasecurity/plugin-runtime';

import { PLUGIN_PACKAGE } from './identity.ts';

export { PLUGIN_PACKAGE };

// The manifest sits one level above this module in BOTH layouts it runs from:
// the installed plugin executes scripts/<entry>.js beside plugin.json, and the
// repo runs src/ beside it too, so one relative path resolves the installed
// manifest from either. Copilot reads a FLAT root manifest (like Antigravity,
// unlike Claude Code's `.claude-plugin/` and Codex's `.codex-plugin/`), so the
// path carries no dotted directory segment. Resolved against import.meta.url,
// never the process cwd — hooks and detached children run from arbitrary
// directories.
const MANIFEST_URL = new URL('../plugin.json', import.meta.url);

/**
 * The plugin's own version, read from the manifest path the hook command
 * passes on argv.
 *
 * **THE OFFSET IS 3, NOT 2, AND THAT IS THIS HOST'S WHOLE DIFFERENCE.** The
 * Claude Code, Codex and Antigravity siblings put their manifest path in
 * `argv[2]`. Here `argv[2]` is the EVENT NAME (see `./hooks/event-name.ts`:
 * seven of the eight recorded payloads carry no event name at all, so argv is
 * the only channel that has one), which displaces the manifest by one.
 *
 * Copying a sibling's reader without moving the offset is the defect to watch
 * for, and it is silent in the worst way: `argv[2]` would hold `'preToolUse'`,
 * `readFileSync` would throw ENOENT, the catch would swallow it, and the
 * version would simply be absent from every inventory row — a missing field,
 * not an error. `test/build-info.test.ts` pins the offset directly for that
 * reason.
 *
 * Best-effort throughout: an unreadable, absent or versionless manifest yields
 * `undefined` and the harness dimension still resolves on `tool` alone.
 *
 * `argv` is a parameter so this unit-tests without a hook process; every
 * shipped caller passes `process.argv`.
 */
export function harnessVersionFromArgv(argv: readonly string[] = process.argv): string | undefined {
  const manifestPath = argv[3];
  if (manifestPath === undefined || manifestPath === '') return undefined;
  // `pathToFileURL`, not a `file://` template: the template mangles a path
  // carrying a space and produces an invalid URL for a Windows drive letter,
  // and both failures land in `readManifestBuild`'s catch as a silently
  // missing version rather than as an error anyone sees.
  return readManifestBuild(pathToFileURL(manifestPath), PLUGIN_PACKAGE)?.version;
}

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
