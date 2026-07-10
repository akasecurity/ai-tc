import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { AvailablePlugin, ComponentStatus, UpdateReport } from '@akasecurity/schema';

import { runCapture } from './exec.ts';
import { AGENT_PLUGINS, pluginRef } from './registry.ts';
import { isNewer } from './semver.ts';

// Pure update-report gathering: version discovery over npm + the local Claude Code
// ledger, with no @akasecurity/plugin-sdk dependency (so the report logic stays unit-
// testable without dragging in the env-reading config layer). Cache + passive-notice
// persistence lives in ./update-cache.ts. The report DTOs live in
// @akasecurity/schema (zod/updates.ts), shared with the web-ui's Updates page.

// The npm package the global `aka` CLI is published as. `npm view` resolves its
// latest version through the user's own npm configuration — the same toolchain
// that installed it.
export const CLI_PACKAGE = '@akasecurity/cli';

// Injectable seams so gatherReport is testable without touching the network or the
// real ~/.claude ledger.
export interface ReportDeps {
  viewVersion: (pkg: string) => string | null;
  installed: Map<string, string>;
  cliInstalled: string | null;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

// Read the CLI's own version from the nearest package.json named `@akasecurity/cli`,
// walking up from `fromDir` (default: this module's directory). Works bundled
// (dist/cli.js → package root), under tsx in dev (src/lib → cli), and from
// the web-ui's standalone server (which passes its cwd — nested inside the
// published CLI package at <cli-pkg>/web-ui/web-ui). Returns null if not
// found — callers treat an unknown installed version the same as an unknown
// latest: never flag an update (a `0.0.0` fallback would be "older" than every
// real release and nag forever).
export function cliVersion(fromDir?: string): string | null {
  let dir = fromDir ?? dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 6; i++) {
    const p = join(dir, 'package.json');
    if (existsSync(p)) {
      try {
        const raw: unknown = JSON.parse(readFileSync(p, 'utf8'));
        if (isRecord(raw) && raw.name === CLI_PACKAGE && typeof raw.version === 'string') {
          return raw.version;
        }
      } catch {
        // unreadable/!JSON — keep walking up
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

// The `recorded_by` stamp for available_packs mirror writes — which binary
// recorded the detection inventory (`aka-cli@<version>`). Undefined when the
// CLI's own version is unknowable (a dev checkout): better absent than a
// lying constant.
export function cliRecordedBy(): { recordedBy: string } | undefined {
  const version = cliVersion();
  return version === null ? undefined : { recordedBy: `aka-cli@${version}` };
}

// Default location of Claude Code's plugin install ledger.
function installedPluginsPath(claudeHome: string): string {
  return join(claudeHome, 'plugins', 'installed_plugins.json');
}

// Parse ~/.claude/plugins/installed_plugins.json (v2) into a map of
// `<plugin>@<marketplace>` → installed version. Missing/garbage file → empty map.
export function installedPluginVersions(
  claudeHome: string = join(homedir(), '.claude'),
): Map<string, string> {
  const out = new Map<string, string>();
  const path = installedPluginsPath(claudeHome);
  if (!existsSync(path)) return out;
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return out;
  }
  if (!isRecord(raw) || !isRecord(raw.plugins)) return out;
  for (const [ref, records] of Object.entries(raw.plugins)) {
    if (!Array.isArray(records) || records.length === 0) continue;
    // Prefer a `user`-scope record; fall back to the first with a version string.
    const record =
      records.find((r): r is Record<string, unknown> => isRecord(r) && r.scope === 'user') ??
      records.find((r): r is Record<string, unknown> => isRecord(r));
    if (record && typeof record.version === 'string') out.set(ref, record.version);
  }
  return out;
}

// `npm view <pkg> version` — the latest published version, or null on any failure.
export function npmViewVersion(pkg: string): string | null {
  const res = runCapture('npm', ['view', pkg, 'version'], 15_000);
  if (!res.ok || !res.stdout) return null;
  // `npm view` may emit warnings on stderr but the version is the last stdout line.
  const line = res.stdout.split('\n').pop()?.trim();
  return line && /^\d/.test(line) ? line : null;
}

// Build the full update report: the CLI plus every marketplace agent, split into
// installed (with an installed-vs-latest status) and available-but-not-installed.
export function gatherReport(deps: ReportDeps): UpdateReport {
  const cliLatest = deps.viewVersion(CLI_PACKAGE);
  const statuses: ComponentStatus[] = [
    {
      id: 'cli',
      name: 'aka CLI',
      kind: 'cli',
      installed: deps.cliInstalled,
      latest: cliLatest,
      updateAvailable:
        deps.cliInstalled !== null && cliLatest !== null && isNewer(cliLatest, deps.cliInstalled),
    },
  ];
  const availablePlugins: AvailablePlugin[] = [];

  for (const agent of AGENT_PLUGINS) {
    const ref = pluginRef(agent);
    if (!ref || !agent.npmPackage) continue;
    const latest = deps.viewVersion(agent.npmPackage);
    const installed = deps.installed.get(ref) ?? null;
    if (installed === null) {
      availablePlugins.push({ id: agent.id, name: agent.name, latest });
      continue;
    }
    statuses.push({
      id: agent.id,
      name: agent.name,
      kind: 'plugin',
      installed,
      latest,
      updateAvailable: latest !== null && isNewer(latest, installed),
    });
  }
  return { statuses, availablePlugins };
}

// Convenience wrapper that wires the real network + filesystem seams. Used by the
// user-facing `check-updates`/`update` commands and the background refresh.
export function gatherReportLive(): UpdateReport {
  return gatherReport({
    viewVersion: npmViewVersion,
    installed: installedPluginVersions(),
    cliInstalled: cliVersion(),
  });
}
