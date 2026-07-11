import { parseArgs } from 'node:util';

import { cliRecordedBy } from '@akasecurity/local-ops';
import type { LocalDatabase } from '@akasecurity/persistence';
import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, dataDir } from '@akasecurity/plugin-sdk';
import type { DetectionListItem } from '@akasecurity/schema';
import { splitDetectionId } from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';

// `aka detections` — the CLI read surface for the installed detection packs:
// one row per pack with its installed version, rule count, enabled state,
// assigned policy, and whether the running binary ships a newer snapshot.
//
// `aka detections update [<pack>… | --all]` applies those updates MANUALLY —
// nothing else in the system (not `aka init`, not the plugin hooks) ever
// modifies an installed pack, so this subcommand (and its dashboard/plugin
// equivalents) is the only way a pack moves to a new version.
export async function runDetections(argv: string[]): Promise<void> {
  // Parse first, THEN read the subcommand from the positionals — `update` must
  // be recognized wherever it lands (e.g. after --home <dir>), not only at
  // argv[0], or a flag-first invocation would silently run the list instead.
  const { values, positionals } = parseArgs({
    args: argv,
    options: { ...HOME_OPTION, all: { type: 'boolean' } },
    allowPositionals: true,
  });
  const sub = positionals[0] === 'update' ? 'update' : 'list';
  if (sub === 'list' && positionals.length > 0) {
    process.stderr.write(
      `aka detections: unknown subcommand '${positionals[0] ?? ''}' (did you mean \`aka detections update\`?)\n`,
    );
    process.exitCode = 1;
    return;
  }
  const home = homeBase(values.home);

  const db = openLocalDatabase(dataDir(home));
  try {
    // Refresh the available mirror from THIS binary's inventory before reading
    // it — `aka detections` reports freshness relative to the running CLI, so
    // it must not compare against whatever binary happened to record last.
    // recordInventory is signature-gated (steady state: one SELECT) and never
    // modifies an installed pack.
    db.installedPacks.recordInventory(bundledDetections(), cliRecordedBy());
    if (sub === 'update') {
      await runUpdateSub(db, positionals.slice(1), values.all === true);
    } else {
      await runListSub(db);
    }
  } finally {
    db.close();
  }
}

async function runListSub(db: LocalDatabase): Promise<void> {
  const { counts, items } = await db.detections.listDetections({ filter: 'all' });
  const out = process.stdout;
  if (items.length === 0) {
    out.write('No detection packs installed yet — run `aka init` (or any plugin hook) first.\n');
    return;
  }

  out.write(`${renderDetectionsTable(items)}\n`);
  const active = items.filter((i) => i.enabled).length;
  out.write(
    `\n${String(items.length)} pack(s) · ${String(items.reduce((n, i) => n + i.ruleCount, 0))} rule(s) · ${String(active)} enabled\n`,
  );
  if (counts.updates > 0) {
    out.write(
      `\n⬆ ${String(counts.updates)} update(s) available. Updates are manual — apply with:\n` +
        `  aka detections update --all          # update every pack\n` +
        `  aka detections update <pack-id>      # update one pack (e.g. ${items.find((i) => i.latestVersion)?.id ?? 'aka/secrets'})\n`,
    );
  } else {
    out.write('\n✓ All detection packs are up to date with this CLI.\n');
  }
}

async function runUpdateSub(db: LocalDatabase, ids: string[], all: boolean): Promise<void> {
  // Full list to tell "unknown pack" (error) apart from "installed but already
  // current" (fine, exit 0); the updates filter alone conflates the two.
  const { items } = await db.detections.listDetections({ filter: 'all' });
  const byId = new Map(items.map((i) => [i.id, i]));

  let targets: DetectionListItem[];
  if (all) {
    targets = items.filter((i) => i.latestVersion != null);
  } else if (ids.length > 0) {
    targets = [];
    for (const id of ids) {
      // Accept both the full "aka/secrets" slug and the bare "secrets" pack id.
      const match = byId.get(id) ?? items.find((i) => i.packId === id);
      if (!match) {
        process.stderr.write(
          `aka detections: unknown pack '${id}' (see \`aka detections\` for the installed list).\n`,
        );
        process.exitCode = 1;
        return;
      }
      if (match.latestVersion == null) {
        // Already current: report it and continue with the rest — not an error.
        process.stdout.write(`✓ ${match.id}: already up to date (v${match.version})\n`);
        continue;
      }
      targets.push(match);
    }
  } else {
    process.stderr.write(
      'aka detections update: pass one or more pack ids, or --all to update everything.\n',
    );
    process.exitCode = 1;
    return;
  }

  if (targets.length === 0) {
    if (all) process.stdout.write('✓ Nothing to update — all detection packs are current.\n');
    return;
  }

  for (const t of targets) {
    const parts = splitDetectionId(t.id);
    const ok = parts ? db.installedPacks.applyUpdate(parts.namespace, parts.packId) : false;
    process.stdout.write(
      ok
        ? `✓ ${t.id}: ${t.version} → ${t.latestVersion ?? t.version}\n`
        : `✗ ${t.id}: update failed (pack missing or no available snapshot)\n`,
    );
    if (!ok) process.exitCode = 1;
  }
}

// Width-padded plain-text table (same pattern as lib/update-render.ts — no
// table/colour dependency). Exported for the unit test.
export function renderDetectionsTable(items: DetectionListItem[]): string {
  const rows = items.map((i) => ({
    pack: i.id,
    installed: `v${i.version}`,
    latest: i.latestVersion ? `v${i.latestVersion}` : `v${i.version}`,
    rules: String(i.ruleCount),
    enabled: i.enabled ? 'yes' : 'no',
    policy: i.policyId ?? 'monitor',
    status: i.latestVersion ? '⬆ update available' : '✓ up to date',
  }));
  const packW = Math.max(4, ...rows.map((r) => r.pack.length));
  const instW = Math.max(9, ...rows.map((r) => r.installed.length));
  const latW = Math.max(6, ...rows.map((r) => r.latest.length));
  const rulesW = Math.max(5, ...rows.map((r) => r.rules.length));
  const enW = Math.max(7, ...rows.map((r) => r.enabled.length));
  const polW = Math.max(6, ...rows.map((r) => r.policy.length));

  const lines = [
    `  ${'Pack'.padEnd(packW)}  ${'Installed'.padEnd(instW)}  ${'Latest'.padEnd(latW)}  ${'Rules'.padEnd(rulesW)}  ${'Enabled'.padEnd(enW)}  ${'Policy'.padEnd(polW)}  Status`,
  ];
  for (const r of rows) {
    lines.push(
      `  ${r.pack.padEnd(packW)}  ${r.installed.padEnd(instW)}  ${r.latest.padEnd(latW)}  ${r.rules.padEnd(rulesW)}  ${r.enabled.padEnd(enW)}  ${r.policy.padEnd(polW)}  ${r.status}`,
    );
  }
  return lines.join('\n');
}
