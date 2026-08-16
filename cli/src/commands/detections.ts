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
//
// `aka detections unquarantine` is the undo for the one verdict the machine
// reaches on its own: a pulled/custom regex rule that blew the ReDoS timing
// budget, or had to be terminated mid-scan, is cached as quarantined and
// dropped from every later scan. That verdict is a wall-clock judgement, so a
// loaded or slow machine can reach it about a rule that is in fact fine —
// without this there is no way back short of deleting the store.
const SUBCOMMANDS = ['update', 'unquarantine'] as const;
type Subcommand = (typeof SUBCOMMANDS)[number] | 'list';

export async function runDetections(argv: string[]): Promise<void> {
  // Parse first, THEN read the subcommand from the positionals — a subcommand
  // must be recognized wherever it lands (e.g. after --home <dir>), not only at
  // argv[0], or a flag-first invocation would silently run the list instead.
  const { values, positionals } = parseArgs({
    args: argv,
    options: { ...HOME_OPTION, all: { type: 'boolean' } },
    allowPositionals: true,
  });
  const named = SUBCOMMANDS.find((s) => s === positionals[0]);
  const sub: Subcommand = named ?? 'list';
  if (sub === 'list' && positionals.length > 0) {
    process.stderr.write(
      `aka detections: unknown subcommand '${positionals[0] ?? ''}' ` +
        `(expected one of: ${SUBCOMMANDS.join(', ')})\n`,
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
    } else if (sub === 'unquarantine') {
      runUnquarantineSub(db);
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
  // Surfaced here because the only other place it is ever mentioned is a line
  // on a hook's stderr, which the harness normally swallows. A quarantined rule
  // is a rule that silently stopped detecting.
  const quarantined = db.ruleProbeCache.countQuarantined();
  if (quarantined > 0) {
    out.write(
      `\n⚠ ${String(quarantined)} rule(s) quarantined for exceeding the ReDoS timing budget — ` +
        `they are excluded from every scan.\n` +
        `  aka detections unquarantine          # forget the verdicts and measure them again\n`,
    );
  }
  // The scan path discards the WHOLE installed snapshot when any rule under an
  // enabled pack fails validation, so one bad entry costs every custom rule and
  // every per-detection action — a far larger loss than the entry itself. The
  // plugin says so on a hook's stderr; this is the surface that survives, and
  // the one its line points at.
  //
  // Unlike a quarantine verdict this caches nothing: the entries are re-read on
  // every scan, so there is no stored verdict to clear and no command offered to
  // clear one. The fix is to repair or reinstall the pack.
  const ruleset = db.installedPacks.installedRuleset();
  if (ruleset.invalidRules > 0) {
    out.write(
      `\n⚠ ${String(ruleset.invalidRules)} rule(s) under enabled packs failed validation — ` +
        'scanning falls back to the bundled packs, so no custom rule and no per-detection ' +
        'action is enforced.\n',
    );
    for (const rejected of ruleset.rejectedRules) {
      const named = rejected.ruleId === null ? '' : ` ${rejected.ruleId}`;
      out.write(`  ${rejected.pack}${named} — ${rejected.reason}\n`);
    }
    const undisclosed = ruleset.invalidRules - ruleset.rejectedRules.length;
    if (undisclosed > 0) out.write(`  …and ${String(undisclosed)} more\n`);
    out.write('  Repair or reinstall the pack — the check re-runs on the next scan.\n');
  }
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

// Clears every cached quarantine verdict. Deliberately all-or-nothing: the
// cache is keyed by a content hash of the pattern, not by rule id, so there is
// no per-rule handle a user could name. Forgetting a verdict only costs one
// re-measurement — the rule is measured again the next time it loads, and lands
// straight back in quarantine if it really is catastrophic.
function runUnquarantineSub(db: LocalDatabase): void {
  const { refused, cleared } = db.ruleProbeCache.clearQuarantined();
  // Three outcomes, not two. A refused write and an empty cache both clear zero
  // rows, and collapsing them would print "nothing to clear" at a user whose
  // rules are still quarantined — on the one command in this feature whose
  // whole job is to undo a silent detection gap.
  if (refused) {
    process.stderr.write(
      'aka detections unquarantine: the store refused the write (another process may be ' +
        'holding it). Nothing was cleared — try again.\n',
    );
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    cleared === 0
      ? '✓ No quarantined rules — nothing to clear.\n'
      : `✓ Cleared ${String(cleared)} quarantine verdict(s). Each rule is measured again the ` +
          `next time it loads, and is re-quarantined if it still exceeds the budget.\n`,
  );
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
