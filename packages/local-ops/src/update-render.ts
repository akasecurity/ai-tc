import type { ComponentStatus, UpdateReport } from '@akasecurity/schema';
import {
  MANAGED_PLUGIN_ADVICE,
  managedPluginNoteParts,
  RELEASE_CHANNEL,
} from '@akasecurity/schema';

/**
 * The lines explaining a `latest` that came from a marketplace pin.
 *
 * Two cases, and each explains something a reader cannot see on their own.
 *
 * A RANGE pin (`range` set) is never orderable, so it gets a note regardless
 * of `npmAhead` — which is always false for one, since there is no single pin
 * version to compare npm against. Without this the row's "Latest" column
 * shows npm's own answer beside a status this machine will never reach that
 * way, and nothing says the version came from npm rather than from what the
 * host will actually resolve the range to.
 *
 * An EXACT pin gets a note only where it is BEHIND npm, because that is the
 * only case a reader cannot account for on their own: the row says "up to
 * date" at a version they can see is not the newest published, and without
 * this the output is indistinguishable from a stale report or a failed
 * update. A pin that equals npm's latest explains nothing and is left unsaid.
 *
 * Both name the marketplace rather than only the version, because the
 * marketplace is the thing that has to move — and under a marketplace
 * registered at a pinned ref, nothing else ever will.
 */
function pinNotes(report: UpdateReport): string[] {
  const notes: string[] = [];
  for (const s of report.statuses) {
    const pin = s.marketplacePin;
    // A managed row's note already says who decides its version. A pin note
    // naming a marketplace "that has to move" would hand the reader a job that
    // is their organization's.
    if (!pin || s.managedInstall) continue;
    if (pin.range !== undefined) {
      const npmPart = pin.npmLatest !== null ? ` npm has v${pin.npmLatest}.` : '';
      notes.push(
        `    ${s.name}: the ${pin.marketplace} marketplace pins ${pin.range}, which the host ` +
          `resolves within — not a single version this report can compare.${npmPart}`,
      );
      continue;
    }
    if (!pin.npmAhead || s.latest === null || pin.npmLatest === null) continue;
    notes.push(
      `    ${s.name}: the ${pin.marketplace} marketplace pins v${s.latest}. ` +
        `npm has v${pin.npmLatest}, which this machine cannot install until that ` +
        `marketplace moves.`,
    );
  }
  return notes;
}

/**
 * The lines explaining a row an organization's managed settings installed.
 *
 * Every such row gets one, pending or not, because the table alone cannot say
 * the one thing a reader needs: that `aka update` will not touch it, and what
 * will. The ref goes beside the name because it is the organization's release
 * this machine follows, which is what someone asking their IT team would quote.
 */
function managedNotes(report: UpdateReport): string[] {
  const notes: string[] = [];
  for (const s of report.statuses) {
    if (!s.managedInstall) continue;
    const { ref, lead } = managedPluginNoteParts(s);
    notes.push(
      `    ${s.name}${ref}: ${lead}${MANAGED_PLUGIN_ADVICE} \`aka update\` leaves it alone.`,
    );
  }
  return notes;
}

function statusLabel(s: ComponentStatus): string {
  // First, because a managed row is never "update available" and its target
  // can be unknown without the row being unknown: the version it runs is the
  // organization's call, and saying so is the whole answer.
  if (s.managedInstall) {
    // Either end unknown means there is no comparison to state — including a
    // managed record that names no version, which must not read as current.
    if (s.installed === null || s.latest === null) return 'managed';
    return s.managedInstall.pending ? 'managed — update pending' : 'managed — up to date';
  }
  // Not-installed plugins are reported under availablePlugins, never here — so a null
  // installed in a status row means "couldn't determine version" (the CLI's own
  // package.json walk-up missed), which reads as unknown, not "not installed".
  if (s.installed === null || s.latest === null) return 'unknown';
  return s.updateAvailable ? 'update available' : 'up to date';
}

/**
 * The channel to SHOW for a row, empty when there is nothing worth showing.
 *
 * Stable and absent read alike, and both render as nothing: a column repeating
 * `stable` on every row of every default machine is noise that pushes the
 * status off the width of a terminal, while a row on another channel is the one
 * case where the version alone does not explain what the machine is following.
 */
function channelCell(s: ComponentStatus): string {
  return s.channel === undefined || s.channel === RELEASE_CHANNEL.Stable ? '' : s.channel;
}

// Render the installed-vs-latest table plus any not-yet-installed plugins as a
// single block of text. Shared by `aka check-updates` and the preamble of `aka
// update` so both read identically.
export function renderReport(report: UpdateReport): string {
  const rows = report.statuses.map((s) => ({
    name: s.name,
    installed: s.installed ?? '—',
    latest: s.latest ?? 'unknown',
    channel: channelCell(s),
    status: statusLabel(s),
  }));

  const nameW = Math.max(9, ...rows.map((r) => r.name.length));
  const instW = Math.max(9, ...rows.map((r) => r.installed.length));
  const latW = Math.max(6, ...rows.map((r) => r.latest.length));
  // The column appears only when some row has something to put in it, so the
  // header of a default report is byte-identical to what it has always been.
  const chanW = rows.some((r) => r.channel !== '')
    ? Math.max(7, ...rows.map((r) => r.channel.length))
    : 0;
  const chanCol = (value: string): string => (chanW === 0 ? '' : `${value.padEnd(chanW)}  `);

  const lines: string[] = [];
  lines.push(
    `  ${'Component'.padEnd(nameW)}  ${'Installed'.padEnd(instW)}  ${'Latest'.padEnd(latW)}  ${chanCol('Channel')}Status`,
  );
  for (const r of rows) {
    lines.push(
      `  ${r.name.padEnd(nameW)}  ${r.installed.padEnd(instW)}  ${r.latest.padEnd(latW)}  ${chanCol(r.channel)}${r.status}`,
    );
  }

  const notes = pinNotes(report);
  if (notes.length > 0) {
    lines.push('');
    lines.push('  Pinned by a marketplace:');
    lines.push(...notes);
  }

  const managed = managedNotes(report);
  if (managed.length > 0) {
    lines.push('');
    lines.push('  Managed by your organization:');
    lines.push(...managed);
  }

  if (report.availablePlugins.length > 0) {
    lines.push('');
    lines.push('  Available plugins (not installed):');
    for (const p of report.availablePlugins) {
      const version = p.latest ? ` v${p.latest}` : '';
      lines.push(`    ${p.name} (${p.id})${version} — install: aka plugins install ${p.id}`);
    }
  }

  return lines.join('\n');
}

// Which statuses actually have an update to apply (installed, latest known, ahead).
export function outdated(report: UpdateReport): ComponentStatus[] {
  return report.statuses.filter((s) => s.updateAvailable);
}

/**
 * The closing line when `aka update` has nothing to apply.
 *
 * "Everything is up to date" is false on a machine whose organization has an
 * update on the way: the managed row is behind, it is just not this command's
 * to apply. Shared by `aka check-updates` and `aka update` so both say the
 * same thing about the same report.
 */
export function nothingToApplyLine(report: UpdateReport): string {
  return report.statuses.some((s) => s.managedInstall?.pending === true)
    ? "Nothing for `aka update` to apply — your organization's pending update arrives " +
        'through Claude Code itself.'
    : 'Everything is up to date.';
}

/**
 * Why an update to a managed install was refused, and what does apply one.
 * The CLI prints it for an explicit target, and the shared apply path returns
 * it to every caller, the dashboard included.
 */
export function managedUpdateRefusal(name: string): string {
  return `${name} is managed by your organization, so nothing was run. ${MANAGED_PLUGIN_ADVICE}`;
}

/**
 * Why an install over a managed one was refused. The plugin is already on the
 * machine, so the answer is that it is there and how it moves, not that an
 * update was refused. `aka plugins install` prints it, and the shared apply
 * path returns it to the dashboard's Install action.
 */
export function managedInstallRefusal(name: string): string {
  return (
    `${name} is managed by your organization and is already installed, so nothing was run. ` +
    MANAGED_PLUGIN_ADVICE
  );
}
