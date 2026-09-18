import type { ComponentStatus, UpdateReport } from '@akasecurity/schema';
import { RELEASE_CHANNEL } from '@akasecurity/schema';

/**
 * The lines explaining a `latest` that came from a marketplace pin.
 *
 * Only where the pin is BEHIND npm, because that is the only case a reader
 * cannot account for on their own: the row says "up to date" at a version they
 * can see is not the newest published, and without this the output is
 * indistinguishable from a stale report or a failed update. A pin that equals
 * npm's latest explains nothing and is left unsaid.
 *
 * It names the marketplace rather than only the version, because the marketplace
 * is the thing that has to move — and under a marketplace registered at a pinned
 * ref, nothing else ever will.
 */
function pinNotes(report: UpdateReport): string[] {
  const notes: string[] = [];
  for (const s of report.statuses) {
    const pin = s.marketplacePin;
    if (!pin || !pin.npmAhead || s.latest === null || pin.npmLatest === null) continue;
    notes.push(
      `    ${s.name}: the ${pin.marketplace} marketplace pins v${s.latest}. ` +
        `npm has v${pin.npmLatest}, which this machine cannot install until that ` +
        `marketplace moves.`,
    );
  }
  return notes;
}

function statusLabel(s: ComponentStatus): string {
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
