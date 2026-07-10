import type { ComponentStatus, UpdateReport } from '@akasecurity/schema';

function statusLabel(s: ComponentStatus): string {
  // Not-installed plugins are reported under availablePlugins, never here — so a null
  // installed in a status row means "couldn't determine version" (the CLI's own
  // package.json walk-up missed), which reads as unknown, not "not installed".
  if (s.installed === null || s.latest === null) return 'unknown';
  return s.updateAvailable ? 'update available' : 'up to date';
}

// Render the installed-vs-latest table plus any not-yet-installed plugins as a
// single block of text. Shared by `aka check-updates` and the preamble of `aka
// update` so both read identically.
export function renderReport(report: UpdateReport): string {
  const rows = report.statuses.map((s) => ({
    name: s.name,
    installed: s.installed ?? '—',
    latest: s.latest ?? 'unknown',
    status: statusLabel(s),
  }));

  const nameW = Math.max(9, ...rows.map((r) => r.name.length));
  const instW = Math.max(9, ...rows.map((r) => r.installed.length));
  const latW = Math.max(6, ...rows.map((r) => r.latest.length));

  const lines: string[] = [];
  lines.push(
    `  ${'Component'.padEnd(nameW)}  ${'Installed'.padEnd(instW)}  ${'Latest'.padEnd(latW)}  Status`,
  );
  for (const r of rows) {
    lines.push(
      `  ${r.name.padEnd(nameW)}  ${r.installed.padEnd(instW)}  ${r.latest.padEnd(latW)}  ${r.status}`,
    );
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
