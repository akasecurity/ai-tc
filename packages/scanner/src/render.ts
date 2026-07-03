// Host-neutral terminal rendering for scan summaries, so every plugin host
// (Claude Code today, Codex/VSCode tomorrow) shows the same report instead of
// each copy-pasting ~120 lines of layout. Pure (data → string), monochrome
// plain text: hosts echo it into transcripts where ANSI is not interpreted, so
// meaning is carried by glyph texture (shade blocks), spacing and labels.
//
// Host-specific concerns stay in the host: wrapping the output in a Markdown
// code fence, and the follow-up hint (a slash-command name) is injected via
// `followUp` rather than hardcoded here.
import { basename, relative } from 'node:path';

import type { MultiRepoScanSummary, WorktreeScanSummary } from './scan.ts';

export interface RenderScanOptions {
  // e.g. 'Run /findings to review details.' — host command names differ.
  followUp?: string;
}

// Severity glyphs: heavier fill = more severe, matching the plugin read
// surfaces' shade grammar. Private copies of the few layout primitives below —
// small enough that sharing a package with the hosts' wider layout kits isn't
// worth the dependency edge.
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;
const SEVERITY_GLYPH: Record<string, string> = {
  critical: '█',
  high: '▓',
  medium: '▒',
  low: '░',
};

function padEnd(text: string, width: number): string {
  const pad = width - text.length;
  return pad > 0 ? text + ' '.repeat(pad) : text;
}

function indent(text: string, spaces = 2): string {
  const pad = ' '.repeat(spaces);
  return text
    .split('\n')
    .map((line) => pad + line)
    .join('\n');
}

// Left-aligned column table with UPPERCASE headers and a per-column rule.
function table(headers: string[], rows: string[][], gap = 3): string {
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)));
  const sep = ' '.repeat(gap);
  const fmt = (cells: string[]): string =>
    cells.map((cell, i) => padEnd(cell, widths[i] ?? 0)).join(sep);
  const ruleLine = widths.map((w) => '─'.repeat(w)).join(sep);
  return [fmt(headers.map((h) => h.toUpperCase())), ruleLine, ...rows.map(fmt)].join('\n');
}

function metaBlock(rows: [string, string][]): string {
  const labelWidth = Math.max(...rows.map(([l]) => l.length));
  return rows.map(([l, v]) => `  ${padEnd(l, labelWidth)}  ${v}`).join('\n');
}

function findingsLabel(total: number, gitignored: number): string {
  if (gitignored === 0) return String(total);
  return `${String(total)} (${String(gitignored)} in .gitignore'd files — informational)`;
}

function severitySection(bySeverity: Record<string, number>): string {
  const rows: string[][] = SEVERITY_ORDER.filter((s) => (bySeverity[s] ?? 0) > 0).map((s) => [
    `${SEVERITY_GLYPH[s] ?? ''} ${s}`,
    String(bySeverity[s]),
  ]);
  return rows.length > 0 ? ['', indent(table(['SEVERITY', 'COUNT'], rows))].join('\n') : '';
}

function followUpSection(opts: RenderScanOptions): string[] {
  return opts.followUp !== undefined ? ['', `  ${opts.followUp}`] : [];
}

export function renderWorktreeSummary(
  summary: WorktreeScanSummary,
  opts: RenderScanOptions = {},
): string {
  const rootLabel = relative(process.cwd(), summary.rootDir) || '.';
  const meta = metaBlock([
    ['Root', rootLabel],
    ['Scanned', `${String(summary.scanned)} files`],
    ['Skipped', `${String(summary.skipped)} (already recorded)`],
    ['Findings', findingsLabel(summary.findings, summary.gitignoredFindings)],
  ]);

  if (summary.findings === 0) {
    return ['✓ Worktree scan complete', '', meta, '', '  No code security issues detected.'].join(
      '\n',
    );
  }

  const ruleRows: string[][] = Object.entries(summary.byRule)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([ruleId, count]) => [ruleId, String(count)]);
  const ruleSection =
    ruleRows.length > 0 ? ['', indent(table(['RULE', 'COUNT'], ruleRows))].join('\n') : '';

  return [
    '✓ Worktree scan complete',
    '',
    meta,
    severitySection(summary.bySeverity),
    ruleSection,
    ...followUpSection(opts),
  ].join('\n');
}

export function renderMultiRepoSummary(
  summary: MultiRepoScanSummary,
  opts: RenderScanOptions = {},
): string {
  const meta = metaBlock([
    ['Repositories', String(summary.repos.length)],
    ['Scanned', `${String(summary.totalScanned)} files`],
    ['Skipped', `${String(summary.totalSkipped)} (already recorded)`],
    ['Findings', findingsLabel(summary.totalFindings, summary.totalGitignoredFindings)],
  ]);

  if (summary.repos.length === 0) {
    return ['✓ Multi-repo scan complete', '', meta, '', '  No repositories found.'].join('\n');
  }

  if (summary.totalFindings === 0) {
    return ['✓ Multi-repo scan complete', '', meta, '', '  No code security issues detected.'].join(
      '\n',
    );
  }

  const repoRows: string[][] = summary.repos
    .filter((r) => r.summary.scanned > 0 || r.summary.findings > 0)
    .map((r) => [basename(r.rootDir), String(r.summary.scanned), String(r.summary.findings)]);
  const repoSection =
    repoRows.length > 0
      ? ['', indent(table(['REPO', 'SCANNED', 'FINDINGS'], repoRows))].join('\n')
      : '';

  return [
    '✓ Multi-repo scan complete',
    '',
    meta,
    severitySection(summary.bySeverity),
    repoSection,
    ...followUpSection(opts),
  ].join('\n');
}
