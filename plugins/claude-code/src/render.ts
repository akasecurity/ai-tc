// Pure renderers for the read surfaces: plain data from the data gateway → a
// formatted, monochrome string. Kept free of I/O so they unit-test without a DB
// and a future interactive TUI can reuse them; query.ts owns the gateway + stdout.
//
// No color anywhere — the surfaces are echoed verbatim into the Claude Code
// transcript, which doesn't render ANSI. Severity / intensity is carried by the
// shade glyphs from present.ts (█ ▓ ▒ ░), so every screen reads in plain text.
import type {
  DataGateway,
  DayActivity,
  FindingView,
  HealthSummary,
  SessionTokenReport,
} from '@akasecurity/plugin-sdk';
import { aggregateTokenUsage, formatCostTotal, formatUsd } from '@akasecurity/plugin-sdk';
import type { DetectionException, DetectionListItem } from '@akasecurity/schema';
import { DetectionCategory, toApiAction } from '@akasecurity/schema';

import {
  bar,
  defList,
  indent,
  padEnd,
  padStart,
  paint,
  SHADE,
  stackedBar,
  table,
  wrapText,
} from './present.ts';

const SEVERITY_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

// Severity → shade glyph: heavier fill = more severe (critical solid, low light),
// so the severity column reads as texture with no color. The same four glyphs
// carry intensity on the /health chart and the unreviewed tallies.
const SEVERITY_GLYPH: Record<string, string> = {
  critical: SHADE.full,
  high: SHADE.dark,
  medium: SHADE.medium,
  low: SHADE.light,
};

function severityGlyph(severity: string): string {
  return SEVERITY_GLYPH[severity] ?? SHADE.light;
}

// Plain-language next step per detection category, shown by `/recommend`.
const ADVICE: Record<string, string> = {
  secret:
    'Rotate the exposed credentials and move them out of prompts (secrets manager / env vars).',
  pii: 'Remove or mask personal data before it reaches the model.',
  financial: 'Strip card and account numbers; share only non-sensitive references.',
  phi: 'Remove protected health information — it should never reach an external model.',
  code_context: 'Confirm this proprietary code context is safe to share.',
  code_flaw:
    'Review the flagged pattern and apply the secure alternative (parameterized queries, safe deserializers, etc.).',
  custom: 'Review against your organization’s custom policy.',
};

// "2026-06-19T11:14:53.000Z" → "06-19 11:14" (compact, table-friendly). A
// finding missing its timestamp renders a placeholder rather than a blank cell
// so the table doesn't read as broken.
function shortTime(iso: string): string {
  if (!iso) return '—';
  return iso.length >= 16 ? `${iso.slice(5, 10)} ${iso.slice(11, 16)}` : iso;
}

function empty(message: string): string {
  return message;
}

// ActionTaken (the DB enum: warn|redact|block|allow|log) -> the user-facing
// palette label the wizard uses (monitor|warn|redact|block|allow). Only 'log'
// differs (-> 'monitor'); everything else is identity. Kept local to the
// render surface so the DB vocabulary never leaks into the first-run screen.
const ACTION_LABEL: Record<string, string> = {
  log: 'monitor',
  warn: 'warn',
  redact: 'redact',
  block: 'block',
  allow: 'allow',
};

// Canonical category order for the posture card, from the schema enum. Rows
// come out of the store in DB order; rendering in this fixed order keeps the
// card stable regardless of how the caller read them. An unknown category (a
// custom rule's) sorts after the known ones, in its incoming order.
const CATEGORY_ORDER: readonly string[] = DetectionCategory.options;
function categoryRank(category: string): number {
  const i = CATEGORY_ORDER.indexOf(category);
  return i === -1 ? CATEGORY_ORDER.length : i;
}

// Compact, aligned per-category posture block for the first-run screen: one
// row per category, its stored action translated to the palette label. Rows
// are rendered in the canonical category order above so the card is stable.
// Pure (no I/O) so it unit-tests without a DB; the caller (firstrun.ts)
// supplies rows read from the policies store.
export function renderPosture(rows: { category: string; action: string }[]): string {
  const width = Math.max(0, ...rows.map((r) => r.category.length));
  return [...rows]
    .sort((a, b) => categoryRank(a.category) - categoryRank(b.category))
    .map((r) => `  ${r.category.padEnd(width)}  ${ACTION_LABEL[r.action] ?? r.action}`)
    .join('\n');
}

const RULE_WIDTH = 64;

// The setup-intro "card" the /aka:setup wizard shows first.
// Factual fields (version, repository, publisher) are read from the plugin
// manifest by the intro script; the descriptive copy (name, tagline, adds) is
// product wording the script supplies. Pure here so it renders without any I/O.
export interface PluginMeta {
  name: string;
  tagline: string;
  repository: string;
  version: string;
  publisher: string;
  adds: string;
}

export function renderSetupIntro(meta: PluginMeta): string {
  const heading = `● Found ${meta.name} — ${meta.tagline}`;

  const details = defList([
    ['Repository', meta.repository],
    ['Version', `${meta.version} · ${meta.publisher}`],
    ['Adds', meta.adds],
  ]);

  const ask = "Before installing I'll ask two quick questions to tailor the setup.";

  return [heading, '', indent(details), '', indent(ask)].join('\n');
}

// Derived posture score (0–100). HEURISTIC — we don't store a posture score, so
// this blends what we actually have: category coverage (how much sensitive-data
// is under an enabled policy) and the share of findings that were acted on
// (block/redact/warn) rather than let through. Centralized so the /health and
// first-run screens agree, and so it can be swapped for the product's intended
// scoring model in one place.
export function healthScore(summary: HealthSummary): number {
  const handled = summary.byAction.block + summary.byAction.redact + summary.byAction.warn;
  const handledRatio = summary.findings === 0 ? 1 : handled / summary.findings;
  return Math.round(100 * (0.6 * summary.coverage + 0.4 * handledRatio));
}

// The "First run" completion screen. Commands,
// posture, findings and recommendations are real; `health` is the derived score
// above. The host's input box and window chrome are not the plugin's to draw.
export interface FirstRunSummary {
  commands: string[];
  // Per-category posture block (renderPosture's output) — the wizard's
  // per-category policy read, one row per category. Optional/omittable: the
  // read lives inside firstrun's fail-open try/catch, so a store that can't
  // be read yet just hides the section rather than breaking the card.
  posture?: string;
  health: number;
  findings: number;
  recommendations: number;
  // Highest-severity findings from the first scan, ranked + capped by topFindings.
  // Omitted (or empty) on a clean scan — the section is hidden then.
  topFindings?: FindingView[];
}

// Rank findings for the install card's "Top findings" list: most severe first,
// then most recent within a severity, capped to `limit`. Pure so the first-run
// script and a future TUI rank identically and it unit-tests without a DB.
export function topFindings(findings: FindingView[], limit = 10): FindingView[] {
  return [...findings]
    .sort((a, b) => {
      const sev = (SEVERITY_WEIGHT[b.severity] ?? 0) - (SEVERITY_WEIGHT[a.severity] ?? 0);
      return sev !== 0 ? sev : b.occurredAt.localeCompare(a.occurredAt);
    })
    .slice(0, limit);
}

export function renderFirstRun(s: FirstRunSummary): string {
  const heading = '✓ AKA Security installed';

  const details = defList([['Commands', s.commands.join(' · ')]]);

  const stats = `Health ${String(s.health)}/100   Findings ${String(s.findings)}   Recommendations ${String(s.recommendations)}`;

  const lines = [heading, '', indent(details)];

  // Per-category posture — hidden when unreadable (fail-open upstream leaves
  // it undefined/empty) so the card degrades gracefully instead of showing an
  // empty section.
  if (s.posture !== undefined && s.posture.length > 0) {
    lines.push('', indent('Posture'), '', indent(s.posture));
  }

  lines.push(
    '',
    indent('─'.repeat(RULE_WIDTH)),
    '',
    indent('First scan complete'),
    '',
    indent(stats),
  );

  // Top findings — a compact, severity-ranked glance at what the first scan
  // caught. Hidden on a clean scan so the card stays a tidy success state.
  const top = s.topFindings ?? [];
  if (top.length > 0) {
    const rows = top.map((f) => [
      `${severityGlyph(f.severity)} ${f.severity}`,
      f.category,
      f.ruleId,
      toApiAction(f.actionTaken),
      f.maskedMatch,
    ]);
    lines.push(
      '',
      indent(`Top findings (${String(top.length)})`),
      '',
      indent(
        table(['Severity', 'Category', 'Rule', 'Action', 'Match'], rows, {
          gap: 4,
          rowSep: true,
        }),
      ),
    );
  }

  lines.push('', indent('Opening your health dashboard… run /health anytime'));
  return lines.join('\n');
}

// `severity`, when set, is the active `--severity` filter — it only tailors the
// heading and the empty-state copy; the caller has already narrowed `findings`.
export function renderFindings(
  findings: FindingView[],
  status: FindingStatus,
  severity?: string,
): string {
  if (findings.length === 0) {
    return empty(
      severity !== undefined
        ? `No ${severity} findings recorded yet.`
        : 'No findings recorded yet — AKA scans prompts, file edits, and tool output as you work.',
    );
  }
  const rows = findings.map((f) => [
    shortTime(f.occurredAt),
    `${severityGlyph(f.severity)} ${f.severity}`,
    f.category,
    f.ruleId,
    toApiAction(f.actionTaken),
    f.maskedMatch,
  ]);
  const heading =
    severity !== undefined
      ? `● Recent ${severity} findings (${String(findings.length)})`
      : `● Recent findings (${String(findings.length)})`;
  return [
    heading,
    '',
    indent(
      table(['Time', 'Severity', 'Category', 'Rule', 'Action', 'Match'], rows, {
        gap: 4,
        rowSep: true,
      }),
    ),
    '',
    indent('Filter by level with --severity <critical|high|medium|low>.'),
    '',
    indent(renderStatusBar(status)),
  ].join('\n');
}

// The /health screen (the marquee dashboard). A row of score gauges, a summary
// line, the 7-day detections chart, and a status footer. Pure — the caller builds
// the report (see buildHealthReport) so this stays I/O-free and testable.
export interface HealthGauge {
  label: string;
  score: number; // 0–100
  note: string; // trailing detail, e.g. "3/4 acted on"
  outOf100?: boolean; // Overall renders "/ 100"
}

export interface HealthDay {
  label: string; // "Mon"
  total: number; // findings detected that day
  redacted: number;
  warned: number;
  blocked: number;
}

export interface HealthReport {
  title: string;
  gauges: HealthGauge[];
  openFindings: number;
  scanCoverage: number; // 0..1
  week: HealthDay[];
  weekFindings: number; // sum of the window's per-day totals
  recommendCount: number;
  unreviewed: { critical: number; high: number; medium: number; low: number };
  score: number; // for the footer "health NN/100"
}

const GAUGE_LABEL_W = 14;
const GAUGE_BAR_W = 18;
const WEEK_LABEL_W = 5;
const WEEK_BAR_W = 44;

function renderGauge(g: HealthGauge): string {
  const fill = bar(g.score, 100, GAUGE_BAR_W);
  const score = padStart(String(g.score), 3);
  const outOf = g.outOf100 === true ? '/ 100' : '     ';
  return `${padEnd(g.label, GAUGE_LABEL_W)}  ${fill}  ${score} ${outOf}   ${g.note}`;
}

// The persistent status line shared by /findings, /health and /recommend.
export interface FindingStatus {
  score: number;
  unreviewed: { critical: number; high: number; medium: number; low: number };
  openFindings: number;
}

// `color` is opt-in and honored only by the status line (the one ANSI-capable
// surface). The transcript footers on /findings, /health and /recommend call
// this with no options and stay monochrome, since ANSI doesn't render there.
function renderStatusBar(s: FindingStatus, opts: { color?: boolean } = {}): string {
  const u = s.unreviewed;
  if (opts.color !== true) {
    // Monochrome (transcript footers): severity carried by shade-glyph texture,
    // never hue, since these surfaces print as plain text in the transcript.
    const unreviewed =
      `unreviewed ${SHADE.full}${String(u.critical)} ${SHADE.dark}${String(u.high)} ` +
      `${SHADE.medium}${String(u.medium)} ${SHADE.light}${String(u.low)}`;
    return `▸▸ AKA   health ${String(s.score)}/100   ${unreviewed}   ⚑ ${String(s.openFindings)} open findings`;
  }

  // Status line: ANSI colour. Severity is one square glyph tinted per level, bar
  // separators divide the sections, the health dot reflects the score, and the
  // flag goes red when findings are open (plain grey when the slate is clean).
  const sep = ` ${paint.dim('│')} `;
  const sq = '■';
  const dot = s.score >= 80 ? paint.ok('●') : s.score >= 50 ? paint.high('●') : paint.critical('●');
  const score = `${dot} health ${paint.bold(String(s.score))}${paint.dim('/100')}`;
  const tally =
    `${paint.dim('unreviewed')} ` +
    `${paint.critical(sq)}${String(u.critical)} ${paint.high(sq)}${String(u.high)} ` +
    `${paint.medium(sq)}${String(u.medium)} ${paint.low(sq)}${String(u.low)}`;
  const flag = s.openFindings > 0 ? paint.critical('⚑') : paint.dim('⚑');
  const open = `${flag} ${String(s.openFindings)} open findings`;
  return `${paint.brand('▸▸ AKA')}${sep}${score}${sep}${tally}${sep}${open}`;
}

// One line for Claude Code's statusLine command (the persistent footer) — the
// same data and look as the read surfaces' status bar, but ANSI is
// honored here (statusLine renders it), so open findings show in red.
export function renderStatusLine(summary: HealthSummary): string {
  return renderStatusBar(findingStatus(summary), { color: true });
}

// Shared status powering the bar on /findings, /health and /recommend: the
// derived score, the unreviewed-by-severity tally, and the open-findings count.
// All three come from the whole-store health summary — NOT the finding page a
// given command fetched — so the footer reads identically on every surface
// regardless of each command's row limit (25 on /findings vs 500 elsewhere).
// `openFindings` is the real finding total (the store has no resolution state,
// so every finding is open) and sums `bySeverity`.
function findingStatus(summary: HealthSummary): FindingStatus {
  return {
    score: healthScore(summary),
    unreviewed: { ...summary.bySeverity },
    openFindings: summary.findings,
  };
}

export function renderHealth(r: HealthReport): string {
  const lines = [`● ${r.title}`, ''];
  for (const g of r.gauges) lines.push(indent(renderGauge(g)));

  lines.push('');
  const pct = Math.round(r.scanCoverage * 100);
  const stats = `Open findings ${String(r.openFindings)}` + `    Scan coverage ${String(pct)}%`;
  lines.push(indent(stats), '');

  lines.push(indent('Detections & actions — last 7 days'));
  const maxDay = Math.max(1, ...r.week.map((d) => d.total));
  for (const d of r.week) {
    const allowed = Math.max(0, d.total - d.redacted - d.warned - d.blocked);
    const segments = [
      { value: allowed, glyph: SHADE.light },
      { value: d.redacted, glyph: SHADE.medium },
      { value: d.warned, glyph: SHADE.dark },
      { value: d.blocked, glyph: SHADE.full },
    ];
    lines.push(
      indent(
        `${padEnd(d.label, WEEK_LABEL_W)}${stackedBar(segments, d.total, maxDay, WEEK_BAR_W)}  ${padStart(String(d.total), 3)}`,
      ),
    );
  }

  lines.push('');
  lines.push(
    indent(
      `${SHADE.light} allowed   ${SHADE.medium} redacted   ${SHADE.dark} warned   ${SHADE.full} blocked`,
    ),
  );
  lines.push(indent(`${String(r.weekFindings)} findings in the last 7 days`));

  lines.push('');
  lines.push(indent(`Run /recommend to review ${String(r.recommendCount)} prioritized actions.`));

  lines.push('');
  lines.push(
    indent(
      renderStatusBar({ score: r.score, unreviewed: r.unreviewed, openFindings: r.openFindings }),
    ),
  );

  return lines.join('\n');
}

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'] as const;

// "2026-06-21" (UTC day from activityByDay) → "Sat". Falls back to the raw day
// string if it can't be parsed, so the chart never breaks on odd input.
function weekday(isoDay: string): string {
  const date = new Date(`${isoDay}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? isoDay : (WEEKDAYS[date.getUTCDay()] ?? isoDay);
}

// Assemble the /health report entirely from gateway data — no placeholders. The
// gauges are the real posture inputs: Overall (the blended score), Coverage (how
// many detection categories sit under an enabled policy) and Handled (the share
// of findings actually acted on). The week chart is the real per-day findings
// breakdown from activityByDay.
//
// NOTE: Skills / Hooks / MCP / Configuration gauges and token accounting are
// intentionally omitted — they need setup-health detectors and a token meter
// this build doesn't capture yet. We show only what we can actually measure
// rather than fabricate numbers.
export function buildHealthReport(
  summary: HealthSummary,
  findings: FindingView[],
  activity: DayActivity[],
): HealthReport {
  const status = findingStatus(summary);

  const handled = summary.byAction.block + summary.byAction.redact + summary.byAction.warn;
  const handledPct = summary.findings === 0 ? 100 : Math.round((handled / summary.findings) * 100);
  const coveragePct = Math.round(summary.coverage * 100);

  const gauges: HealthGauge[] = [
    {
      label: 'Overall',
      score: status.score,
      note: `${String(summary.findings)} finding${summary.findings === 1 ? '' : 's'} total`,
      outOf100: true,
    },
    { label: 'Coverage', score: coveragePct, note: 'categories under policy' },
    {
      label: 'Handled',
      score: handledPct,
      note:
        summary.findings === 0
          ? 'no findings yet'
          : `${String(handled)}/${String(summary.findings)} acted on`,
    },
  ];

  const week: HealthDay[] = activity.map((d) => ({
    label: weekday(d.day),
    total: d.total,
    redacted: d.redacted,
    warned: d.warned,
    blocked: d.blocked,
  }));

  return {
    title: 'Setup health — local Claude Code deployment',
    gauges,
    openFindings: status.openFindings,
    scanCoverage: summary.coverage,
    week,
    weekFindings: week.reduce((n, d) => n + d.total, 0),
    // Exactly the number of rows /recommend renders (one per category, capped),
    // so "review N prioritized actions" always matches that screen.
    recommendCount: buildRecommendations(findings).length,
    unreviewed: status.unreviewed,
    score: status.score,
  };
}

// One row of the /recommend list. Severity drives ordering + the shade label;
// `context` is the meta left of the arrow, `action` the verb after.
export interface Recommendation {
  severity: string;
  title: string;
  description: string;
  context: string;
  action: string;
}

// Per-category copy for findings-derived recommendations (the live source until
// the setup-health recommender lands). Title + the verb after the → arrow.
const REC_TEMPLATE: Record<string, { title: string; action: string }> = {
  secret: { title: 'Exposed secret detected', action: 'Rotate' },
  pii: { title: 'Personal data in a prompt', action: 'Remove' },
  financial: { title: 'Financial data detected', action: 'Strip' },
  phi: { title: 'Health information detected', action: 'Remove' },
  code_context: { title: 'Proprietary code shared', action: 'Review' },
  custom: { title: 'Custom policy match', action: 'Review' },
};

// Cap on the recommendation list. One entry per category, so today it's bounded
// by the handful of REC_TEMPLATE categories — but custom rules can mint new
// categories, so cap it explicitly. Entries are severity-ranked, so the cap keeps
// the most important; the slice only ever drops low-priority overflow.
const MAX_RECOMMENDATIONS = 10;

// Derive recommendations from real findings: one per category, ranked by
// severity then frequency, described with the category's advice. (Setup-health
// items — MCP/hooks/permissions — need detectors we don't have, so
// the live list speaks to the sensitive-data findings we actually capture.)
export function buildRecommendations(findings: FindingView[]): Recommendation[] {
  interface Bucket {
    category: string;
    count: number;
    severity: string;
    weight: number;
    ruleId: string;
  }
  const buckets = new Map<string, Bucket>();
  for (const f of findings) {
    const b = buckets.get(f.category) ?? {
      category: f.category,
      count: 0,
      severity: f.severity,
      weight: 0,
      ruleId: f.ruleId,
    };
    b.count++;
    const w = SEVERITY_WEIGHT[f.severity] ?? 0;
    if (w > b.weight) {
      b.weight = w;
      b.severity = f.severity;
      b.ruleId = f.ruleId;
    }
    buckets.set(f.category, b);
  }

  return [...buckets.values()]
    .sort((a, b) => b.weight - a.weight || b.count - a.count)
    .slice(0, MAX_RECOMMENDATIONS)
    .map((b) => {
      const t = REC_TEMPLATE[b.category] ?? { title: `${b.category} finding`, action: 'Review' };
      return {
        severity: b.severity,
        title: t.title,
        description: ADVICE[b.category] ?? 'Review this finding against your policy.',
        context: `${b.ruleId} · ${String(b.count)} finding${b.count === 1 ? '' : 's'}`,
        action: t.action,
      };
    });
}

// Description wrap width for a recommendation. The body sits indented under the
// severity badge; this keeps the block within a comfortable reading measure on a
// wide terminal while still fitting ~80 columns once indented.
const REC_DESC_WIDTH = 72;
// Indent of the body/meta lines, aligning them under the severity badge that
// follows the "N. " rank prefix.
const REC_BODY_INDENT = '   ';

export function renderRecommend(recs: Recommendation[], status: FindingStatus): string {
  if (recs.length === 0) {
    return empty(
      'No recommendations yet — nothing to act on. Guidance appears as AKA detects sensitive content.',
    );
  }

  const count = `${String(recs.length)} recommendation${recs.length === 1 ? '' : 's'}`;
  const lines = [`● ${count} for your setup, ordered by severity:`, ''];

  recs.forEach((r, i) => {
    // Heading: rank · severity badge (two spaces) · what's wrong.
    const badge = `${severityGlyph(r.severity)} ${r.severity.toUpperCase()}`;
    lines.push(indent(`${String(i + 1)}. ${badge}  ${r.title}`));
    // Description, wrapped and indented under the badge.
    for (const line of wrapText(r.description, REC_DESC_WIDTH)) {
      lines.push(indent(`${REC_BODY_INDENT}${line}`));
    }
    // A blank line, then the finding context and the action verb on one line.
    lines.push('', indent(`${REC_BODY_INDENT}${r.context}  → ${r.action}`), '');
  });

  lines.push(
    indent('Run /recommend <n> to act on one, or /health for the summary.'),
    '',
    indent(renderStatusBar(status)),
  );
  return lines.join('\n');
}

export function renderAudit(findings: FindingView[]): string {
  if (findings.length === 0) {
    return empty('No decisions recorded yet — AKA logs each detection here as it acts.');
  }
  const rows = findings.map((f) => [
    shortTime(f.occurredAt),
    toApiAction(f.actionTaken),
    f.ruleId,
    f.category,
    // Join only the parts that are present so a finding missing sourceTool/kind
    // renders cleanly instead of a bare "/".
    [f.sourceTool, f.kind].filter(Boolean).join('/'),
  ]);
  return [
    `Recent decisions (${String(findings.length)})`,
    '',
    table(['Time', 'Action', 'Rule', 'Category', 'Source'], rows),
  ].join('\n');
}

// Thousands-separated integer for token counts (locale-stable, monochrome).
function num(value: number): string {
  return Math.round(value).toLocaleString('en-US');
}

// /aka:tokens — token usage rolled up across sessions by (provider, model). Token
// counts are saved truth; cost is DERIVED (— for unknown pricing, e.g. local Ollama
// or a non-Anthropic gateway). When any call is unpriced the totals are a LOWER
// bound, rendered with "≥" and a footnote, never silently understated.
export function renderTokens(reports: SessionTokenReport[]): string {
  if (reports.length === 0) {
    return empty('No token usage recorded yet — AKA reconciles your transcripts as you work.');
  }

  // Collapse every rollup onto its (provider, model) via the shared aggregator —
  // the SAME roll-up the OSS Activity page, `aka stats`, and the TUI use, so every
  // surface agrees on the per-model totals and the ≥-lower-bound cost.
  const summary = aggregateTokenUsage(reports);
  const rows = summary.models.map((m) => [
    m.provider,
    m.model,
    num(m.inputTokens),
    num(m.outputTokens),
    num(m.cacheTokens),
    num(m.totalTokens),
    m.estimatedCostUsd !== null ? formatUsd(m.estimatedCostUsd) : '—',
  ]);

  const totalCost = formatCostTotal(summary.estimatedCostUsd, summary.costIsPartial);
  const sessions =
    summary.sessionCount === 1 ? '1 session' : `${String(summary.sessionCount)} sessions`;
  const lines = [
    `Token usage — ${sessions}, ${num(summary.totalTokens)} tokens, ${totalCost}`,
    '',
    table(['Provider', 'Model', 'Input', 'Output', 'Cache', 'Total', 'Cost'], rows),
  ];
  if (summary.costIsPartial) {
    lines.push('', '— = unknown pricing (local / non-Anthropic model); cost is a lower bound.');
  }
  return lines.join('\n');
}

// "in 42m" / "in 3h" / "in 2d" — relative expiry for the /aka:exceptions table.
// A permanent grant has no expiry and renders as —; a just-lapsed one as
// "expired" (list() normally filters those, but the renderer stays honest for
// any caller). Takes `nowMs` so it is pure and unit-tests deterministically.
function relativeExpiry(expiresAt: string | null, nowMs: number): string {
  if (expiresAt === null) return '—';
  const deltaMs = Date.parse(expiresAt) - nowMs;
  if (Number.isNaN(deltaMs)) return expiresAt;
  if (deltaMs <= 0) return 'expired';
  const minutes = Math.ceil(deltaMs / 60_000);
  if (minutes < 60) return `in ${String(minutes)}m`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `in ${String(hours)}h`;
  return `in ${String(Math.round(hours / 24))}d`;
}

// /aka:exceptions — the ACTIVE detection-exception grants, read-only. Shows the
// masked preview (values are never stored — only a keyed fingerprint), the rule,
// scope, relative expiry, use count, and who granted it. Creation and revocation
// stay in the terminal (`aka exception …`) on purpose: a slash command is
// model-invocable, so this surface only displays and points at the CLI.
export function renderExceptions(exceptions: DetectionException[], nowMs = Date.now()): string {
  if (exceptions.length === 0) {
    return [
      'No active exceptions.',
      'One is granted when a detection blocks you — follow the instructions in the block message.',
    ].join('\n');
  }

  const rows = exceptions.map((e) => [
    e.id.slice(0, 8),
    e.maskedValue,
    e.ruleId,
    e.scope,
    relativeExpiry(e.expiresAt, nowMs),
    e.maxUses === null ? String(e.useCount) : `${String(e.useCount)}/${String(e.maxUses)}`,
    e.createdBy,
  ]);

  const howTo = defList([
    ['Grant from a recent block', 'aka exception approve'],
    ['Undo a grant', 'aka exception revoke <id>'],
  ]);

  return [
    `● Active exceptions (${String(exceptions.length)})`,
    '',
    indent(table(['ID', 'Value', 'Rule', 'Scope', 'Expires', 'Uses', 'Created by'], rows)),
    '',
    indent(howTo),
  ].join('\n');
}

// /aka:detections — the installed detection packs, read-only: installed
// version, rule count, enabled state, effective policy, and whether the
// running plugin ships a newer snapshot. Updates are MANUAL by design (nothing
// auto-updates an installed pack), and applying one stays in the terminal /
// dashboard on purpose — a slash command is model-invocable, so this surface
// only displays and points at the CLI (mirrors renderExceptions).
export function renderDetections(items: DetectionListItem[]): string {
  if (items.length === 0) {
    return [
      'No detection packs installed yet.',
      'They are recorded on the first plugin hook of a session, or by `aka init`.',
    ].join('\n');
  }

  const rows = items.map((i) => [
    i.id,
    `v${i.version}`,
    i.latestVersion ? `v${i.latestVersion}` : `v${i.version}`,
    String(i.ruleCount),
    i.enabled ? 'yes' : 'no',
    i.policyId ?? 'monitor',
    i.latestVersion ? '⬆ update available' : '✓ up to date',
  ]);

  const updates = items.filter((i) => i.latestVersion != null);
  const totalRules = items.reduce((n, i) => n + i.ruleCount, 0);
  const active = items.filter((i) => i.enabled).length;

  const lines = [
    `● Installed detections (${String(items.length)} packs · ${String(totalRules)} rules · ${String(active)} enabled)`,
    '',
    indent(table(['Pack', 'Installed', 'Latest', 'Rules', 'Enabled', 'Policy', 'Status'], rows)),
    '',
  ];
  if (updates.length > 0) {
    lines.push(
      indent(
        `⬆ ${String(updates.length)} update(s) available. Updates are never applied automatically —`,
      ),
      indent('apply them yourself in a terminal or the dashboard:'),
      '',
      indent(
        defList([
          ['Update every pack', 'aka detections update --all'],
          ['Update one pack', `aka detections update ${updates[0]?.packId ?? '<pack-id>'}`],
          ['Review in the dashboard', 'aka dashboard → Detections → Update'],
        ]),
      ),
    );
  } else {
    lines.push(indent('✓ All detection packs are up to date with this plugin.'));
  }
  return lines.join('\n');
}

export type QuerySubcommand = 'findings' | 'health' | 'recommend' | 'audit' | 'tokens';

// Severity levels accepted by the `--severity` filter on /findings.
export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface QueryOptions {
  severity?: Severity;
}

// `exceptions` is listed for the user-facing usage line but dispatched
// UPSTREAM in query.ts (it reads the local store directly, not the gateway) —
// runQuery itself never receives it.
const USAGE = 'Usage: query <findings|health|recommend|audit|tokens|exceptions|detections>';

// Dispatch a read subcommand against a resolved data gateway and return the text
// to print. Reads only — nothing is mutated here. Async because the DataGateway
// contract is async.
export async function runQuery(
  sub: string,
  gateway: DataGateway,
  opts: QueryOptions = {},
): Promise<string> {
  switch (sub) {
    case 'findings': {
      // Pull a wider window when filtering so the severity isn't limited to the
      // 25 most recent overall; otherwise keep the default recent slice.
      const limit = opts.severity !== undefined ? 500 : 25;
      // Independent reads — fetch concurrently.
      const [findings, summary] = await Promise.all([
        gateway.recentFindings({ limit }),
        gateway.healthSummary(),
      ]);
      // Narrow to the requested level when a `--severity` filter is given; the
      // status bar still reflects the whole-store summary, so its tally stays put
      // even though the listed rows are a recent (and possibly filtered) slice.
      const rows =
        opts.severity !== undefined
          ? findings.filter((f) => f.severity === opts.severity)
          : findings;
      return renderFindings(rows, findingStatus(summary), opts.severity);
    }
    case 'health': {
      const [summary, findings, activity] = await Promise.all([
        gateway.healthSummary(),
        gateway.recentFindings({ limit: 500 }),
        gateway.activityByDay(7),
      ]);
      return renderHealth(buildHealthReport(summary, findings, activity));
    }
    case 'recommend': {
      const [findings, summary] = await Promise.all([
        gateway.recentFindings({ limit: 500 }),
        gateway.healthSummary(),
      ]);
      return renderRecommend(buildRecommendations(findings), findingStatus(summary));
    }
    case 'audit':
      return renderAudit(await gateway.recentFindings({ limit: 25 }));
    case 'tokens':
      return renderTokens(await gateway.tokenReports());
    default:
      return USAGE;
  }
}
