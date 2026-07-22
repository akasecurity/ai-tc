import { parseArgs } from 'node:util';

import { openLocalDatabase } from '@akasecurity/persistence';
import { dataDir } from '@akasecurity/plugin-sdk';
import {
  aggregateTokenUsage,
  DEFAULT_TIME_RANGE,
  RANGE_DAYS,
  type SeveritySummaryResponse,
  TIME_RANGES,
  type TimeRange,
  type TokenUsageSummary,
} from '@akasecurity/schema';

import { HOME_OPTION, homeBase } from '../lib/args.ts';
import { compactTokens, totalCostLabel, usdCost } from '../lib/tokens.ts';

const DAY_MS = 86_400_000;

// Exported for the unit test (same pattern as renderFindingsSummary).
export function parseRange(value: string | undefined): TimeRange {
  return (TIME_RANGES as readonly string[]).includes(value ?? '')
    ? (value as TimeRange)
    : DEFAULT_TIME_RANGE;
}

// `aka stats` — print local-store aggregates: findings by severity + enforcement
// actions in a range, installed-pack counts, and the latest findings. All reads
// go through @akasecurity/persistence (no backend).
export async function runStats(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    options: { ...HOME_OPTION, range: { type: 'string' } },
  });
  const home = homeBase(values.home);
  const range = parseRange(values.range);

  const db = openLocalDatabase(dataDir(home));
  const tokenFromMs = Date.now() - RANGE_DAYS[range] * DAY_MS;
  const [health, severity, enforcement, packs, recent, tokenReports] = await Promise.all([
    db.findings.healthSummary(),
    db.security.severitySummary(),
    db.security.enforcementActions(range),
    db.installedPacks.counts(),
    db.findings.recentFindings({ limit: 5 }),
    // Token usage folded into stats — no dedicated `aka tokens` command. Scoped
    // to the same range as enforcement; cost DERIVED via the shared cost model.
    db.activity.tokenReports(tokenFromMs),
  ]);
  db.close();
  const tokenUsage = aggregateTokenUsage(tokenReports);

  const out = process.stdout;
  out.write(`AKA — local store (${home})\n\n`);

  out.write(`${renderFindingsSummary(severity)}\n`);

  out.write(`\nEnforcement (${range}): ${String(enforcement.total)} intercepted\n`);
  for (const a of enforcement.actions) {
    const delta = a.delta === 0 ? '' : ` (${a.delta > 0 ? '+' : ''}${String(a.delta)} wk/wk)`;
    out.write(`  ${a.kind.padEnd(9)} ${String(a.count)}${delta}\n`);
  }

  out.write(
    `\nCoverage: ${String(Math.round(health.coverage * 100))}% of detection categories have an enabled policy\n`,
  );
  out.write(
    `Detections: ${String(packs.packs)} pack(s) · ${String(packs.rules)} rule(s) · ${String(packs.enabled)} enabled\n`,
  );

  out.write(`\n${renderTokenUsage(tokenUsage, range)}\n`);

  if (recent.length > 0) {
    out.write(`\nLatest findings:\n`);
    for (const f of recent) {
      out.write(
        `  ${f.occurredAt.slice(0, 16).replace('T', ' ')}  ${f.severity.padEnd(8)} ${f.ruleId}  ${f.maskedMatch}\n`,
      );
    }
  }
}

// Findings block: the severity breakdown plus the two-track "caught vs needs
// remediation" framing — Caught (sum of bySeverity[].caught: findings handled
// in-flight by enforcement, or resolved at rest) vs Needs remediation (the
// top-level needsRemediation: still open at rest). Both fields are optional on
// SeveritySummaryResponse (absent on the pre-resolution-feature response), so
// missing values default to 0 rather than recomputing from raw findings.
// Exported for the unit test (same pattern as renderDetectionsTable).
export function renderFindingsSummary(severity: SeveritySummaryResponse): string {
  const caught = severity.bySeverity.reduce((sum, s) => sum + (s.caught ?? 0), 0);
  const needsRemediation = severity.needsRemediation ?? 0;

  const labelWidth = Math.max(
    9,
    ...severity.bySeverity.map((s) => s.severity.length),
    'Needs remediation'.length,
  );

  const lines = [`Findings: ${String(severity.total)} total`];
  for (const s of severity.bySeverity) {
    lines.push(`  ${s.severity.padEnd(labelWidth)} ${String(s.count)}`);
  }
  lines.push(`  ${'Caught'.padEnd(labelWidth)} ${String(caught)}`);
  lines.push(`  ${'Needs remediation'.padEnd(labelWidth)} ${String(needsRemediation)}`);
  return lines.join('\n');
}

// Cap on the per-model rows the stats block prints — the heaviest spenders. The
// full per-session/per-model detail lives on the web-ui Activity page and the
// plugin's `/aka:tokens`; here we keep it a glance.
const TOP_MODELS = 6;

// Token-usage block: sessions + total tokens + estimated cost for the range,
// then the top models by spend. Token counts are exact; cost is DERIVED at read
// time — a `—` means unknown pricing (local / non-Anthropic), so a `≥` total is a
// lower bound. Exported for the unit test (same pattern as renderFindingsSummary).
export function renderTokenUsage(summary: TokenUsageSummary, range: TimeRange): string {
  if (summary.models.length === 0) {
    return `Token usage (${range}): none recorded`;
  }
  const total = totalCostLabel(summary.estimatedCostUsd, summary.costIsPartial);
  const sessions = `${String(summary.sessionCount)} session${summary.sessionCount === 1 ? '' : 's'}`;
  const lines = [
    `Token usage (${range}): ${sessions} · ${compactTokens(summary.totalTokens)} tokens · ${total}`,
  ];

  const shown = summary.models.slice(0, TOP_MODELS);
  const labelWidth = Math.max(...shown.map((m) => `${m.provider}/${m.model}`.length));
  for (const m of shown) {
    const cost = m.estimatedCostUsd !== null ? usdCost(m.estimatedCostUsd) : '—';
    lines.push(
      `  ${`${m.provider}/${m.model}`.padEnd(labelWidth)}  ${compactTokens(m.totalTokens).padStart(7)}  ${cost}`,
    );
  }
  if (summary.models.length > TOP_MODELS) {
    lines.push(`  … and ${String(summary.models.length - TOP_MODELS)} more model(s)`);
  }
  if (summary.costIsPartial) {
    lines.push('  — = unknown pricing (local / non-Anthropic); cost is a lower bound.');
  }
  return lines.join('\n');
}
