import type { FindingView, ModelTokenUsage, TokenUsageSummary } from '@akasecurity/schema';
import { Box, Text, useApp, useInput } from 'ink';
import type { ReactElement } from 'react';
import { useState } from 'react';

import { compactTokens, totalCostLabel, usdCost } from '../lib/tokens.ts';
import { gaugeFill, padEnd, padStart, stackedBar, wrapText } from './bars.ts';
import type {
  FindingStatus,
  HealthDay,
  HealthGauge,
  HealthReport,
  Recommendation,
} from './report.ts';
import { actionColor, COLOR, scoreColor, severityColor, severityGlyph, SHADE } from './theme.ts';

// The `aka tui` view — an interactive, COLOUR terminal dashboard that mirrors the
// plugin's transcript slash-command screens (/health, /findings, /recommend,
// /audit). Those surfaces are monochrome because the Claude Code transcript can't
// render ANSI; here Ink drives a real terminal, so the same layout grammar (the
// ░▒▓█ shade bars, the gauges, the status line) is reproduced in the design
// tokens' colours. Tab / ←→ / 1–4 switch views; ↑/↓ navigate a list; q quits.

const GAUGE_LABEL_W = 14;
const GAUGE_BAR_W = 18;
const WEEK_LABEL_W = 5;
const WEEK_BAR_W = 44;
const REC_DESC_WIDTH = 72;
const MATCH_W = 28;
// Token-usage block on the Health screen: the heaviest N models, provider/model
// left-padded to this width. Full per-session detail lives on the web-ui Activity
// page + the plugin's /aka:tokens; here it's a glance folded into the overview.
const TOKEN_ROWS = 4;
const TOKEN_LABEL_W = 30;

const VIEWS = ['health', 'findings', 'recommend', 'audit'] as const;
type View = (typeof VIEWS)[number];
const TABS: { key: View; label: string }[] = [
  { key: 'health', label: 'Health' },
  { key: 'findings', label: 'Findings' },
  { key: 'recommend', label: 'Recommend' },
  { key: 'audit', label: 'Audit' },
];

// "2026-06-19T11:14:53.000Z" → "06-19 11:14"; placeholder for a missing stamp.
function shortTime(iso: string): string {
  if (!iso) return '—';
  return iso.length >= 16 ? `${iso.slice(5, 10)} ${iso.slice(11, 16)}` : iso;
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, Math.max(0, max - 1))}…` : text;
}

// ── shared bits ────────────────────────────────────────────────────────────

function Sep(): ReactElement {
  return <Text color={COLOR.dim}>{' │ '}</Text>;
}

interface Cell {
  text: string;
  color?: string;
}

function TableRow({
  cells,
  widths,
  gap,
  selected,
}: {
  cells: Cell[];
  widths: number[];
  gap: number;
  selected: boolean;
}): ReactElement {
  if (selected) {
    const line = cells.map((c, i) => padEnd(c.text, widths[i] ?? 0)).join(' '.repeat(gap));
    return <Text inverse>{line}</Text>;
  }
  return (
    <Text>
      {cells.map((c, i) => {
        const padded =
          padEnd(c.text, widths[i] ?? 0) + (i < cells.length - 1 ? ' '.repeat(gap) : '');
        return c.color !== undefined ? (
          <Text key={i} color={c.color}>
            {padded}
          </Text>
        ) : (
          <Text key={i}>{padded}</Text>
        );
      })}
    </Text>
  );
}

// A left-aligned table with UPPERCASE dim headers — the /findings + /audit look,
// with the selected row highlighted (inverse) instead of the transcript's rule.
function DataTable({
  headers,
  rows,
  selected,
}: {
  headers: string[];
  rows: Cell[][];
  selected: number;
}): ReactElement {
  const gap = 3;
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i]?.text ?? '').length)),
  );
  return (
    <Box flexDirection="column">
      <Text color={COLOR.dim} bold>
        {headers.map((h, i) => (
          <Text key={i}>
            {padEnd(h.toUpperCase(), widths[i] ?? 0)}
            {i < headers.length - 1 ? ' '.repeat(gap) : ''}
          </Text>
        ))}
      </Text>
      {rows.map((cells, ri) => (
        <TableRow key={ri} cells={cells} widths={widths} gap={gap} selected={selected === ri} />
      ))}
    </Box>
  );
}

function Heading({ title, dot = true }: { title: string; dot?: boolean }): ReactElement {
  return (
    <Text>
      {dot ? <Text color={COLOR.ok}>{'● '}</Text> : null}
      <Text bold>{title}</Text>
    </Text>
  );
}

function StatusBar({ status }: { status: FindingStatus }): ReactElement {
  const u = status.unreviewed;
  return (
    <Text>
      <Text bold color={COLOR.brand}>
        {'▸▸ AKA'}
      </Text>
      <Sep />
      <Text color={scoreColor(status.score)}>{'●'}</Text>
      {' health '}
      <Text bold>{String(status.score)}</Text>
      <Text color={COLOR.dim}>{'/100'}</Text>
      <Sep />
      <Text color={COLOR.dim}>{'unreviewed'}</Text> <Text color={COLOR.critical}>{'■'}</Text>
      {String(u.critical)} <Text color={COLOR.high}>{'■'}</Text>
      {String(u.high)} <Text color={COLOR.medium}>{'■'}</Text>
      {String(u.medium)} <Text color={COLOR.low}>{'■'}</Text>
      {String(u.low)}
      <Sep />
      <Text color={status.openFindings > 0 ? COLOR.critical : COLOR.dim}>{'⚑'}</Text>
      {` ${String(status.openFindings)} open findings`}
    </Text>
  );
}

// ── Health view ──────────────────────────────────────────────────────────────

function Gauge({ g }: { g: HealthGauge }): ReactElement {
  const { filled, empty } = gaugeFill(g.score, 100, GAUGE_BAR_W);
  const outOf = g.outOf100 === true ? '/ 100' : '     ';
  return (
    <Text>
      {padEnd(g.label, GAUGE_LABEL_W)}
      {'  '}
      <Text color={scoreColor(g.score)}>{SHADE.full.repeat(filled)}</Text>
      <Text color={COLOR.dim}>{SHADE.light.repeat(empty)}</Text>
      {'  '}
      <Text bold>{padStart(String(g.score), 3)}</Text> <Text color={COLOR.dim}>{outOf}</Text>
      {'   '}
      <Text color={COLOR.dim}>{g.note}</Text>
    </Text>
  );
}

function WeekRow({ d, max }: { d: HealthDay; max: number }): ReactElement {
  const allowed = Math.max(0, d.total - d.redacted - d.warned - d.blocked);
  const { runs, blank } = stackedBar(
    [
      { value: allowed, glyph: SHADE.light, color: COLOR.ok },
      { value: d.redacted, glyph: SHADE.medium, color: COLOR.low },
      { value: d.warned, glyph: SHADE.dark, color: COLOR.medium },
      { value: d.blocked, glyph: SHADE.full, color: COLOR.critical },
    ],
    d.total,
    max,
    WEEK_BAR_W,
  );
  return (
    <Text>
      {padEnd(d.label, WEEK_LABEL_W)}
      {runs.map((r, i) => (
        <Text key={i} color={r.color}>
          {r.glyph.repeat(r.len)}
        </Text>
      ))}
      {' '.repeat(blank)}
      {'  '}
      {padStart(String(d.total), 3)}
    </Text>
  );
}

function Legend(): ReactElement {
  return (
    <Text>
      <Text color={COLOR.ok}>{SHADE.light}</Text>
      {' allowed   '}
      <Text color={COLOR.low}>{SHADE.medium}</Text>
      {' redacted   '}
      <Text color={COLOR.medium}>{SHADE.dark}</Text>
      {' warned   '}
      <Text color={COLOR.critical}>{SHADE.full}</Text>
      {' blocked'}
    </Text>
  );
}

// One per-model row in the token-usage block: provider/model · total tokens ·
// derived cost (— for unknown pricing). Colour mirrors the DataTable rows.
function TokenRow({ m }: { m: ModelTokenUsage }): ReactElement {
  const cost = m.estimatedCostUsd !== null ? usdCost(m.estimatedCostUsd) : '—';
  return (
    <Text>
      <Text color={COLOR.dim}>{padEnd(`${m.provider}/${m.model}`, TOKEN_LABEL_W)}</Text>
      {'  '}
      {padStart(compactTokens(m.totalTokens), 8)}
      {'  '}
      <Text>{cost}</Text>
    </Text>
  );
}

// Token usage folded into the Health screen (no dedicated token tab): sessions +
// total tokens + estimated cost, then the heaviest models. Token counts are
// exact; cost is DERIVED — a `≥` total is a lower bound when pricing is unknown.
function TokenUsageSection({ usage }: { usage: TokenUsageSummary }): ReactElement | null {
  if (usage.models.length === 0) return null;
  const sessions = `${String(usage.sessionCount)} session${usage.sessionCount === 1 ? '' : 's'}`;
  const cost = totalCostLabel(usage.estimatedCostUsd, usage.costIsPartial);
  return (
    <Box flexDirection="column" marginTop={1}>
      <Box paddingLeft={2}>
        {/* Window label must track the `tokenReports(...)` bound in tui.tsx (90d). */}
        <Text>{'Token usage · last 90 days'}</Text>
      </Box>
      <Box paddingLeft={2}>
        <Text color={COLOR.dim}>
          {`${sessions} · ${compactTokens(usage.totalTokens)} tokens · ${cost}`}
        </Text>
      </Box>
      {usage.models.slice(0, TOKEN_ROWS).map((m) => (
        <Box key={`${m.provider} ${m.model}`} paddingLeft={2}>
          <TokenRow m={m} />
        </Box>
      ))}
    </Box>
  );
}

function HealthView({
  report,
  tokenUsage,
}: {
  report: HealthReport;
  tokenUsage: TokenUsageSummary;
}): ReactElement {
  const maxDay = Math.max(1, ...report.week.map((d) => d.total));
  const pct = Math.round(report.scanCoverage * 100);
  return (
    <Box flexDirection="column">
      <Heading title={report.title} />

      <Box flexDirection="column" marginTop={1}>
        {report.gauges.map((g) => (
          <Box key={g.label} paddingLeft={2}>
            <Gauge g={g} />
          </Box>
        ))}
      </Box>

      <Box marginTop={1} paddingLeft={2}>
        <Text>
          {`Open findings ${String(report.openFindings)}`}
          {'    '}
          {`Scan coverage ${String(pct)}%`}
        </Text>
      </Box>

      <Box flexDirection="column" marginTop={1}>
        <Box paddingLeft={2}>
          <Text>{'Detections & actions — last 7 days'}</Text>
        </Box>
        {report.week.map((d, i) => (
          <Box key={i} paddingLeft={2}>
            <WeekRow d={d} max={maxDay} />
          </Box>
        ))}
      </Box>

      <Box flexDirection="column" marginTop={1}>
        <Box paddingLeft={2}>
          <Legend />
        </Box>
        <Box paddingLeft={2}>
          <Text
            color={COLOR.dim}
          >{`${String(report.weekFindings)} findings in the last 7 days`}</Text>
        </Box>
      </Box>

      <Box marginTop={1} paddingLeft={2}>
        <Text color={COLOR.dim}>
          {`Press 3 (Recommend) to review ${String(report.recommendCount)} prioritized actions.`}
        </Text>
      </Box>

      <TokenUsageSection usage={tokenUsage} />
    </Box>
  );
}

// ── Findings / Audit / Recommend views ───────────────────────────────────────

function FindingsView({
  findings,
  selected,
}: {
  findings: FindingView[];
  selected: number;
}): ReactElement {
  if (findings.length === 0) {
    return (
      <Text color={COLOR.dim}>
        {'No findings recorded yet — AKA scans prompts, file edits, and tool output as you work.'}
      </Text>
    );
  }
  const rows: Cell[][] = findings.map((f) => [
    { text: shortTime(f.occurredAt), color: COLOR.dim },
    { text: `${severityGlyph(f.severity)} ${f.severity}`, color: severityColor(f.severity) },
    { text: f.category },
    { text: f.ruleId, color: COLOR.dim },
    { text: f.actionTaken, color: actionColor(f.actionTaken) },
    { text: truncate(f.maskedMatch, MATCH_W) },
  ]);
  return (
    <Box flexDirection="column">
      <Heading title={`Recent findings (${String(findings.length)})`} />
      <Box marginTop={1}>
        <DataTable
          headers={['Time', 'Severity', 'Category', 'Rule', 'Action', 'Match']}
          rows={rows}
          selected={selected}
        />
      </Box>
    </Box>
  );
}

function AuditView({
  findings,
  selected,
}: {
  findings: FindingView[];
  selected: number;
}): ReactElement {
  if (findings.length === 0) {
    return (
      <Text color={COLOR.dim}>
        {'No decisions recorded yet — AKA logs each detection here as it acts.'}
      </Text>
    );
  }
  const rows: Cell[][] = findings.map((f) => [
    { text: shortTime(f.occurredAt), color: COLOR.dim },
    { text: f.actionTaken, color: actionColor(f.actionTaken) },
    { text: f.ruleId },
    { text: f.category },
    { text: [f.sourceTool, f.kind].filter(Boolean).join('/'), color: COLOR.dim },
  ]);
  return (
    <Box flexDirection="column">
      <Heading title={`Recent decisions (${String(findings.length)})`} dot={false} />
      <Box marginTop={1}>
        <DataTable
          headers={['Time', 'Action', 'Rule', 'Category', 'Source']}
          rows={rows}
          selected={selected}
        />
      </Box>
    </Box>
  );
}

function RecommendView({
  recs,
  selected,
}: {
  recs: Recommendation[];
  selected: number;
}): ReactElement {
  if (recs.length === 0) {
    return (
      <Text color={COLOR.dim}>
        {
          'No recommendations yet — nothing to act on. Guidance appears as AKA detects sensitive content.'
        }
      </Text>
    );
  }
  return (
    <Box flexDirection="column">
      <Heading
        title={`${String(recs.length)} recommendation${recs.length === 1 ? '' : 's'} for your setup, ordered by severity:`}
      />
      {recs.map((r, i) => (
        <Box key={i} flexDirection="column" marginTop={1} paddingLeft={2}>
          <Text>
            {`${String(i + 1)}. `}
            <Text color={severityColor(r.severity)} bold>
              {`${severityGlyph(r.severity)} ${r.severity.toUpperCase()}`}
            </Text>
            {'  '}
            {selected === i ? <Text inverse>{r.title}</Text> : <Text bold>{r.title}</Text>}
          </Text>
          {wrapText(r.description, REC_DESC_WIDTH).map((line, li) => (
            <Text key={li} color={COLOR.dim}>{`   ${line}`}</Text>
          ))}
          <Text>
            {'   '}
            <Text color={COLOR.dim}>{r.context}</Text>
            {'  → '}
            <Text color={COLOR.brand} bold>
              {r.action}
            </Text>
          </Text>
        </Box>
      ))}
    </Box>
  );
}

// ── App shell ────────────────────────────────────────────────────────────────

export type DashboardView = View;

interface Props {
  home: string;
  report: HealthReport;
  status: FindingStatus;
  findings: FindingView[];
  recommendations: Recommendation[];
  // Cross-session token usage (folded into the Health screen — no dedicated
  // token tab), rolled up per (provider, model) with derived cost.
  tokenUsage: TokenUsageSummary;
  // Which screen to open on. Lets `aka tui <view>` deep-link to a surface, the
  // way each slash command is its own screen; defaults to Health.
  initialView?: View;
}

export function Dashboard({
  home,
  report,
  status,
  findings,
  recommendations,
  tokenUsage,
  initialView = 'health',
}: Props): ReactElement {
  const { exit } = useApp();
  const [view, setView] = useState<View>(initialView);
  const [selected, setSelected] = useState(0);

  const listLen =
    view === 'findings' || view === 'audit'
      ? findings.length
      : view === 'recommend'
        ? recommendations.length
        : 0;

  const go = (next: View): void => {
    setView(next);
    setSelected(0);
  };

  useInput((input, key) => {
    if (input === 'q' || key.escape) {
      exit();
      return;
    }
    const index = VIEWS.indexOf(view);
    if (key.tab || key.rightArrow) {
      go(VIEWS[(index + 1) % VIEWS.length] ?? 'health');
      return;
    }
    if (key.leftArrow) {
      go(VIEWS[(index - 1 + VIEWS.length) % VIEWS.length] ?? 'health');
      return;
    }
    const n = Number.parseInt(input, 10);
    if (!Number.isNaN(n) && n >= 1 && n <= VIEWS.length) {
      const v = VIEWS[n - 1];
      if (v !== undefined) go(v);
      return;
    }
    if (key.downArrow || input === 'j') {
      setSelected((i) => Math.min(i + 1, Math.max(listLen - 1, 0)));
    }
    if (key.upArrow || input === 'k') {
      setSelected((i) => Math.max(i - 1, 0));
    }
  });

  return (
    <Box flexDirection="column" paddingX={1}>
      <Box flexDirection="column" marginBottom={1}>
        <Text>
          <Text bold color={COLOR.brand}>
            {'▸▸ AKA'}
          </Text>
          <Text color={COLOR.dim}>{`   local store · ${home}`}</Text>
        </Text>
        <Box marginTop={1}>
          {TABS.map((t, i) => {
            const active = t.key === view;
            const label = `${String(i + 1)} ${t.label}`;
            return (
              <Box key={t.key} marginRight={3}>
                {active ? (
                  <Text color={COLOR.brand} bold underline>
                    {label}
                  </Text>
                ) : (
                  <Text color={COLOR.dim}>{label}</Text>
                )}
              </Box>
            );
          })}
        </Box>
      </Box>

      {view === 'health' && <HealthView report={report} tokenUsage={tokenUsage} />}
      {view === 'findings' && <FindingsView findings={findings} selected={selected} />}
      {view === 'recommend' && <RecommendView recs={recommendations} selected={selected} />}
      {view === 'audit' && <AuditView findings={findings} selected={selected} />}

      <Box flexDirection="column" marginTop={1}>
        <StatusBar status={status} />
        <Text color={COLOR.dim}>{'↑/↓ navigate · ←/→ or Tab switch view · 1–4 jump · q quit'}</Text>
      </Box>
    </Box>
  );
}
