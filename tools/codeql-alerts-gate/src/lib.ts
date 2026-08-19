// Pure logic for the CodeQL open-alert gate: reading the baseline, summarising
// a live alert list, and comparing the two. The CLI entry (check-alerts.ts)
// owns all I/O, so the unit suite drives every outcome from canned inputs.
//
// What this is for. CodeQL runs on every PR, on every push to main and weekly,
// and its findings land in the Security tab — which nothing reads. Twenty-six
// alerts accumulated there, none of them dismissed, with nothing anywhere
// saying the number was going up. An analysis whose output is consumed by no
// one is a report, not a gate, and the cost of that is invisible by
// construction: no run is red, no check is failing, and the count only moves in
// one direction.
//
// This does NOT triage anything and must not be read as accepting the alerts it
// counts. It answers one question — is the number rising? — and the baseline is
// a record of outstanding work rather than a permitted level.

/** The counts a baseline file pins. */
export interface AlertBaseline {
  total: number;
  bySeverity: Record<string, number>;
}

/** One alert, as the code-scanning REST API returns it. */
export interface Alert {
  rule?: { id?: string; security_severity_level?: string; severity?: string };
  state?: string;
}

export class AlertGateConfigError extends Error {}

/**
 * The baseline, refused rather than defaulted when it does not parse.
 *
 * A missing or malformed baseline read as zero would fail every run; read as
 * Infinity it would pass every run. Neither is a safe default, and the second
 * is the dangerous one — it is silent, and it is what "just make it not crash"
 * produces.
 */
export function parseBaseline(json: string): AlertBaseline {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new AlertGateConfigError('the CodeQL alert baseline is not valid JSON');
  }
  const raw = parsed as { total?: unknown; bySeverity?: unknown } | null;
  if (typeof raw?.total !== 'number' || !Number.isInteger(raw.total) || raw.total < 0) {
    throw new AlertGateConfigError('the baseline needs an integer "total" of zero or more');
  }
  // `Array.isArray` as well as the null check: `typeof [] === 'object'`, so a
  // bySeverity written as a list would parse into severities named '0', '1', …
  // and every real severity would then read as risen-from-zero. A malformed
  // baseline has to be refused, not reinterpreted.
  if (
    raw.bySeverity === null ||
    typeof raw.bySeverity !== 'object' ||
    Array.isArray(raw.bySeverity)
  ) {
    throw new AlertGateConfigError('the baseline needs a "bySeverity" object');
  }
  const bySeverity: Record<string, number> = {};
  for (const [severity, count] of Object.entries(raw.bySeverity as Record<string, unknown>)) {
    if (typeof count !== 'number' || !Number.isInteger(count) || count < 0) {
      throw new AlertGateConfigError(`the baseline's "${severity}" count must be an integer`);
    }
    bySeverity[severity] = count;
  }
  // The two halves have to describe the same tree. A hand edit that lowers the
  // total and forgets a severity (or the reverse) otherwise reaches compare()
  // as a real baseline, where it fails on the total alone — a red run whose
  // cause is a typo in this file rather than anything about the alerts.
  const summed = Object.values(bySeverity).reduce((a, b) => a + b, 0);
  if (summed !== raw.total) {
    throw new AlertGateConfigError(
      `the baseline's severities add up to ${String(summed)} but its total says ${String(raw.total)}`,
    );
  }
  return { total: raw.total, bySeverity };
}

/**
 * The severity a single alert counts under.
 *
 * `security_severity_level` is what a security query reports and is what the
 * Security tab groups by; `severity` is the fallback a non-security query
 * carries (the workflow-permissions rule is one). An alert with neither is
 * counted as `unknown` rather than dropped — dropping it would let a whole
 * class of alert grow without moving the total, which is the one number this
 * gate is built on.
 */
export const severityOf = (alert: Alert): string =>
  alert.rule?.security_severity_level ?? alert.rule?.severity ?? 'unknown';

export interface AlertSummary {
  total: number;
  bySeverity: Record<string, number>;
  /** Rule ids and their counts, for the report — never gated on. */
  byRule: Record<string, number>;
}

export function summarise(alerts: Alert[]): AlertSummary {
  const bySeverity: Record<string, number> = {};
  const byRule: Record<string, number> = {};
  for (const alert of alerts) {
    const severity = severityOf(alert);
    bySeverity[severity] = (bySeverity[severity] ?? 0) + 1;
    const rule = alert.rule?.id ?? 'unknown';
    byRule[rule] = (byRule[rule] ?? 0) + 1;
  }
  return { total: alerts.length, bySeverity, byRule };
}

export interface AlertDrift {
  /** Severities whose count went up, and by how much. */
  risen: { severity: string; was: number; now: number }[];
  /** Severities whose count went down — the baseline is stale, lower it. */
  fallen: { severity: string; was: number; now: number }[];
  totalWas: number;
  totalNow: number;
}

/**
 * Compare live counts against the baseline, per severity and in total.
 *
 * A ratchet in BOTH directions, matching how every other allowance in this
 * repository behaves. A rise is the failure the gate exists for. A fall fails
 * too, because a baseline nobody lowers stops describing the tree: fix eight
 * alerts under a one-way gate and the number that was supposed to mean
 * "outstanding work" now permits eight new ones silently.
 *
 * Per severity as well as in total, because a total alone is blind to the swap
 * — one high fixed and one medium introduced leaves the total flat while the
 * tree got better, and the reverse leaves it flat while the tree got worse.
 */
export function compareAlerts(baseline: AlertBaseline, summary: AlertSummary): AlertDrift {
  const risen: AlertDrift['risen'] = [];
  const fallen: AlertDrift['fallen'] = [];
  // The union of both key sets: a severity that appeared for the first time is
  // absent from the baseline, and one that was fully fixed is absent from the
  // live summary. Iterating either alone misses one of those.
  for (const severity of new Set([
    ...Object.keys(baseline.bySeverity),
    ...Object.keys(summary.bySeverity),
  ])) {
    const was = baseline.bySeverity[severity] ?? 0;
    const now = summary.bySeverity[severity] ?? 0;
    if (now > was) risen.push({ severity, was, now });
    else if (now < was) fallen.push({ severity, was, now });
  }
  risen.sort((a, b) => a.severity.localeCompare(b.severity));
  fallen.sort((a, b) => a.severity.localeCompare(b.severity));
  return { risen, fallen, totalWas: baseline.total, totalNow: summary.total };
}

export const isAlertFailure = (drift: AlertDrift): boolean =>
  drift.risen.length > 0 || drift.fallen.length > 0 || drift.totalNow !== drift.totalWas;

const table = (counts: Record<string, number>): string[] => {
  const rows = Object.entries(counts).sort(([a], [b]) => a.localeCompare(b));
  return [
    '| Key | Count |',
    '| --- | --- |',
    ...rows.map(([k, n]) => `| \`${k}\` | ${String(n)} |`),
  ];
};

export function buildAlertSummary(drift: AlertDrift, summary: AlertSummary): string {
  const lines = ['# CodeQL open alerts', ''];
  lines.push(`**${String(drift.totalNow)} open** (baseline ${String(drift.totalWas)}).`, '');

  if (drift.risen.length > 0) {
    lines.push('## The alert count went UP', '');
    for (const { severity, was, now } of drift.risen) {
      lines.push(`- \`${severity}\`: ${String(was)} → ${String(now)}`);
    }
    lines.push(
      '',
      '**Do not raise the baseline to absorb it.** That is the one response that defeats this',
      'gate, and it is exactly what "twenty-six accumulated with nothing saying so" looked',
      'like while it was happening. Fix the alert, or dismiss it in the Security tab with a',
      'recorded reason, and lower the baseline in the same commit.',
      '',
    );
  }

  if (drift.fallen.length > 0) {
    lines.push('## The alert count went DOWN — lower the baseline', '');
    for (const { severity, was, now } of drift.fallen) {
      lines.push(`- \`${severity}\`: ${String(was)} → ${String(now)}`);
    }
    lines.push(
      '',
      'This is the good direction, and it fails on purpose: a baseline nobody lowers stops',
      'describing the tree, and the headroom it leaves behind admits new alerts silently.',
      'Update `.github/codeql-alert-baseline.json` and this goes green.',
      '',
    );
  }

  // The totals can disagree while every severity matches — a half-finished hand
  // edit of the baseline. `parseBaseline` now refuses that file outright, so
  // this is unreachable from a real run; it stays because without it the case
  // failed with NO section and NO annotation, showing a red job whose entire
  // output looked healthy. A failure this gate cannot explain is worse than one
  // it never detects.
  if (drift.risen.length === 0 && drift.fallen.length === 0 && drift.totalNow !== drift.totalWas) {
    lines.push(
      '## The totals disagree, though every severity matches',
      '',
      `Baseline total ${String(drift.totalWas)}, live total ${String(drift.totalNow)}, and no severity moved.`,
      '',
      'That means the baseline contradicts itself rather than the tree having changed.',
      'Make `total` equal the sum of `bySeverity` in `.github/codeql-alert-baseline.json`.',
      '',
    );
  }

  if (!isAlertFailure(drift)) {
    lines.push(
      'Unchanged from the baseline. Every count below is outstanding work, not an',
      'accepted level.',
      '',
    );
  }

  lines.push('## By severity', '', ...table(summary.bySeverity), '');
  lines.push('## By rule', '', ...table(summary.byRule), '');
  return lines.join('\n');
}

/**
 * The alerts response, parsed and shape-checked.
 *
 * Refused rather than read as an empty list: empty compares against a non-zero
 * baseline as "every alert was fixed", which is the good news this gate would
 * otherwise be trusted for.
 */
export function parseAlertsResponse(stdout: string): Alert[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error(`gh did not return JSON: ${stdout.trim().slice(0, 400)}`);
  }
  if (!Array.isArray(parsed))
    throw new Error('the code-scanning response was not a list of alerts');
  return parsed as Alert[];
}

/**
 * The outside world this gate touches, taken as a parameter — the same seam
 * `required-checks-gate` uses, and for the same reason: the exit-code mapping
 * and the messages are decisions, and they were unreachable by any test while
 * they sat in the entry file beside a `spawnSync`.
 */
export interface AlertIo {
  /** The raw baseline JSON. */
  readBaseline: () => string;
  /** Fetch the open alerts, returning `gh`'s raw stdout. */
  fetchAlerts: () => string;
  print: (line: string) => void;
  appendSummary: (text: string) => void;
}

const alertMessageOf = (error: unknown): string =>
  error instanceof Error ? error.message : String(error);

/**
 * Compare the open alerts against the baseline. Returns the process exit code
 * rather than setting it: 0 matched · 1 moved · 2 unreadable · 3 misconfigured.
 */
export function runAlertGate(io: AlertIo): number {
  let baseline: AlertBaseline;
  try {
    baseline = parseBaseline(io.readBaseline());
  } catch (error) {
    io.print(`::error::${alertMessageOf(error)}`);
    return error instanceof AlertGateConfigError ? 3 : 2;
  }

  let alerts: Alert[];
  try {
    alerts = parseAlertsResponse(io.fetchAlerts());
  } catch (error) {
    io.print(`::error::could not read the open CodeQL alerts: ${alertMessageOf(error)}`);
    return 2;
  }

  const summary = summarise(alerts);
  const drift = compareAlerts(baseline, summary);
  const report = buildAlertSummary(drift, summary);

  io.appendSummary(report);
  io.print(report);

  for (const { severity, was, now } of drift.risen) {
    io.print(
      `::error::open ${severity} CodeQL alerts rose from ${String(was)} to ${String(now)} — triage them, do not raise the baseline`,
    );
  }
  for (const { severity, was, now } of drift.fallen) {
    io.print(
      `::error::open ${severity} CodeQL alerts fell from ${String(was)} to ${String(now)} — lower the baseline`,
    );
  }

  if (isAlertFailure(drift)) return 1;
  io.print(`Open CodeQL alerts match the baseline: ${String(drift.totalNow)} outstanding.`);
  return 0;
}
