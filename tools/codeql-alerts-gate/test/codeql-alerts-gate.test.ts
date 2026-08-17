import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  type Alert,
  type AlertBaseline,
  AlertGateConfigError,
  buildAlertSummary,
  compareAlerts,
  isAlertFailure,
  parseBaseline,
  severityOf,
  summarise,
} from '../src/lib.ts';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));

const alert = (severity: string, ruleId = 'js/path-injection'): Alert => ({
  rule: { id: ruleId, security_severity_level: severity },
});

const baseline = (total: number, bySeverity: Record<string, number>): AlertBaseline => ({
  total,
  bySeverity,
});

describe('parseBaseline', () => {
  it('reads the total and the per-severity counts', () => {
    expect(parseBaseline('{"total":3,"bySeverity":{"high":2,"medium":1}}')).toEqual({
      total: 3,
      bySeverity: { high: 2, medium: 1 },
    });
  });

  // Neither default is safe, and one of them is silently dangerous: read as
  // zero a broken baseline fails every run, but read as absent-or-huge it
  // PASSES every run, which is the state this gate exists to end.
  it('refuses a baseline it cannot read rather than defaulting', () => {
    expect(() => parseBaseline('not json')).toThrow(AlertGateConfigError);
    expect(() => parseBaseline('{"bySeverity":{}}')).toThrow(/integer "total"/);
    expect(() => parseBaseline('{"total":1}')).toThrow(/"bySeverity" object/);
    expect(() => parseBaseline('{"total":-1,"bySeverity":{}}')).toThrow(/integer "total"/);
    expect(() => parseBaseline('{"total":1,"bySeverity":{"high":"2"}}')).toThrow(/"high" count/);
  });

  // The shipped file, so the reader and the record cannot drift apart.
  it('reads the repository’s own baseline', () => {
    const parsed = parseBaseline(
      readFileSync(`${REPO_ROOT}/.github/codeql-alert-baseline.json`, 'utf8'),
    );
    // The per-severity counts must add up to the total, or the two halves of
    // the gate disagree about the same tree and one of them is always wrong.
    const summed = Object.values(parsed.bySeverity).reduce((a, b) => a + b, 0);
    expect(summed).toBe(parsed.total);
  });
});

describe('severityOf', () => {
  it('prefers the security severity a security query reports', () => {
    expect(severityOf({ rule: { security_severity_level: 'high', severity: 'warning' } })).toBe(
      'high',
    );
  });

  // The workflow-permissions rule is the live example: it is not a security
  // query, so it carries only `severity`.
  it('falls back to the plain severity a non-security query carries', () => {
    expect(severityOf({ rule: { severity: 'medium' } })).toBe('medium');
  });

  // Counted, never dropped. A dropped class can grow without moving the total,
  // and the total is the number this whole gate rests on.
  it('counts an alert carrying neither rather than dropping it', () => {
    expect(severityOf({})).toBe('unknown');
    expect(summarise([{}]).total).toBe(1);
  });
});

describe('compareAlerts', () => {
  it('is quiet when the counts match the baseline exactly', () => {
    const drift = compareAlerts(
      baseline(2, { high: 2 }),
      summarise([alert('high'), alert('high')]),
    );
    expect(isAlertFailure(drift)).toBe(false);
  });

  // The failure the gate exists for.
  it('fails when a severity count rises', () => {
    const drift = compareAlerts(
      baseline(1, { high: 1 }),
      summarise([alert('high'), alert('high')]),
    );
    expect(drift.risen).toEqual([{ severity: 'high', was: 1, now: 2 }]);
    expect(isAlertFailure(drift)).toBe(true);
  });

  // The good direction, failing on purpose — same ratchet every other allowance
  // in this repository uses. Fix eight alerts under a one-way gate and the
  // baseline now silently permits eight new ones.
  it('fails when a severity count falls, so the baseline gets lowered', () => {
    const drift = compareAlerts(baseline(2, { high: 2 }), summarise([alert('high')]));
    expect(drift.fallen).toEqual([{ severity: 'high', was: 2, now: 1 }]);
    expect(isAlertFailure(drift)).toBe(true);
  });

  // A total alone is blind to this: one high fixed and one medium introduced
  // leaves 2 == 2 while the tree changed in both directions at once.
  it('sees a swap that leaves the total unchanged', () => {
    const drift = compareAlerts(
      baseline(2, { high: 2 }),
      summarise([alert('high'), alert('medium')]),
    );
    expect(drift.totalNow).toBe(drift.totalWas);
    expect(drift.risen).toEqual([{ severity: 'medium', was: 0, now: 1 }]);
    expect(drift.fallen).toEqual([{ severity: 'high', was: 2, now: 1 }]);
    expect(isAlertFailure(drift)).toBe(true);
  });

  // Iterating either key set alone misses one end of this: a brand-new severity
  // is absent from the baseline, and a fully-fixed one is absent from the live
  // summary. Both are the interesting cases.
  it('sees a severity that is new, and one that disappeared entirely', () => {
    const appeared = compareAlerts(baseline(0, {}), summarise([alert('critical')]));
    expect(appeared.risen).toEqual([{ severity: 'critical', was: 0, now: 1 }]);

    const gone = compareAlerts(baseline(1, { low: 1 }), summarise([]));
    expect(gone.fallen).toEqual([{ severity: 'low', was: 1, now: 0 }]);
  });

  // The per-severity counts can all match while the total does not, if a
  // baseline is edited by hand and only half updated. Catch it rather than
  // reporting a clean run against a record that contradicts itself.
  it('fails when the total disagrees even though every severity matches', () => {
    const drift = compareAlerts(baseline(99, { high: 1 }), summarise([alert('high')]));
    expect(drift.risen).toEqual([]);
    expect(drift.fallen).toEqual([]);
    expect(isAlertFailure(drift)).toBe(true);
  });
});

describe('buildAlertSummary', () => {
  it('reports the by-rule breakdown, which is never gated on', () => {
    const summary = summarise([alert('high', 'js/polynomial-redos'), alert('high')]);
    const report = buildAlertSummary(compareAlerts(baseline(2, { high: 2 }), summary), summary);
    expect(report).toContain('js/polynomial-redos');
    expect(report).toContain('js/path-injection');
  });

  // The one response that would defeat the gate is raising the baseline to
  // absorb a new alert, so the failure text has to say so where it is read.
  it('tells the reader not to raise the baseline when the count rose', () => {
    const summary = summarise([alert('high'), alert('high')]);
    const report = buildAlertSummary(compareAlerts(baseline(1, { high: 1 }), summary), summary);
    expect(report).toContain('went UP');
    // Case-insensitive: the instruction is sentence-initial, so pinning the
    // lower-case spelling would fail on wording that is perfectly correct.
    expect(report.toLowerCase()).toContain('do not raise the baseline');
    expect(report.toLowerCase()).toContain('dismiss');
  });

  it('tells the reader to lower the baseline when the count fell', () => {
    const summary = summarise([alert('high')]);
    const report = buildAlertSummary(compareAlerts(baseline(2, { high: 2 }), summary), summary);
    expect(report).toContain('went DOWN');
    expect(report).toContain('.github/codeql-alert-baseline.json');
  });

  // A quiet run must not read as an endorsement. The counts it prints are
  // untriaged findings, and the report is the only place anyone sees them.
  it('says the unchanged counts are outstanding work rather than an accepted level', () => {
    const summary = summarise([alert('high')]);
    const report = buildAlertSummary(compareAlerts(baseline(1, { high: 1 }), summary), summary);
    expect(report).toContain('outstanding work, not an');
  });
});

// Regressions from the xhigh review of this change.
describe('baseline shapes the review found unguarded', () => {
  // `typeof [] === 'object'`, so an array satisfied the old check and parsed
  // into severities named '0', '1', … Every real severity then read as
  // risen-from-zero and the failure named severities that do not exist.
  it('refuses a bySeverity written as an array', () => {
    expect(() => parseBaseline('{"total":26,"bySeverity":[25,1]}')).toThrow(AlertGateConfigError);
  });

  // A half-finished hand edit — the exact edit the two-way ratchet asks for —
  // otherwise reached compare() as a real baseline and failed on the total
  // alone, with no section and no annotation naming the cause.
  it('refuses a baseline whose severities do not add up to its total', () => {
    expect(() => parseBaseline('{"total":30,"bySeverity":{"high":25,"medium":1}}')).toThrow(
      /add up to 26 but its total says 30/,
    );
  });
});

describe('buildAlertSummary explains a totals-only mismatch', () => {
  // Unreachable from a parsed baseline now, and kept because a failure this
  // gate cannot explain is worse than one it never detects: before the fix the
  // report rendered no section at all and check-alerts.ts emitted no
  // annotation, so the job went red showing output that looked healthy.
  it('names the contradiction rather than failing silently', () => {
    const summary = summarise([{ rule: { id: 'r', security_severity_level: 'high' } }]);
    const drift = compareAlerts({ total: 99, bySeverity: { high: 1 } }, summary);
    expect(isAlertFailure(drift)).toBe(true);
    const report = buildAlertSummary(drift, summary);
    expect(report).toContain('totals disagree');
    expect(report).toContain('codeql-alert-baseline.json');
  });
});
