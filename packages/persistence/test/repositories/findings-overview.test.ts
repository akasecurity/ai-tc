import { randomUUID } from 'node:crypto';

import type {
  DetectedFindingWithKey,
  EventKind,
  ListFindingInstancesQuery,
  ResolutionMethod,
} from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { SqliteFindingsRepository } from '../../src/repositories/findings.ts';
import { captureEvent, captureFinding } from '../helpers/capture-fixtures.ts';
import { explain, type RecordedQuery, recordingConnection } from '../helpers/query-plans.ts';
import { useTempStore } from '../helpers/temp-store.ts';

// findingsOverview feeds the Findings page's summary strip. Its whole contract
// is that each number is the one the list beneath it would show under that
// filter alone, so the suite asserts the numbers AND that agreement.
//
// The fixture straddles every field: each count is a strict subset of the
// total and differs from every other count, so a field reading the wrong
// status or no predicate at all lands on a different number.

const NOW = Date.parse('2026-06-29T12:00:00.000Z');

const store = useTempStore('aka-findings-overview-', { migrated: true });
let db: LocalDatabase;

beforeEach(() => {
  db = store.open();
});

// One finding on its own capture. The shared builders give every call a
// distinct masked value, which is what keeps the store's session dedup from
// collapsing two fixture rows into one.
function record(opts: { kind: EventKind; findingKey?: string }): void {
  const { kind } = opts;
  const event = captureEvent({
    kind,
    ...(kind === 'code_change' ? { metadata: { filePath: `/tmp/${randomUUID()}.ts` } } : {}),
  });
  const finding: DetectedFindingWithKey = {
    ...captureFinding(event.id),
    ...(opts.findingKey ? { findingKey: opts.findingKey } : {}),
  };
  db.recordCapture(event, [finding]);
}

type ResolutionStatus = 'resolved' | 'dismissed' | 'open';

const METHOD_FOR: Record<ResolutionStatus, ResolutionMethod> = {
  resolved: 'fixed-at-source',
  dismissed: 'false-positive',
  open: 'redetected',
};

function resolve(findingKey: string, status: ResolutionStatus): void {
  db.resolutions.insertResolution({
    findingKey,
    status,
    method: METHOD_FOR[status],
    resolvedAt: NOW,
    evidence: '{}',
  });
}

// A transcript-reconciler finding: it sits in the same tables but on a
// non-capture `tool_call` row, which the Findings list never shows. The status
// classifier reads any kind but `code_change` as handled, so counting it would
// move two fields: `findings` and `handled`.
function seedTranscriptFinding(): void {
  const raw = store.openRaw();
  raw
    .prepare(
      `INSERT INTO inspection_definitions
         (id, rule_id, name, category, severity, definition, version)
       VALUES ('def-transcript', 'transcript-rule', 'transcript-rule', 'secret', 'critical', '{}', '1')`,
    )
    .run();
  raw
    .prepare(
      `INSERT INTO audit_events (id, event_type, started_at, content)
       VALUES ('ev-transcript', 'tool_call', 0, '')`,
    )
    .run();
  raw
    .prepare(
      `INSERT INTO inspection_findings
         (id, audit_event_id, inspection_definition_id, span_start, span_end,
          masked_match, action_taken, confidence)
       VALUES ('f-transcript', 'ev-transcript', 'def-transcript', 0, 1, '••', 'block', 1)`,
    )
    .run();
}

function seedStraddlingFixture(): void {
  // In-flight, across every live capture kind: born handled. Four of them, so
  // the handled count collides with no other field.
  record({ kind: 'prompt' });
  record({ kind: 'response' });
  record({ kind: 'tool_use' });
  record({ kind: 'prompt' });
  // At-rest, never resolved: open.
  record({ kind: 'code_change', findingKey: 'k-open' });
  // At-rest, fixed at source: resolved.
  record({ kind: 'code_change', findingKey: 'k-res' });
  resolve('k-res', 'resolved');
  // At-rest, dismissed. Two of them, so the dismissed count does not collide
  // with the resolved one.
  record({ kind: 'code_change', findingKey: 'k-dis-1' });
  resolve('k-dis-1', 'dismissed');
  record({ kind: 'code_change', findingKey: 'k-dis-2' });
  resolve('k-dis-2', 'dismissed');
  // At-rest, legacy row with no key: the list calls it open.
  record({ kind: 'code_change' });
  // At-rest, resolved and then redetected: the latest row wins, so open again.
  record({ kind: 'code_change', findingKey: 'k-redet' });
  resolve('k-redet', 'resolved');
  resolve('k-redet', 'open');

  seedTranscriptFinding();
}

describe('SqliteFindingsRepository.findingsOverview', () => {
  it('counts every capture finding once per field it belongs to', async () => {
    seedStraddlingFixture();

    expect(await db.findings.findingsOverview()).toEqual({
      findings: 10,
      open: 3,
      handled: 4,
      resolved: 1,
      dismissed: 2,
    });
  });

  // Every finding has exactly one status, so the four status cells account for
  // the whole Findings count and nothing on the strip is left unexplained.
  it('adds the four statuses up to the findings count', async () => {
    seedStraddlingFixture();

    const { findings, open, handled, resolved, dismissed } = await db.findings.findingsOverview();
    expect(findings).toBeGreaterThan(0);
    expect(open + handled + resolved + dismissed).toBe(findings);
  });

  // The property the strip exists for: each number is what the flat list
  // totals under that one filter. Asserted against the list itself rather than
  // restated, so a change to how the list classifies a finding moves both or
  // fails here.
  it.for<
    [
      keyof Awaited<ReturnType<LocalDatabase['findings']['findingsOverview']>>,
      ListFindingInstancesQuery,
    ]
  >([
    ['findings', {}],
    ['open', { status: ['open'] }],
    ['handled', { status: ['handled'] }],
    ['resolved', { status: ['resolved'] }],
    ['dismissed', { status: ['dismissed'] }],
  ])('%s equals the flat list total for that filter', async ([field, query]) => {
    seedStraddlingFixture();

    const overview = await db.findings.findingsOverview();
    const list = await db.findings.listFindingInstances(query);
    expect(list.totals.findings).toBeGreaterThan(0);
    expect(overview[field]).toBe(list.totals.findings);
  });

  // The event side is answered from the capture-kind rollup index alone. A
  // field store's audit_events rows are mostly body overflow pages, so a plan
  // that starts fetching them costs per finding what made /security slow. The
  // store never runs ANALYZE, and neither does this fixture, so this is the
  // plan a real store gets.
  it('reads the event side from the covering rollup index, never the event rows', async () => {
    seedStraddlingFixture();

    const raw = store.openRaw();
    const recorded: RecordedQuery[] = [];
    await new SqliteFindingsRepository(recordingConnection(raw, recorded)).findingsOverview();
    expect(recorded).toHaveLength(1);
    const [query] = recorded;
    if (query === undefined) throw new Error('findingsOverview issued no statement');

    const steps = explain(raw, query).map((row) => row.detail);
    const eventStep = steps.find((detail) => /^(SEARCH|SCAN) e\b/.test(detail));
    expect(eventStep, steps.join('\n')).toMatch(/USING COVERING INDEX idx_audit_capture_rollup\b/);
  });

  it('reads all zeros from an empty store', async () => {
    expect(await db.findings.findingsOverview()).toEqual({
      findings: 0,
      open: 0,
      handled: 0,
      resolved: 0,
      dismissed: 0,
    });
  });
});
