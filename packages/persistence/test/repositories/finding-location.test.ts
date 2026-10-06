import { randomUUID } from 'node:crypto';

import type { DetectedFindingWithKey, FindingContext, IngestEvent } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { SqliteFindingsRepository } from '../../src/repositories/findings.ts';
import { corpusConnection } from '../helpers/corpus.ts';
import type { RecordedQuery } from '../helpers/query-plans.ts';
import { recordingConnection } from '../helpers/query-plans.ts';
import { useTempStore } from '../helpers/temp-store.ts';

// Where a finding sits in the text it was detected in — line, column and the
// masked excerpt — as the store writes it and as each read hands it on.

const store = useTempStore('aka-finding-location-', { migrated: true });
let db: LocalDatabase;

beforeEach(() => {
  db = store.open();
});

const EXCERPT: FindingContext = {
  basis: 'file',
  firstLine: 3,
  lines: ['const a = 1;', 'element.innerHTML = userInput;', 'const b = 2;'],
  match: { line: 4, start: 8, end: 19 },
};

const TEXT = ['one', 'two', 'const a = 1;', 'element.innerHTML = userInput;', 'const b = 2;'].join(
  '\n',
);

function recordOne(location: DetectedFindingWithKey['location'], filePath = '/repo/src/a.ts') {
  const event: IngestEvent = {
    id: randomUUID(),
    sourceTool: 'claude-code',
    kind: 'code_change',
    occurredAt: new Date().toISOString(),
    contentHash: randomUUID(),
    content: TEXT,
    metadata: { filePath, toolName: 'Write' },
  };
  const start = TEXT.indexOf('innerHTML');
  const finding: DetectedFindingWithKey = {
    id: randomUUID(),
    eventId: event.id,
    ruleId: 'code-flaws/xss-inner-html',
    category: 'code_flaw',
    severity: 'high',
    span: { start, end: start + 'innerHTML ='.length },
    maskedMatch: 'i*********=',
    actionTaken: 'log',
    confidence: 0.8,
    ...(location === undefined ? {} : { location }),
  };
  db.recordCapture(event, [finding]);
  return finding.id;
}

function columnsOf(id: string) {
  return corpusConnection(db)
    .prepare(`SELECT line, col, context FROM inspection_findings WHERE id = ?`)
    .get(id) as { line: number | null; col: number | null; context: string | null };
}

describe('recordCapture — finding location', () => {
  it('stores the line, the column and the excerpt as JSON', () => {
    const id = recordOne({ line: 4, col: 9, context: EXCERPT });
    const row = columnsOf(id);
    expect(row.line).toBe(4);
    expect(row.col).toBe(9);
    expect(JSON.parse(row.context ?? 'null')).toEqual(EXCERPT);
  });

  it('stores a position with no excerpt when none could be built', () => {
    const id = recordOne({ line: 4, col: 9, context: null });
    expect(columnsOf(id)).toEqual({ line: 4, col: 9, context: null });
  });

  it('stores nothing for a finding recorded without a location', () => {
    const id = recordOne(undefined);
    expect(columnsOf(id)).toEqual({ line: null, col: null, context: null });
  });
});

describe('the findings list — position, never the excerpt', () => {
  it('carries the line and column on each row', async () => {
    const id = recordOne({ line: 4, col: 9, context: EXCERPT });
    const res = await db.findings.listFindingInstances({});
    const row = res.items.find((item) => item.id === id);
    expect(row?.line).toBe(4);
    expect(row?.col).toBe(9);
    // The excerpt is fetched for the open finding only.
    expect(row?.match.context).toBeUndefined();
  });

  it('reads neither the excerpt nor the event text', async () => {
    recordOne({ line: 4, col: 9, context: EXCERPT });
    const recorded: RecordedQuery[] = [];
    const repo = new SqliteFindingsRepository(recordingConnection(corpusConnection(db), recorded));
    const res = await repo.listFindingInstances({});
    // Control: the read ran and returned the row.
    expect(res.items).toHaveLength(1);
    expect(recorded.length).toBeGreaterThan(0);
    for (const query of recorded) {
      expect(query.sql).not.toMatch(/\bf\.context\b/);
      expect(query.sql).not.toMatch(/\be\.content\b/);
    }
  });
});

describe('findingContextSource — what the drawer reads one finding from', () => {
  it('returns the stored excerpt, the event text and the offsets', () => {
    const id = recordOne({ line: 4, col: 9, context: EXCERPT });
    const source = db.findings.findingContextSource(id);
    expect(JSON.parse(source?.context ?? 'null')).toEqual(EXCERPT);
    expect(source?.content).toBe(TEXT);
    expect(source?.spanStart).toBe(TEXT.indexOf('innerHTML'));
    expect(source?.ruleId).toBe('code-flaws/xss-inner-html');
    expect(source?.category).toBe('code_flaw');
    expect(source?.toolName).toBe('Write');
    expect(source?.wholeFile).toBe(false);
  });

  it('returns null for an id that names no finding', () => {
    expect(db.findings.findingContextSource('no-such-finding')).toBeNull();
  });
});
