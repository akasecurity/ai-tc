import { randomUUID } from 'node:crypto';

import type { DetectedFindingWithKey, IngestEvent } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../../src/database.ts';
import { corpusConnection } from '../helpers/corpus.ts';
import { useTempStore } from '../helpers/temp-store.ts';

const store = useTempStore('aka-finding-variable-name-', { migrated: true });
let db: LocalDatabase;

beforeEach(() => {
  db = store.open();
});

const NAME = ['STRIPE', 'SECRET', 'KEY'].join('_');
const TEXT = [NAME, '[REDACTED:SECRET]'].join(String.fromCharCode(61));

function record(variableName: string | undefined, findingKey?: string): string {
  const event: IngestEvent = {
    id: randomUUID(),
    sourceTool: 'claude-code',
    kind: 'code_change',
    occurredAt: new Date().toISOString(),
    contentHash: randomUUID(),
    content: TEXT,
    metadata: { filePath: '/repo/.env' },
  };
  const start = NAME.length + 1;
  const finding: DetectedFindingWithKey = {
    id: randomUUID(),
    eventId: event.id,
    ruleId: 'secrets-infra/env-key-value',
    category: 'secret',
    severity: 'high',
    span: { start, end: TEXT.length },
    maskedMatch: 's*********2',
    actionTaken: 'redact',
    confidence: 0.9,
    ...(findingKey === undefined ? {} : { findingKey }),
    ...(variableName === undefined ? {} : { variableName }),
  };
  db.recordCapture(event, [finding]);
  return finding.id;
}

function nameOf(where: string, param: string): unknown {
  const row = corpusConnection(db)
    .prepare(`SELECT variable_name FROM inspection_findings WHERE ${where} = ?`)
    .get(param) as Record<string, unknown>;
  return row.variable_name;
}

describe('recordCapture — variable name', () => {
  it('stores the variable name a secret was assigned to', () => {
    expect(nameOf('id', record(NAME))).toBe(NAME);
  });

  it('stores null for a finding with no variable name', () => {
    expect(nameOf('id', record(undefined))).toBeNull();
  });

  it('follows a re-detected at-rest finding', () => {
    record(undefined, 'key-env');
    expect(nameOf('finding_key', 'key-env')).toBeNull();
    record(NAME, 'key-env');
    expect(nameOf('finding_key', 'key-env')).toBe(NAME);
  });

  it('hands the name to the recent-findings read, and omits it when absent', async () => {
    record(undefined);
    record(NAME);
    const [newest, older] = await db.findings.recentFindings({ limit: 2 });
    const views = [newest, older];
    expect(views.find((v) => v?.variableName === NAME)).toBeDefined();
    expect(views.filter((v) => v !== undefined && !('variableName' in v))).toHaveLength(1);
  });
});
