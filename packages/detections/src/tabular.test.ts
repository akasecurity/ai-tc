import { extractCsv } from '@aka/extract';
import { Rule as RuleSchema } from '@aka/schema';
import { describe, expect, it } from 'vitest';

import { scanTabular } from './tabular.ts';

const ssnRule = RuleSchema.parse({
  specVersion: 1,
  id: 'test/ssn',
  name: 'SSN',
  category: 'pii',
  severity: 'high',
  matcher: { type: 'regex', pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b', flags: 'g' },
});

// Gated: a bare date only counts as a DOB when a birth label is nearby.
const dobRule = RuleSchema.parse({
  specVersion: 1,
  id: 'test/dob',
  name: 'DOB',
  category: 'pii',
  severity: 'high',
  matcher: { type: 'regex', pattern: '\\b\\d{4}-\\d{2}-\\d{2}\\b', flags: 'g' },
  requiresNearby: { labels: ['dob', 'date of birth', 'birth'], windowChars: 40 },
});

const rules = [ssnRule, dobRule];

describe('scanTabular', () => {
  it('maps value matches to column/row and uses the header as gating context', () => {
    const table = {
      columns: ['first_name', 'dob', 'ssn'],
      rows: [['Alice', '1990-05-01', '123-45-6789']],
    };
    const found = scanTabular(table, rules);

    // SSN value match in the ssn column.
    expect(found).toContainEqual(
      expect.objectContaining({
        column: 'ssn',
        rowIndex: 0,
        ruleId: 'test/ssn',
        viaHeaderCue: false,
      }),
    );
    // The gated DOB rule fires because the `dob` header prefixes the value.
    expect(found).toContainEqual(
      expect.objectContaining({ column: 'dob', ruleId: 'test/dob', viaHeaderCue: false }),
    );
    // A name has no value pattern, but the column header flags it.
    expect(found).toContainEqual(
      expect.objectContaining({
        column: 'first_name',
        match: 'Alice',
        ruleId: 'header-cue',
        viaHeaderCue: true,
        category: 'pii',
      }),
    );
  });

  it('normalizes snake_case headers so whitespace-based label regexes can match', () => {
    const memberIdRule = RuleSchema.parse({
      specVersion: 1,
      id: 'test/member-id',
      name: 'Member ID',
      category: 'phi',
      severity: 'high',
      matcher: {
        type: 'regex',
        pattern: '\\bmember\\s*(?:id|number|no|#)\\s*[:#]?\\s*[A-Za-z0-9]{6,20}\\b',
        flags: 'gi',
      },
    });

    const table = { columns: ['member_id'], rows: [['ABC987654321']] };
    const found = scanTabular(table, [memberIdRule]);

    expect(found).toContainEqual(
      expect.objectContaining({ column: 'member_id', ruleId: 'test/member-id', viaHeaderCue: false }),
    );
  });

  it('does not fire the gated DOB rule when the column header lacks the label', () => {
    const table = { columns: ['col_x'], rows: [['1990-05-01']] };
    const found = scanTabular(table, rules).filter((f) => f.ruleId === 'test/dob');
    expect(found).toHaveLength(0);
  });

  it('end-to-end: extractCsv -> scanTabular detects PII across rows', () => {
    const csv = 'first_name,dob,ssn\nAlice,1990-05-01,123-45-6789\nBob,1985-12-30,987-65-4321';
    const ext = extractCsv(csv);
    const found = scanTabular({ columns: ext.columns, rows: ext.rows }, rules);

    expect(found.filter((f) => f.ruleId === 'test/ssn')).toHaveLength(2);
    expect(found.filter((f) => f.column === 'first_name' && f.viaHeaderCue)).toHaveLength(2);
    expect(found.filter((f) => f.ruleId === 'test/dob')).toHaveLength(2);
  });
});
