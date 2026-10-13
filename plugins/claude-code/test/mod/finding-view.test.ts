import { describe, expect, it } from 'vitest';

import {
  bandFindings,
  chipText,
  mergeFindings,
  parseFindingRecord,
  parseFindingsJsonl,
  severityStyle,
  statusText,
  type ViewFinding,
} from '../../src/mod/finding-view.ts';

const POINTER = ['[', '[aka:secret:ABCDE.', 'A'.repeat(26), '.', 'B'.repeat(16), ']', ']'].join('');

function view(over: Record<string, unknown> = {}): ViewFinding {
  const f = parseFindingRecord(rec(over));
  if (f === null) throw new Error('fixture is not a finding');
  return f;
}

const rec = (over: Record<string, unknown> = {}) => ({
  v: 1,
  id: 'a1b2c3d4e5f60718',
  at: '2026-10-13T12:00:00.000Z',
  ruleId: 'secrets/github-pat',
  shortName: 'GitHub token',
  category: 'secret',
  severity: 'critical',
  action: 'redacted',
  where: 'prompt',
  ...over,
});

describe('parseFindingRecord', () => {
  it('reads a valid record', () => {
    const f = parseFindingRecord(rec());
    expect(f?.label).toBe('GitHub token');
    expect(f?.at).toBe(Date.parse('2026-10-13T12:00:00.000Z'));
    expect(f?.pointer).toBeUndefined();
  });
  it('falls back to the rule id when there is no short name', () => {
    expect(parseFindingRecord(rec({ shortName: undefined }))?.label).toBe('secrets/github-pat');
  });
  it('labels by rule id when the short name is empty, oversized or not a string', () => {
    for (const shortName of ['', 'x'.repeat(65), 4]) {
      expect(parseFindingRecord(rec({ shortName }))?.label).toBe('secrets/github-pat');
    }
    expect(parseFindingRecord(rec({ shortName: 'x'.repeat(64) }))?.label).toBe('x'.repeat(64));
  });
  it('accepts a category it does not know', () => {
    expect(parseFindingRecord(rec({ category: 'banana' }))?.category).toBe('banana');
  });
  it('reads an unknown severity as low', () => {
    expect(parseFindingRecord(rec({ severity: 'catastrophic' }))?.severity).toBe('low');
  });
  it('refuses a record with a raw value or an extra field', () => {
    expect(parseFindingRecord(rec({ rawMatch: 'x' }))).toBeNull();
    expect(parseFindingRecord(rec({ id: 'nope' }))).toBeNull();
  });
  it('refuses a value that is not a record', () => {
    expect(parseFindingRecord(null)).toBeNull();
    expect(parseFindingRecord([])).toBeNull();
    expect(parseFindingRecord('x')).toBeNull();
  });
  it('refuses a bad version, rule, category, action, where, time, short name or pointer', () => {
    for (const over of [
      { v: 2 },
      { ruleId: '' },
      { category: 3 },
      { action: 'deleted' },
      { where: 'elsewhere' },
      { at: 'yesterday' },
      { at: 5 },
      { category: '' },
      { category: 'a-b' },
      { category: 'A B' },
      { at: '2026' },
      { at: 'Oct 13 2026' },
      { action: 'vaulted', pointer: 'not-a-pointer' },
      { action: 'vaulted', pointer: 7 },
      { action: 'vaulted', pointer: POINTER.replace('secret', 'a-b') },
    ]) {
      expect(parseFindingRecord(rec(over))).toBeNull();
    }
  });
  it('keeps the pointer of a vaulted finding', () => {
    expect(parseFindingRecord(rec({ action: 'vaulted', pointer: POINTER }))?.pointer).toBe(POINTER);
  });
  it('refuses a vaulted finding without a pointer', () => {
    expect(parseFindingRecord(rec({ action: 'vaulted' }))).toBeNull();
  });
  it('refuses a pointer on a finding that is not vaulted', () => {
    expect(parseFindingRecord(rec({ action: 'redacted', pointer: POINTER }))).toBeNull();
  });
});

describe('parseFindingsJsonl', () => {
  it('keeps complete lines and skips a truncated last one', () => {
    const text = `${JSON.stringify(rec())}\n\n${JSON.stringify(rec({ id: 'b1b2c3d4e5f60718' })).slice(0, 30)}`;
    expect(parseFindingsJsonl(text).map((f) => f.id)).toEqual(['a1b2c3d4e5f60718']);
  });
  it('skips a line that parses but is not a finding', () => {
    expect(parseFindingsJsonl('{"v":1}\n[]')).toEqual([]);
  });
});

describe('mergeFindings', () => {
  it('keeps one copy of a finding reported twice, newest first, capped', () => {
    const a = view();
    const b = view({ id: 'b1b2c3d4e5f60718', at: '2026-10-13T12:01:00.000Z' });
    expect(mergeFindings([a], [a, b]).map((f) => f.id)).toEqual([b.id, a.id]);
    expect(mergeFindings([a], [b], 1).map((f) => f.id)).toEqual([b.id]);
  });
});

describe('styles and text', () => {
  it('maps each severity to a theme colour and a word', () => {
    expect(severityStyle('critical')).toEqual({ color: 'error', word: 'CRITICAL' });
    expect(severityStyle('high')).toEqual({ color: 'warning', word: 'HIGH' });
    expect(severityStyle('medium')).toEqual({ color: 'suggestion', word: 'MEDIUM' });
    expect(severityStyle('low')).toEqual({ color: 'inactive', word: 'LOW' });
  });
  it('writes a chip', () => {
    const f = view({ action: 'vaulted', pointer: POINTER });
    expect(chipText(f)).toBe('CRITICAL  GitHub token · vaulted · prompt');
  });
  it('shows at most three recent findings in the band', () => {
    const now = Date.parse('2026-10-13T12:01:00.000Z');
    const many = [0, 1, 2, 3, 4].map((i) =>
      view({ id: `a1b2c3d4e5f6071${String(i)}`, at: '2026-10-13T12:00:30.000Z' }),
    );
    const old = view({ id: 'c1b2c3d4e5f60718', at: '2026-10-13T11:50:00.000Z' });
    const band = bandFindings([...many, old], now);
    expect(band.shown).toHaveLength(3);
    expect(band.more).toBe(2);
  });
  it('leaves a finding from the future out of the band', () => {
    const f = view();
    expect(bandFindings([f], f.at - 1)).toEqual({ shown: [], more: 0 });
  });
  it('counts by severity in the status line', () => {
    const fs = [
      rec({ id: 'a000000000000001' }),
      rec({ id: 'a000000000000002' }),
      rec({ id: 'a000000000000003', severity: 'high' }),
      rec({ id: 'a000000000000004', severity: 'low' }),
    ].map((r) => view(r));
    expect(statusText(fs, 'in-place')).toBe(
      'AKA · redacting in place · 2 critical  1 high  1 other',
    );
  });
});
