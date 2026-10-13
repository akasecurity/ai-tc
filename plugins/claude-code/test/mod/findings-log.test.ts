import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ModFinding } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  appendModFindings,
  findingId,
  findingKey,
  modFindingsFrom,
  modFindingsPath,
  pointersByFinding,
  recordModFindings,
} from '../../src/mod/findings-log.ts';

const match = (ruleId: string, start: number, end: number, rawMatch: string) => ({
  ruleId,
  category: 'secret' as const,
  severity: 'critical' as const,
  span: { start, end },
  rawMatch,
  confidence: 1,
});

const TOKEN = 'gh' + 'p_' + 'a'.repeat(36);
const POINTER = '[[' + 'aka:secret:AE.' + 'A'.repeat(26) + '.' + 'A'.repeat(16) + ']]';

describe('findingId', () => {
  it('is stable for the same event and span, and differs otherwise', () => {
    const a = findingId('s1', 'prompt', `x ${TOKEN}`, 'secrets/github-pat', { start: 2, end: 42 });
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(
      findingId('s1', 'prompt', `x ${TOKEN}`, 'secrets/github-pat', { start: 2, end: 42 }),
    ).toBe(a);
    expect(
      findingId('s2', 'prompt', `x ${TOKEN}`, 'secrets/github-pat', { start: 2, end: 42 }),
    ).not.toBe(a);
  });
});

describe('modFindingsFrom', () => {
  const build = (action: 'vaulted' | 'blocked', pointers?: ReadonlyMap<string, string>) =>
    modFindingsFrom({
      sessionId: 's1',
      kind: 'prompt',
      text: `use ${TOKEN}`,
      result: {
        action: action === 'blocked' ? 'block' : 'redact',
        findings: [match('secrets/github-pat', 4, 44, TOKEN)],
      } as never,
      where: 'prompt',
      action,
      ...(pointers === undefined ? {} : { pointers }),
    });

  it('builds records with the short name and no raw value', () => {
    const records = build(
      'vaulted',
      new Map([[findingKey(match('secrets/github-pat', 4, 44, TOKEN)), POINTER]]),
    );
    expect(records).toHaveLength(1);
    expect(ModFinding.parse(records[0])).toBeTruthy();
    expect(records[0]?.shortName).toBe('GitHub token');
    expect(records[0]?.pointer).toBe(POINTER);
    expect(JSON.stringify(records)).not.toContain(TOKEN);
  });

  const named = (ruleId: string, ruleNames?: Record<string, string>) =>
    modFindingsFrom({
      sessionId: 's1',
      kind: 'prompt',
      text: `use ${TOKEN}`,
      result: {
        action: 'redact',
        findings: [match(ruleId, 4, 44, TOKEN)],
        ...(ruleNames === undefined ? {} : { ruleNames }),
      } as never,
      where: 'prompt',
      action: 'redacted',
    })[0];

  it('labels a rule with no short name by the full name of the rule that matched', () => {
    const record = named('acme/ticket', { 'acme/ticket': 'Acme ticket' });
    expect(record?.shortName).toBe('Acme ticket');
    expect(ModFinding.parse(record)).toBeTruthy();
  });

  it('cuts a long rule name to 64 characters', () => {
    const record = named('acme/ticket', { 'acme/ticket': 'n'.repeat(70) });
    expect(record?.shortName).toBe('n'.repeat(64));
    expect(ModFinding.parse(record)).toBeTruthy();
  });

  it('leaves the label to the rule id when the rule has no name', () => {
    expect(named('acme/ticket')).not.toHaveProperty('shortName');
    expect(named('acme/ticket', { 'acme/ticket': '  ' })).not.toHaveProperty('shortName');
  });

  it('prefers the short name a bundled rule ships', () => {
    expect(
      named('secrets/github-pat', { 'secrets/github-pat': 'GitHub personal access token' })
        ?.shortName,
    ).toBe('GitHub token');
  });

  it('demotes vaulted to redacted when no pointer matches', () => {
    const records = build('vaulted', new Map([['other', POINTER]]));
    expect(records[0]?.action).toBe('redacted');
    expect(records[0]).not.toHaveProperty('pointer');
    expect(ModFinding.parse(records[0])).toBeTruthy();
  });

  it('never attaches a pointer to a non-vaulted action', () => {
    const records = build('blocked', new Map([[TOKEN, POINTER]]));
    expect(records[0]?.action).toBe('blocked');
    expect(records[0]).not.toHaveProperty('pointer');
    expect(ModFinding.parse(records[0])).toBeTruthy();
  });
});

describe('appendModFindings', () => {
  const blocked = () =>
    modFindingsFrom({
      sessionId: 's1',
      kind: 'prompt',
      text: TOKEN,
      result: { action: 'block', findings: [match('secrets/github-pat', 0, 40, TOKEN)] } as never,
      where: 'prompt',
      action: 'blocked',
    });

  it('appends one JSON line per finding, owner-only', () => {
    const dataDir = mkdtempSync(join(tmpdir(), 'aka-mf-'));
    appendModFindings(dataDir, 's1', blocked());
    appendModFindings(dataDir, 's1', blocked());
    const path = modFindingsPath(dataDir, 's1') ?? '';
    const lines = readFileSync(path, 'utf8').trim().split('\n');
    expect(lines).toHaveLength(2);
    if (process.platform !== 'win32') expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it('refuses a session id that would leave the findings folder', () => {
    expect(modFindingsPath('/tmp/x', '../escape')).toBeNull();
    expect(modFindingsPath('/tmp/x', 'a/b')).toBeNull();
    expect(modFindingsPath('/tmp/x', '')).toBeNull();
  });

  it('never throws, even when the folder cannot be created', () => {
    expect(() => {
      appendModFindings('/dev/null/nope', 's1', blocked());
    }).not.toThrow();
  });
});

describe('pointersByFinding', () => {
  const a = match('secrets/github-pat', 0, 4, 'aaaa');
  const b = match('secrets/github-pat', 10, 14, 'bbbb');

  it('pairs pointers with kept findings in span order', () => {
    const map = pointersByFinding([b, a], undefined, ['p1', 'p2']);
    expect(map.get(findingKey(a))).toBe('p1');
    expect(map.get(findingKey(b))).toBe('p2');
  });

  it('never lends a kept pointer to a destroyed finding of the same value', () => {
    const kept = match('secrets/github-pat', 0, 4, 'same');
    const destroyed = match('secrets/github-pat', 10, 14, 'same');
    const text = 'same, and same';
    const records = modFindingsFrom({
      sessionId: 's1',
      kind: 'prompt',
      text,
      result: { action: 'redact', findings: [kept, destroyed] } as never,
      where: 'prompt',
      action: 'vaulted',
      pointers: pointersByFinding([kept, destroyed], new Set([kept]), [POINTER]),
    });
    expect(records.map((r) => [r.action, r.pointer])).toEqual([
      ['vaulted', POINTER],
      ['redacted', undefined],
    ]);
  });

  it('answers nothing when the counts differ', () => {
    expect(pointersByFinding([a, b], undefined, ['p1']).size).toBe(0);
  });
});

describe('recordModFindings', () => {
  it('never throws when a record cannot be built', () => {
    const result = {
      get findings(): never {
        throw new Error('boom');
      },
    };
    expect(
      recordModFindings(tmpdir(), 's1', {
        sessionId: 's1',
        kind: 'prompt',
        text: 'x',
        result: result as never,
        where: 'prompt',
        action: 'blocked',
      }),
    ).toEqual([]);
  });
});
