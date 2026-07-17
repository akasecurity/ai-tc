import { describe, expect, it } from 'vitest';

import { langColor, rollup } from '../../src/inventory/data.ts';

describe('rollup', () => {
  it('counts flags and orders them by FLAG_ORDER severity', () => {
    const parts = rollup([
      { flags: ['stale'] },
      { flags: ['risk', 'stale'] },
      { flags: ['conflict'] },
      { flags: [] },
    ]);
    expect(parts).toEqual([
      { key: 'risk', count: 1 },
      { key: 'conflict', count: 1 },
      { key: 'stale', count: 2 },
    ]);
  });

  it('omits the project-only "findings" flag (not in FLAG_ORDER)', () => {
    expect(rollup([{ flags: ['findings'] }])).toEqual([]);
  });
});

describe('langColor', () => {
  it('maps known languages case-insensitively', () => {
    expect(langColor('TypeScript')).toBe('#3178C6');
    expect(langColor('rust')).toBe('#DEA584');
  });

  it('falls back to a neutral token for unknown languages', () => {
    expect(langColor('Brainfuck')).toBe('var(--color-border-strong)');
  });
});
