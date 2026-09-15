import { describe, expect, it } from 'vitest';

import { providerMark } from '../../src/data-shares/meta.ts';

describe('providerMark', () => {
  it('keys the color on colorKey, so two names sharing one key get the same color', () => {
    expect(providerMark('GitHub', 'github').color).toBe(providerMark('GitHub Raw', 'github').color);
  });

  it('keys the color on colorKey rather than on name, for any two names sharing it', () => {
    expect(providerMark('x', 'github').color).toBe(providerMark('y', 'github').color);
  });

  it('lets the colorKey move the color for one fixed name', () => {
    // The palette has six entries, so a handful of keys is guaranteed to reach
    // at least two of them — unless the key is ignored or the color is constant,
    // which is what this case exists to catch.
    const keys = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l'];
    const colors = new Set(keys.map((key) => providerMark('GitHub', key).color));
    expect(colors.size).toBeGreaterThan(1);
  });

  it('derives short from name regardless of colorKey', () => {
    expect(providerMark('New Relic', 'github').short).toBe('NR');
    expect(providerMark('New Relic', 'gitlab').short).toBe('NR');
    expect(providerMark('New Relic').short).toBe('NR');
  });

  it('falls back to hashing the name when no colorKey is given', () => {
    // Omitting the key is the same as passing the name as the key, and a
    // different name reaches a different color for at least one of these.
    expect(providerMark('Acme').color).toBe(providerMark('Acme', 'Acme').color);
    const names = ['Acme', 'Bolt', 'Corgi', 'Delta', 'Echo', 'Fjord', 'Gamma', 'Hydra'];
    const colors = new Set(names.map((name) => providerMark(name).color));
    expect(colors.size).toBeGreaterThan(1);
  });
});
