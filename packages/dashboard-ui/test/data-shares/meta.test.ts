import { describe, expect, it } from 'vitest';

import { providerMark } from '../../src/data-shares/meta.ts';

describe('providerMark', () => {
  it('gives every mark of one name the same color', () => {
    expect(providerMark('GitHub').color).toBe(providerMark('GitHub').color);
  });

  it('gives two different names different colors, for at least one pair', () => {
    // The palette has six entries, so a handful of names is guaranteed to
    // reach at least two of them — unless the hash ignores its input or the
    // color is constant, which is what this case exists to catch.
    const names = ['Acme', 'Bolt', 'Corgi', 'Delta', 'Echo', 'Fjord', 'Gamma', 'Hydra'];
    const colors = new Set(names.map((name) => providerMark(name).color));
    expect(colors.size).toBeGreaterThan(1);
  });

  it('derives short from name', () => {
    expect(providerMark('New Relic').short).toBe('NR');
    expect(providerMark('Okta').short).toBe('OK');
  });
});
