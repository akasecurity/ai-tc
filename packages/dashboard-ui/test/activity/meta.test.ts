import { Harness } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { HARNESS_IDS, HARNESS_KIND } from '../../src/activity/meta.ts';
import { PROVIDERS } from '../../src/shared/Provider.tsx';

// The harness vocabulary lives in the schema; the filter list, kind labels,
// and lettermarks live here. A harness added upstream can therefore arrive
// without any of the three — these pin all of them to the enum.
describe('HARNESS_IDS', () => {
  // Order, not membership. HARNESS_IDS derives from the registry, so a sorted
  // set comparison is satisfied by construction and would stay green if the
  // list went back to being hand-written in some other order — while
  // HarnessSelect treats this as the canonical display order. Comparing the
  // sequence is what still fails on that.
  it('is exactly the schema Harness vocabulary, in its declared order', () => {
    expect([...HARNESS_IDS]).toEqual([...Harness.options]);
  });

  it('gives every harness a non-empty kind label', () => {
    for (const id of HARNESS_IDS) {
      expect(HARNESS_KIND[id].trim()).not.toBe('');
    }
  });

  it('gives every harness a PROVIDERS lettermark entry', () => {
    for (const id of HARNESS_IDS) {
      expect(PROVIDERS[id]).toBeDefined();
    }
  });
});
