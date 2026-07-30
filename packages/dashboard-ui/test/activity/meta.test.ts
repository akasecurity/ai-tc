import { Harness } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { HARNESS_IDS, HARNESS_KIND } from '../../src/activity/meta.ts';
import { PROVIDERS } from '../../src/shared/Provider.tsx';

// The harness vocabulary lives in the schema; the filter list, kind labels,
// and lettermarks live here. A harness added upstream can therefore arrive
// without any of the three — these pin all of them to the enum.
describe('HARNESS_IDS', () => {
  it('covers exactly the schema Harness vocabulary', () => {
    expect([...HARNESS_IDS].sort()).toEqual([...Harness.options].sort());
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
