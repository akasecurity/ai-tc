import { Harness } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { HARNESS_IDS, HARNESS_KIND } from '../../src/activity/meta.ts';
import { PROVIDERS } from '../../src/shared/Provider.tsx';

// The harness vocabulary lives in the schema; the filter list, kind labels,
// and lettermarks live here. A harness added upstream can therefore arrive
// without any of the three — these pin all of them to the enum.
describe('HARNESS_IDS', () => {
  // Membership is derived, so it needs no assertion — HARNESS_IDS IS
  // Object.values(HARNESS), and Harness.options is the same expression over the
  // same object. Comparing the two therefore holds under every possible change
  // to the registry, including the one that matters: HarnessSelect renders this
  // sequence as the filter's display order, so swapping two members in a schema
  // file silently reorders the dashboard.
  //
  // The literal below is what makes that visible. It is deliberately a second
  // spelling of the order — the one thing this file pins that the registry
  // cannot pin for itself — and adding a harness upstream is MEANT to fail here,
  // so the decision about where it appears in the filter is made by someone
  // rather than inherited from a declaration order.
  it('lists every harness the registry defines, in the filter display order', () => {
    expect([...HARNESS_IDS]).toEqual([
      'claudecode',
      'cursor',
      'copilot',
      'codex',
      'antigravity',
      'windsurf',
      'claudedesktop',
      'chatgpt',
      'claudeai',
      'api',
    ]);
    // Membership stays derived: the literal above may reorder the vocabulary but
    // may not drop or invent a member.
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
