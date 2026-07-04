import { describe, expect, it } from 'vitest';

import {
  matcherSummary,
  PLACEHOLDER_POLICY,
  policyMeta,
  provenanceState,
  toneColors,
} from './meta.ts';

describe('matcherSummary', () => {
  it('renders each matcher kind as a one-line summary', () => {
    expect(matcherSummary({ type: 'regex', pattern: '\\d+', flags: 'g' })).toBe('/\\d+/g');
    expect(
      matcherSummary({ type: 'keyword', keywords: ['aws', 'gcp'], caseSensitive: false }),
    ).toBe('aws · gcp');
    expect(matcherSummary({ type: 'validator', name: 'luhn' })).toBe('luhn');
  });
});

describe('policyMeta', () => {
  it('resolves each built-in policy id to its label', () => {
    expect(policyMeta('monitor').label).toBe('Monitor');
    expect(policyMeta('block').label).toBe('Block');
  });

  it('falls back to a neutral entry for an unknown id (keeping the id as label)', () => {
    const m = policyMeta('mystery');
    expect(m.label).toBe('mystery');
    expect(m.tone).toBe('gray');
  });

  it('defaults unassigned detections to monitor', () => {
    expect(PLACEHOLDER_POLICY).toBe('monitor');
    expect(policyMeta(PLACEHOLDER_POLICY).label).toBe('Monitor');
  });

  // Regression: a custom policy id can be any string, including one that collides
  // with an Object.prototype member. Without an Object.hasOwn guard, POLICY_META[id]
  // resolves the inherited function (truthy, so ?? never fires), the tone comes back
  // undefined, and toneColors([undefined]) throws — crashing the whole Policies page.
  it.each(['constructor', 'toString', 'hasOwnProperty', '__proto__'])(
    'resolves the prototype-polluting id %j to the safe neutral fallback',
    (id) => {
      const m = policyMeta(id);
      expect(m.label).toBe(id);
      expect(m.tone).toBe('gray');
      // The destructure that crashed the page must succeed on the fallback tone.
      expect(toneColors(m.tone)).toHaveLength(2);
    },
  );

  it('renders a custom policy distinctly from the Monitor builtin (own icon)', () => {
    // The fallback must NOT reuse Monitor's icon, or a custom script reads as the
    // log-only Monitor policy in the list and detail header.
    expect(policyMeta('my-custom-script').icon).not.toBe(policyMeta('monitor').icon);
  });
});

describe('provenanceState', () => {
  it('maps the three store states honestly — unknown is NOT up-to-date', () => {
    // No mirror row recorded yet (fresh machine, dashboard-only usage): the
    // store cannot back an "up to date" claim.
    expect(provenanceState({ update: null })).toBe('unknown');
    // The store VERIFIED the installed snapshot against the recorded binary.
    expect(provenanceState({ update: { available: false, latestVersion: '2.0.0' } })).toBe(
      'up-to-date',
    );
    expect(
      provenanceState({ update: { available: true, latestVersion: '2.5.0', latestRuleCount: 21 } }),
    ).toBe('update-available');
  });
});
