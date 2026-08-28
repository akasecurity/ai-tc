import { BUILTIN_POLICIES, KNOWN_BUILTIN_IDS } from '@akasecurity/schema';
import { toneColors } from '@akasecurity/ui-kit';
import { describe, expect, it } from 'vitest';

import {
  matcherSummary,
  PLACEHOLDER_POLICY,
  policyMeta,
  provenanceState,
} from '../../src/detections/meta.ts';

describe('matcherSummary', () => {
  it('renders each matcher kind as a one-line summary', () => {
    expect(matcherSummary({ type: 'regex', pattern: '\\d+', flags: 'g' })).toBe('/\\d+/g');
    expect(
      matcherSummary({ type: 'keyword', keywords: ['aws', 'gcp'], caseSensitive: false }),
    ).toBe('aws · gcp');
  });
});

describe('policyMeta', () => {
  it('resolves each built-in policy id to its label', () => {
    expect(policyMeta('monitor').label).toBe('Monitor');
    expect(policyMeta('block').label).toBe('Block');
    expect(policyMeta('vault').label).toBe('Redact & Vault');
  });

  it('carries real metadata for EVERY built-in — none falls through to the fallback', () => {
    // The fallback is indistinguishable from a styling bug: an unlabelled gray
    // pill with an empty description card. Derived from the canonical id set so
    // an added archetype fails here rather than rendering as one.
    for (const id of KNOWN_BUILTIN_IDS) {
      const m = policyMeta(id);
      expect(m.label, `${id} has no label`).not.toBe(id);
      expect(m.desc, `${id} has no description`).not.toBe('');
      expect(m.icon, `${id} uses the neutral fallback icon`).not.toBe(policyMeta('mystery').icon);
    }
  });

  it('gives each built-in a description matching the schema catalog', () => {
    // Two copies of this prose exist — the schema catalog (which the CLI and the
    // plugins render) and this map (which the dashboard renders). Drift between
    // them means the same policy is described two different ways depending on
    // where the user reads it.
    for (const id of KNOWN_BUILTIN_IDS) {
      expect(policyMeta(id).desc, `${id} description drifted from the schema catalog`).toBe(
        BUILTIN_POLICIES[id].description,
      );
      expect(policyMeta(id).label, `${id} label drifted from the schema catalog`).toBe(
        BUILTIN_POLICIES[id].name,
      );
    }
  });

  it('falls back to a neutral entry for an unknown id (keeping the id as label)', () => {
    const m = policyMeta('mystery');
    expect(m.label).toBe('mystery');
    expect(m.tone).toBe('neutral');
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
      expect(m.tone).toBe('neutral');
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
