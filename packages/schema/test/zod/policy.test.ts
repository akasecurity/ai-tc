import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { ExceptionBundleEntry } from '../../src/zod/exception.ts';
import { DetectionCategory } from '../../src/zod/finding.ts';
import {
  actionRank,
  builtinPolicyToAction,
  DEFAULT_ACTIONS,
  FULL_ENFORCEMENT_POSTURE,
  mergeRaiseOnly,
  Policy,
  POLICY_BUNDLE_SHAPE_ID,
  PolicyBundle,
  PolicyTarget,
  RedactFallback,
  ruleCategoryMap,
  strongerRedactFallback,
} from '../../src/zod/policy.ts';

describe('DEFAULT_ACTIONS — severity-floor cold-start values', () => {
  it('never hard-enforces (block) or silently rewrites payloads (redact) before onboarding', () => {
    // A fresh store with no per-category policy falls back to these. None may
    // block or redact on its own — the cold-start floor only ever surfaces
    // (warn) or logs. This guards against a category quietly regaining an
    // enforcing default and hard-acting on an un-onboarded machine.
    for (const [category, action] of Object.entries(DEFAULT_ACTIONS)) {
      expect(action, `${category} cold-start action`).not.toBe('block');
      expect(action, `${category} cold-start action`).not.toBe('redact');
    }
  });

  it('assigns a fallback action to every detection category', () => {
    expect(new Set(Object.keys(DEFAULT_ACTIONS))).toEqual(new Set(DetectionCategory.options));
  });

  it('floors critical/high-severity categories to warn, low/observe-only categories to log', () => {
    expect(DEFAULT_ACTIONS.secret).toBe('warn');
    expect(DEFAULT_ACTIONS.pii).toBe('warn');
    expect(DEFAULT_ACTIONS.financial).toBe('warn');
    expect(DEFAULT_ACTIONS.phi).toBe('warn');
    expect(DEFAULT_ACTIONS.code_flaw).toBe('warn');
    expect(DEFAULT_ACTIONS.custom).toBe('warn');
    expect(DEFAULT_ACTIONS.code_context).toBe('log');
    expect(DEFAULT_ACTIONS.config).toBe('log');
  });
});

describe('FULL_ENFORCEMENT_POSTURE — the "Actively redact" onboarding preset', () => {
  it('pins the pre-severity-floor enforcement mapping', () => {
    expect(FULL_ENFORCEMENT_POSTURE).toEqual({
      secret: 'block',
      pii: 'redact',
      financial: 'redact',
      phi: 'redact',
      code_flaw: 'warn',
      custom: 'warn',
      code_context: 'warn',
      config: 'warn',
    });
  });

  it('assigns a value to every detection category', () => {
    expect(new Set(Object.keys(FULL_ENFORCEMENT_POSTURE))).toEqual(
      new Set(DetectionCategory.options),
    );
  });
});

describe('PolicyBundle.ruleVersions', () => {
  const baseBundle = {
    version: '1',
    policies: [],
    customKeywords: [],
    fetchedAt: '2025-12-31T00:00:00.000Z',
  };

  it('parses without ruleVersions (older backends / on-disk caches omit it)', () => {
    const result = PolicyBundle.safeParse(baseBundle);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.ruleVersions).toBeUndefined();
    }
  });

  it('parses with ruleVersions present, keyed by ruleId', () => {
    const result = PolicyBundle.safeParse({
      ...baseBundle,
      ruleVersions: { 'secrets/aws-access-key': '2.3.1' },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.ruleVersions).toEqual({ 'secrets/aws-access-key': '2.3.1' });
    }
  });
});

describe('PolicyBundle.redactFallback', () => {
  const baseBundle = {
    version: '1',
    policies: [],
    customKeywords: [],
    fetchedAt: '2025-12-31T00:00:00.000Z',
  };

  it('parses without it — an older backend or on-disk cache omits it', () => {
    const result = PolicyBundle.safeParse(baseBundle);
    expect(result.success).toBe(true);
    if (result.success) expect(result.data.redactFallback).toBeUndefined();
  });

  it('accepts the three fallback values and refuses the two it excludes', () => {
    for (const value of RedactFallback.options) {
      expect(PolicyBundle.safeParse({ ...baseBundle, redactFallback: value }).success).toBe(true);
    }
    // `redact` and `vault` are the thing that could not be carried out, so
    // neither is an answer to what happens instead.
    for (const value of ['redact', 'vault']) {
      expect(PolicyBundle.safeParse({ ...baseBundle, redactFallback: value }).success).toBe(false);
    }
  });
});

describe('strongerRedactFallback — an organization tightens, never loosens', () => {
  it('takes the remote value only when it is stronger', () => {
    expect(strongerRedactFallback('warn', 'block')).toBe('block');
    expect(strongerRedactFallback('monitor', 'warn')).toBe('warn');
    expect(strongerRedactFallback('monitor', 'block')).toBe('block');
  });

  it('keeps the local value when the remote one is weaker', () => {
    // The direction that matters: a control plane must not be able to turn a
    // device's Block into a Warn, which would let a value through on a field
    // that cannot be masked.
    expect(strongerRedactFallback('block', 'warn')).toBe('block');
    expect(strongerRedactFallback('block', 'monitor')).toBe('block');
    expect(strongerRedactFallback('warn', 'monitor')).toBe('warn');
  });

  it('keeps the local value when there is no remote one at all', () => {
    for (const local of RedactFallback.options) {
      expect(strongerRedactFallback(local, undefined)).toBe(local);
    }
  });

  it('is total over the vocabulary, and never returns a value outside it', () => {
    // Derived rather than enumerated, so a member added to RedactFallback is
    // covered here without editing the loop. What that buys is TOTALITY and
    // idempotence over whatever the enum currently holds — not a guarantee that
    // the merge can tell every pair apart, which the next case is for.
    for (const local of RedactFallback.options) {
      for (const remote of RedactFallback.options) {
        const merged = strongerRedactFallback(local, remote);
        expect(RedactFallback.options).toContain(merged);
        // Idempotent against the local value. NOT the whole property — it holds
        // for an implementation that ignores `remote` entirely, since then
        // `merged === local` and `f(local, local) === local`. The three explicit
        // pairs above are what catch that; this states the ladder is consistent.
        expect(strongerRedactFallback(merged, local)).toBe(merged);
      }
    }
  });

  it('ranks every member DISTINCTLY, so no pair can compare as equal', () => {
    // The claim the case above used to make and could not keep. The palette
    // maps many-to-one — `redact` and `vault` both carry `action: 'redact'` —
    // so widening RedactFallback to a member that aliases an existing one
    // introduces a genuinely unordered pair, and the loop above would report it
    // green: both sides rank the same, `strongerAction` returns its first
    // argument, and the idempotence check then passes either way.
    //
    // Ranked distinctly, a merge cannot silently pick one of two incomparable
    // members. Today: monitor/warn/block rank 1/2/4.
    const ranks = RedactFallback.options.map((id) => actionRank(builtinPolicyToAction(id)));
    expect(
      new Set(ranks).size,
      `ranks ${ranks.join(', ')} for ${RedactFallback.options.join(', ')}`,
    ).toBe(RedactFallback.options.length);
  });
});

describe('mergeRaiseOnly — a cached tenant bundle can only tighten a local one', () => {
  const policy = (target: Policy['target'], action: Policy['action'], enabled = true): Policy => ({
    id: `${JSON.stringify(target)}-${action}-${String(enabled)}`,
    scope: 'global',
    target,
    action,
    enabled,
  });

  it('leaves the local bundle untouched when the tenant declares nothing', () => {
    const local = [policy({ category: 'secret' }, 'warn'), policy({ ruleId: 'r1' }, 'log')];
    const merged = mergeRaiseOnly(local, [], new Map());
    expect(merged).toStrictEqual(local);
  });

  it('lets the tenant raise a category above the local policy', () => {
    const local = [policy({ category: 'secret' }, 'warn')];
    const remote = [policy({ category: 'secret' }, 'block')];
    const merged = mergeRaiseOnly(local, remote, new Map());
    expect(merged).toHaveLength(1);
    expect(merged[0]?.action).toBe('block');
  });

  // ⚠ THE FIRST-WRITE-WINS TEST. A naive [...remote, ...local] concatenation
  // hands the remote side precedence for a contended target, so a tenant
  // policy weaker than the user's own would win under first-write-wins even
  // though it never should. Exactly one policy must survive per key, and it
  // must be the stronger one.
  it('never lets a weaker tenant policy win a contended target', () => {
    const local = [policy({ category: 'secret' }, 'block')];
    const remote = [policy({ category: 'secret' }, 'warn')];
    const merged = mergeRaiseOnly(local, remote, new Map());
    expect(merged).toHaveLength(1);
    expect(merged[0]?.action).toBe('block');
  });

  // ⚠ THE CROSS-NAMESPACE TEST. `resolveAction` consults a ruleId-targeted
  // policy before a category one, so a local category policy must floor a
  // remote RULE-targeted policy that resolves into that category — otherwise
  // the two never meet on a shared key and the weaker one still wins at
  // resolution time.
  it('floors a remote ruleId policy at what the local bundle enforces for its category', () => {
    const categoryByRuleId = new Map<string, DetectionCategory>([['aws-key', 'secret']]);
    const local = [policy({ category: 'secret' }, 'block')];
    const remote = [policy({ ruleId: 'aws-key' }, 'allow')];
    const merged = mergeRaiseOnly(local, remote, categoryByRuleId);
    const ruleEntry = merged.find((p) => 'ruleId' in p.target);
    expect(ruleEntry?.action).toBe('block');
    // The local category policy itself must still be present, untouched.
    const categoryEntry = merged.find((p) => 'category' in p.target);
    expect(categoryEntry?.action).toBe('block');
  });

  // The mirror of the case above: an unassigned local pack (a weak ruleId
  // policy) must not undercut what the tenant enforces for that rule's
  // category.
  it('floors a local ruleId policy at what the tenant enforces for its category', () => {
    const categoryByRuleId = new Map<string, DetectionCategory>([['aws-key', 'secret']]);
    const local = [policy({ ruleId: 'aws-key' }, 'log')];
    const remote = [policy({ category: 'secret' }, 'block')];
    const merged = mergeRaiseOnly(local, remote, categoryByRuleId);
    const ruleEntry = merged.find((p) => 'ruleId' in p.target);
    expect(ruleEntry?.action).toBe('block');
  });

  it('clamps a remote-only target to the compiled-in floor for its category', () => {
    // 'secret' floors to at least DEFAULT_ACTIONS.secret; a remote policy
    // below it must never be honoured verbatim, since the cache is read with
    // no signature or provenance check.
    const remote = [policy({ category: 'secret' }, 'allow')];
    const merged = mergeRaiseOnly([], remote, new Map());
    expect(merged).toHaveLength(1);
    const [clamped] = merged;
    expect(clamped).toBeDefined();
    // A missing entry ranks below everything (actionRank('') === -1), so this
    // still fails rather than passing vacuously if the assertion above ever did
    // not hold.
    expect(actionRank(clamped?.action ?? '')).toBeGreaterThanOrEqual(
      actionRank(DEFAULT_ACTIONS.secret),
    );
  });

  it('leaves an unresolvable ruleId unclamped rather than guessing a floor', () => {
    const remote = [policy({ ruleId: 'unknown-rule' }, 'allow')];
    const merged = mergeRaiseOnly([], remote, new Map());
    expect(merged).toEqual(remote);
  });

  it('carries disabled policies through from both sides, untouched', () => {
    const local = [policy({ category: 'secret' }, 'block', false)];
    const remote = [policy({ ruleId: 'r1' }, 'allow', false)];
    const merged = mergeRaiseOnly(local, remote, new Map());
    expect(merged).toEqual(expect.arrayContaining([...local, ...remote]));
    expect(merged).toHaveLength(2);
  });

  it('keeps only the first local policy for a duplicate target', () => {
    const local = [policy({ category: 'secret' }, 'block'), policy({ category: 'secret' }, 'log')];
    const merged = mergeRaiseOnly(local, [], new Map());
    expect(merged).toHaveLength(1);
    expect(merged[0]?.action).toBe('block');
  });

  it('still carries a target only the tenant declares', () => {
    const remote = [policy({ category: 'pii' }, 'redact')];
    const merged = mergeRaiseOnly([], remote, new Map());
    expect(merged.some((p) => 'category' in p.target && p.target.category === 'pii')).toBe(true);
  });
});

describe('ruleCategoryMap — the trust order mergeRaiseOnly floors against', () => {
  const rule = (id: string, category: DetectionCategory) =>
    ({
      specVersion: 1,
      id,
      name: id,
      category,
      severity: 'critical',
      matcher: { type: 'keyword', keywords: [id] },
    }) as NonNullable<PolicyBundle['rules']>[number];

  it('resolves a rule from any tier', () => {
    const map = ruleCategoryMap(
      [rule('wire-only', 'secret')],
      [rule('local-only', 'pii')],
      [rule('compiled-only', 'financial')],
    );
    expect(map.get('wire-only')).toBe('secret');
    expect(map.get('local-only')).toBe('pii');
    expect(map.get('compiled-only')).toBe('financial');
  });

  // ⚠ THE TRUST-ORDER TEST. The wire tier is the SAME unsigned bundle the
  // clamp exists to defend against, so it must never be able to redeclare a
  // rule id the device already knows a category for — neither the locally
  // installed tier nor the compiled-in one.
  it('never lets the wire tier override a locally installed rule’s category', () => {
    const map = ruleCategoryMap(
      [rule('shared-id', 'code_context')],
      [rule('shared-id', 'secret')],
      [],
    );
    expect(map.get('shared-id')).toBe('secret');
  });

  it('never lets the wire tier override a compiled-in rule’s category', () => {
    const map = ruleCategoryMap(
      [rule('shared-id', 'code_context')],
      [],
      [rule('shared-id', 'secret')],
    );
    expect(map.get('shared-id')).toBe('secret');
  });

  it('lets the compiled-in tier override a locally installed one', () => {
    // Compiled-in is the MOST trusted tier — it anchors the clamp whatever an
    // installed pack or the wire claims.
    const map = ruleCategoryMap(
      [],
      [rule('shared-id', 'code_context')],
      [rule('shared-id', 'secret')],
    );
    expect(map.get('shared-id')).toBe('secret');
  });

  it('leaves a rule id absent from every tier with no floor at all', () => {
    const map = ruleCategoryMap([rule('known', 'secret')], [], []);
    expect(map.has('unknown')).toBe(false);
  });

  it('is total over an absent (undefined) rules list at the wire and local tiers', () => {
    // `PolicyBundle['rules']` is optional at these two tiers, so both must
    // tolerate `undefined` the way `?? []` does. The compiled tier is NOT
    // optional — see ruleCategoryMap's own comment — so it takes `[]` here
    // rather than `undefined`, which no longer compiles.
    expect(() => ruleCategoryMap(undefined, undefined, [])).not.toThrow();
    expect(ruleCategoryMap(undefined, undefined, []).size).toBe(0);
  });
});

// The stamp exists so a cache narrowed by an older build can be told apart from
// one this build wrote. It is only worth anything if it actually tracks the
// schema — a constant that drifted free of `PolicyBundle` would go on matching
// every record forever, which is indistinguishable from not having it.
describe('POLICY_BUNDLE_SHAPE_ID tracks the schema it describes', () => {
  it('names every top-level bundle field', () => {
    const named = new Set(POLICY_BUNDLE_SHAPE_ID.split(','));
    const missing = Object.keys(PolicyBundle.shape).filter((key) => !named.has(key));
    expect(missing, 'bundle fields absent from the stamp').toEqual([]);
  });

  it('names the NESTED policy fields too', () => {
    // The top level alone is not enough, and this is the case that shows why:
    // `Policy` is a plain object, so Zod narrows it exactly as it narrows the
    // bundle, while `policies` stays one unchanged key. A build that widens
    // `Policy` would move no top-level key, its stamp would read as a match,
    // and the same 304 would replay the same narrowed policies.
    const named = new Set(POLICY_BUNDLE_SHAPE_ID.split(','));
    const missing = Object.keys(Policy.shape).filter((key) => !named.has(`policies.${key}`));
    expect(missing, 'policy fields absent from the stamp').toEqual([]);
  });

  it('names the NESTED exception fields too', () => {
    // The same argument as `policies` above, and it needs its own case: without
    // it the entire `exceptions.*` half of the derivation could be deleted with
    // every other assertion here still green. `ExceptionBundleEntry` is a pick
    // of a plain object, so Zod narrows it exactly as it narrows `Policy` while
    // `exceptions` stays one unchanged key.
    const named = new Set(POLICY_BUNDLE_SHAPE_ID.split(','));
    const missing = Object.keys(ExceptionBundleEntry.shape).filter(
      (key) => !named.has(`exceptions.${key}`),
    );
    expect(missing, 'exception fields absent from the stamp').toEqual([]);
  });

  it('names the fields of BOTH PolicyTarget union members', () => {
    // `policies.target` is one key whatever the target holds, so widening
    // either member moves nothing the other walks can see — the same trap as
    // `Policy`, one level further down and easier to miss. Neither member is
    // strict, so Zod narrows both.
    const named = new Set(POLICY_BUNDLE_SHAPE_ID.split(','));
    const missing = PolicyTarget.options
      .flatMap((member) => ('shape' in member ? Object.keys(member.shape) : []))
      .filter((key) => !named.has(`policies.target.${key}`));
    expect(missing, 'target fields absent from the stamp').toEqual([]);
  });

  it('survives a union member that is not a plain object', () => {
    // The `shape` guard is load-bearing, not defensive. This derivation runs at
    // MODULE LOAD in a package every hook script bundles, so an unguarded
    // `.shape` on a non-object member would not produce a narrower stamp — it
    // would throw on import and take every hook with it, which is the one thing
    // the plugin may never do. Driven on the pattern rather than on
    // `PolicyTarget` itself, because the real union has no such member yet and
    // the point is what happens when someone adds one.
    const mixed = z.union([z.object({ ruleId: z.string() }), z.literal('everything')]);
    const walk = (): string[] =>
      mixed.options.flatMap((member) => ('shape' in member ? Object.keys(member.shape) : []));
    expect(walk).not.toThrow();
    expect(walk()).toEqual(['ruleId']);
  });

  it('carries the two fields whose loss this was built for', () => {
    // Named rather than derived, so the assertion is not satisfied by whatever
    // the schema happens to say today. `prohibitedModels` is the governance
    // decision that went missing; `provenance` is the nested field added one
    // commit before the stamp existed, and the reason the nested half is here.
    expect(POLICY_BUNDLE_SHAPE_ID.split(',')).toContain('prohibitedModels');
    expect(POLICY_BUNDLE_SHAPE_ID.split(',')).toContain('policies.provenance');
  });

  it('is exactly the sorted union of those shapes, and nothing else', () => {
    // Written to disk and compared by EQUALITY, so the property that matters is
    // that it is reproducible from the shapes — not merely equal to itself,
    // which a module-level const always is. Pins the composition too: an extra
    // key, a missing half, or an unsorted join all fail here.
    const expected = [
      ...Object.keys(PolicyBundle.shape),
      ...Object.keys(Policy.shape).map((key) => `policies.${key}`),
      ...PolicyTarget.options
        // Guarded exactly as the derivation is, or the two stop agreeing the
        // moment a non-object member is added.
        .flatMap((member) => ('shape' in member ? Object.keys(member.shape) : []))
        .map((key) => `policies.target.${key}`),
      ...Object.keys(ExceptionBundleEntry.shape).map((key) => `exceptions.${key}`),
    ].sort();
    expect(POLICY_BUNDLE_SHAPE_ID.split(',')).toEqual(expected);
  });
});
