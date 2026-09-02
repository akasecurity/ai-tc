// The one reading of a policy bundle's enforcement decisions.
//
// Three questions are asked of a bundle on every capture — what action applies
// to this finding, whether its span may be rewritten, whether the value behind
// it may be kept — and the first two collapse into `actionFor`. That reading
// used to live inside the hook runtime's closure, where nothing else could
// reach it, so every other consumer of pack policy had to re-derive it or skip
// it; two readings of one bundle are two answers nobody compares, and the one
// that skips is the one that vaults a value the user only asked to monitor.
import type { ActionTaken, PolicyBundle } from '@akasecurity/schema';
import { DEFAULT_ACTIONS } from '@akasecurity/schema';

export interface PolicyResolver {
  /**
   * The enforcement action a finding resolves to, from its rule id and its
   * category. Total: an unpoliced category falls to DEFAULT_ACTIONS and an
   * unknown one to 'log', so there is no input that returns nothing.
   */
  actionFor(ruleId: string, category: string): ActionTaken;
  /**
   * Whether the rule's detection chose the reversible archetype (Redact &
   * Vault). Says nothing about whether the value is being stripped at all —
   * that is `actionFor`'s answer, and both have to agree before anything is
   * vaulted.
   */
  isReversible(ruleId: string): boolean;
}

/**
 * Build a resolver over one policy bundle.
 *
 * Neither this nor the resolver it returns ever throws: it sits on the hook
 * path, where a fail-open catch upstream would turn a resolution fault into a
 * capture that detected nothing at all. A bundle whose policies cannot be
 * indexed therefore yields an EMPTY index rather than a partial one — every
 * finding then resolves through the per-category fallback, which is a posture
 * somebody chose, where half an index is a policy set nobody authored.
 */
export function createPolicyResolver(bundle: PolicyBundle): PolicyResolver {
  // Indexed once rather than scanned per lookup: a standalone-complete bundle
  // carries one policy PER RULE (~100+) and a hook resolves several times per
  // finding, so a linear scan would be O(policies) on every call. First-write-
  // wins reproduces the order a `.find` over the array had — an explicit
  // ruleId-targeted policy precedes the pack-derived ones.
  const byRule = new Map<string, ActionTaken>();
  const byCategory = new Map<string, ActionTaken>();
  let reversible: ReadonlySet<string> = new Set<string>();
  try {
    for (const policy of bundle.policies) {
      if (!policy.enabled) continue;
      if ('ruleId' in policy.target) {
        if (!byRule.has(policy.target.ruleId)) byRule.set(policy.target.ruleId, policy.action);
      } else if (!byCategory.has(policy.target.category)) {
        byCategory.set(policy.target.category, policy.action);
      }
    }
    // The reversibility axis rides beside the policies rather than on them (see
    // PolicyBundle.reversibleRuleIds). An absent field means an older producer,
    // and the empty set it yields is the one-way behaviour that predates it —
    // the safe direction to default, since nothing is then kept.
    reversible = new Set(bundle.reversibleRuleIds ?? []);
  } catch {
    byRule.clear();
    byCategory.clear();
    reversible = new Set<string>();
  }

  return {
    actionFor(ruleId: string, category: string): ActionTaken {
      // A per-rule policy — the per-detection Monitor/Warn/Redact/Block
      // assignment a gateway synthesizes from installed_packs.policy_id — wins
      // over the category default, so a detection set to Monitor actually
      // stops enforcing rather than falling through to DEFAULT_ACTIONS
      // (secret → warn).
      const byRuleAction = byRule.get(ruleId);
      if (byRuleAction !== undefined) return byRuleAction;
      const byCategoryAction = byCategory.get(category);
      if (byCategoryAction !== undefined) return byCategoryAction;
      // `category` is an arbitrary string here, so the lookup is treated as
      // possibly-missing and the 'log' fallback stays reachable.
      const fallback = (DEFAULT_ACTIONS as Partial<Record<string, ActionTaken>>)[category];
      return fallback ?? 'log';
    },
    isReversible(ruleId: string): boolean {
      return reversible.has(ruleId);
    },
  };
}
