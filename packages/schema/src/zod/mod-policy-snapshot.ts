import { z } from 'zod';

import { ActionTaken } from './finding.ts';
import { Rule } from './rule.ts';

// What the Claude Code prompt.submit mod needs to reach the verdict the
// UserPromptSubmit command hook would reach: the policy, resolved down to
// lookups, and the ruleset it applies to. The mod runs with no Node and no
// store, so `aka` writes this file and the mod reads it.
//
// Resolution order is the one createPolicyResolver reads a PolicyBundle in: a
// rule-targeted action wins, then the rule's category, then 'log'. Category
// rows are written out for EVERY category, with DEFAULT_ACTIONS already applied
// to an unpoliced one, so the reader needs no second default table.
//
// It carries rule definitions (patterns, keywords, examples) and never a
// matched value: nothing in it is derived from a prompt, a finding or a vault.
export const MOD_POLICY_SNAPSHOT_VERSION = 1;

/** The most the mod will read: `$.fs.read` itself rejects anything over 4 MiB. */
export const MOD_POLICY_SNAPSHOT_MAX_BYTES = 4 * 1024 * 1024;

export const ModPolicySnapshot = z
  .object({
    version: z.literal(MOD_POLICY_SNAPSHOT_VERSION),
    generatedAt: z.iso.datetime(),
    // The complete effective ruleset, as the hook's runtime scans with it: the
    // user's enabled installed packs (user-modified and custom packs included).
    // Absent means the store holds no authoritative snapshot, and the reader
    // scans with the packs it ships — the hook's own fallback.
    rules: z.array(Rule).optional(),
    // Rule-targeted actions (first enabled policy per rule wins).
    ruleActions: z.record(z.string(), ActionTaken),
    // The resolved action per detection category.
    categoryActions: z.record(z.string(), ActionTaken),
    // Rules with an active exception grant. Honouring a grant means matching a
    // keyed fingerprint of the value and consuming a use, which only the hook can
    // do, so the mod leaves a finding of one of these rules for the hook to decide.
    exceptionRuleIds: z.array(z.string()),
  })
  .meta({ id: 'ModPolicySnapshot' });
export type ModPolicySnapshot = z.infer<typeof ModPolicySnapshot>;
