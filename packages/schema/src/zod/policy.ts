import { z } from 'zod';

import { ExceptionBundleEntry } from './exception.ts';
import type { ActionTaken, DetectionCategory, Severity } from './finding.ts';
import {
  ActionTaken as ActionTakenSchema,
  DetectionCategory as DetectionCategorySchema,
} from './finding.ts';
import { Rule } from './rule.ts';

export const PolicyScope = z.enum(['global', 'repo', 'user']).meta({ id: 'PolicyScope' });
export type PolicyScope = z.infer<typeof PolicyScope>;

// THREE ENFORCEMENT AXES — do not conflate (see also DEFAULT_ACTIONS below):
//   1. CATEGORY — a rule's taxonomy (secret/pii/…); the per-category fallback.
//   2. RULE — a single rule id.
//   3. PACK ("detection", namespace/packId) — the install unit, whose per-pack
//      policy lives on installed_packs.policy_id (a BuiltinPolicyId archetype).
// PolicyTarget can address only a RULE or a CATEGORY — there is deliberately NO
// `{ packId }` variant. The per-PACK assignment is bridged INTO this contract as
// per-RULE policies: the bundle builder (standalone-gateway.getPolicyBundle)
// expands each pack's policy_id into
// one `{ ruleId }`-targeted policy per rule the pack owns, and resolveAction prefers
// a ruleId match over a category match. So per-pack enforcement is expressed here,
// but only via rule ids — a pack is never named directly. Cardinality note: a
// category maps to MANY packs (secret → secrets + secrets-infra) and custom/config
// map to zero, so a single `{ category }` policy can never stand in for a pack.
export const PolicyTarget = z
  .union([z.object({ ruleId: z.string() }), z.object({ category: DetectionCategorySchema })])
  .meta({ id: 'PolicyTarget' });
export type PolicyTarget = z.infer<typeof PolicyTarget>;

// The canonical open-source policy shape AND the public OpenAPI component
// 'Policy'. Tenant-free: the local store + the wire PolicyBundle use it directly,
// and it backs the policies API contract — the public contract carries no
// scoping columns.
export const Policy = z
  .object({
    id: z.guid(),
    scope: PolicyScope,
    target: PolicyTarget,
    action: ActionTakenSchema,
    enabled: z.boolean().default(true),
    customKeywords: z.array(z.string()).optional(),
    // Display name — optional so older policy rows without name still parse.
    // Added for the findings API (policy.name column migration).
    name: z.string().optional(),
  })
  .meta({ id: 'Policy' });
export type Policy = z.infer<typeof Policy>;

export const PolicyBundle = z
  .object({
    version: z.string(),
    policies: z.array(Policy),
    // Rules from the installed marketplace packs (snapshotted by the
    // control plane). The plugin registers these in addition to its bundled
    // packs. Optional so older backends — and older on-disk caches — that omit
    // the field still parse; consumers read `bundle.rules ?? []`.
    rules: z.array(Rule).optional(),
    // When true, `rules` IS the complete effective ruleset and the runtime must
    // NOT merge its compiled-in bundled packs — the standalone gateway sets this
    // after reading the user's installed snapshot (installed_packs, enabled
    // packs only), which is how detection updates stay manual: new bundled
    // rules run only after the user applies the pack update. Absent/false keeps
    // the historical composition (bundled packs + rules) — older caches.
    rulesComplete: z.boolean().optional(),
    // Active detection exceptions, evaluation subset only (see
    // ExceptionBundleEntry). Optional so older bundle producers — and older
    // on-disk caches — that omit the field still parse; consumers read
    // `bundle.exceptions ?? []`.
    exceptions: z.array(ExceptionBundleEntry).optional(),
    customKeywords: z.array(z.string()),
    fetchedAt: z.iso.datetime(),
  })
  .meta({ id: 'PolicyBundle' });
export type PolicyBundle = z.infer<typeof PolicyBundle>;

// Enforcement-coverage denominators use this, NOT DEFAULT_ACTIONS: 'config'
// findings only observe (see above), so a config policy can never be "covered"
// by enforcement and would permanently drag the coverage % down. Derived by
// exclusion so a new enforceable category extends coverage automatically.
export const OBSERVE_ONLY_CATEGORIES: readonly DetectionCategory[] = ['config'];
export const ENFORCEABLE_CATEGORIES: readonly DetectionCategory[] =
  DetectionCategorySchema.options.filter((c) => !OBSERVE_ONLY_CATEGORIES.includes(c));

// Highest static severity each category's rules can emit (from the bundled rule
// packs). Used ONLY by the cold-start severity floor below — NOT per-instance risk.
export const CATEGORY_PEAK_SEVERITY: Record<DetectionCategory, Severity> = {
  secret: 'critical',
  financial: 'critical', // core-financial/credit-card
  code_flaw: 'critical',
  pii: 'high',
  phi: 'high',
  custom: 'high', // user-defined; conservative
  code_context: 'low',
  config: 'low', // observe-only; floors to monitor regardless
};

// Cold-start floor: with NO evidence to judge genuineness, a category whose
// rules can emit critical/high must at least surface (warn); low/medium-only or
// observe-only categories log (monitor).
export function severityFloorPolicy(category: DetectionCategory): 'warn' | 'monitor' {
  if (OBSERVE_ONLY_CATEGORIES.includes(category)) return 'monitor';
  const peak = CATEGORY_PEAK_SEVERITY[category];
  return peak === 'critical' || peak === 'high' ? 'warn' : 'monitor';
}

export function severityFloorPosture(): Record<DetectionCategory, 'warn' | 'monitor'> {
  const out = {} as Record<DetectionCategory, 'warn' | 'monitor'>;
  for (const c of DetectionCategorySchema.options) out[c] = severityFloorPolicy(c);
  return out;
}

// ─── M1: Built-in policy catalog (read-only) ────────────────────────────────

export const PolicyKind = z.enum(['builtin', 'custom']).meta({ id: 'PolicyKind' });
export type PolicyKind = z.infer<typeof PolicyKind>;

// Single source of truth for the built-in policy ids, declared in display order
// (monitor → warn → redact → block, least → most restrictive). This one runtime
// array feeds the Zod enum (BuiltinPolicyId), PATCH membership validation, the
// catalog display order (BUILTIN_ORDER), and the catalog keys (BUILTIN_POLICIES) —
// so the literal set is declared exactly once here.
export const KNOWN_BUILTIN_IDS = ['monitor', 'warn', 'redact', 'block'] as const;

export const BuiltinPolicyId = z.enum(KNOWN_BUILTIN_IDS).meta({ id: 'BuiltinPolicyId' });
export type BuiltinPolicyId = z.infer<typeof BuiltinPolicyId>;

// Display order of the built-in catalog. Aliases the canonical id set (already
// declared least → most restrictive) so display order can never drift from
// membership; kept as a named export for call sites that read it as display order.
export const BUILTIN_ORDER: readonly BuiltinPolicyId[] = KNOWN_BUILTIN_IDS;

// Name/description/action for each built-in archetype, keyed by id. The
// `Record<BuiltinPolicyId, …>` constraint forces this to stay exhaustive with
// KNOWN_BUILTIN_IDS, so adding a builtin is a single coordinated edit (id set +
// this spec) rather than three synchronized literals.
export const BUILTIN_POLICY_SPECS: Record<
  BuiltinPolicyId,
  { name: string; description: string; action: ActionTaken }
> = {
  monitor: {
    name: 'Monitor',
    action: 'log',
    description: 'Log every match for audit. The request is allowed through untouched.',
  },
  warn: {
    name: 'Warn',
    action: 'warn',
    description: 'Allow the request, but warn the user inline before it is sent.',
  },
  redact: {
    name: 'Redact',
    action: 'redact',
    description: 'Automatically strip the matched value from the request, then continue.',
  },
  block: {
    name: 'Block',
    action: 'block',
    description: 'Refuse the request entirely whenever any rule in this detection matches.',
  },
};

// Maps the palette BuiltinPolicyId (monitor/warn/redact/block) to the ActionTaken
// enum actually stored on policies.action (warn/redact/block/allow/log).
// monitor -> log; warn/redact/block are identity. Derived from
// BUILTIN_POLICY_SPECS so the mapping can never drift from the catalog.
export function builtinPolicyToAction(id: BuiltinPolicyId): ActionTaken {
  return BUILTIN_POLICY_SPECS[id].action;
}

// The per-CATEGORY enforcement FALLBACK (axis 1). Used when no more-specific
// policy applies to a finding's rule. It is NOT the per-pack default — an
// unassigned PACK resolves to DEFAULT_PACK_POLICY_ID ('monitor'), not to its
// category's action here. Precedence at enforcement (both surfaces): a per-rule
// policy (synthesized from the pack's policy_id, or an explicit ruleId policy)
// wins over a per-category policy, which wins over this fallback. So a category
// floored to `warn` here still only logs if its pack is set to Monitor.
//
// Cold-start seed = the severity floor (observe-first), routed through the
// single catalog mapper so the monitor->log translation lives in exactly one
// place (builtinPolicyToAction). severityFloorPolicy returns 'warn'|'monitor',
// both valid BuiltinPolicyId, so this is total over every DetectionCategory.
export const DEFAULT_ACTIONS: Record<DetectionCategory, ActionTaken> = Object.fromEntries(
  DetectionCategorySchema.options.map((c) => [c, builtinPolicyToAction(severityFloorPolicy(c))]),
) as Record<DetectionCategory, ActionTaken>;

// Locked catalog of the 4 built-in policy archetypes — the single source of truth
// for the local policy-catalog read port. Each entry's `id` is derived from
// its record key, never re-declared.
export const BUILTIN_POLICIES: Record<
  BuiltinPolicyId,
  { id: BuiltinPolicyId; name: string; description: string; action: ActionTaken }
> = Object.fromEntries(
  KNOWN_BUILTIN_IDS.map((id) => [id, { id, ...BUILTIN_POLICY_SPECS[id] }]),
) as Record<
  BuiltinPolicyId,
  { id: BuiltinPolicyId; name: string; description: string; action: ActionTaken }
>;

// The default built-in policy for a PACK ("detection") that has no explicit
// assignment (installed_packs.policy_id IS NULL). The whole product treats an
// unassigned detection as Monitor (log-only): the dashboards render it
// (dashboard-ui PLACEHOLDER_POLICY), the local store coalesces to it, and
// every enforcement path resolves an unassigned pack to it. This is the
// single source of that default so no caller can drift.
export const DEFAULT_PACK_POLICY_ID: BuiltinPolicyId = 'monitor';

// The enforcement ActionTaken a PACK's assigned built-in policy resolves to
// (monitor→log, warn→warn, redact→redact, block→block). This is the ONE
// authoritative mapping from the per-PACK policy axis (installed_packs.policy_id,
// a BuiltinPolicyId string) to an enforcement action — every consumer (e.g.
// persistence installedRuleset) resolves through it,
// so a detection's Monitor/Warn/Redact/Block choice resolves
// identically everywhere. A NULL/undefined/unknown id coalesces to the
// monitor-by-default posture (DEFAULT_PACK_POLICY_ID). NOTE: this is the PACK
// axis; it is deliberately distinct from DEFAULT_ACTIONS, which is the per-CATEGORY
// fallback. See PolicyTarget / DEFAULT_ACTIONS for how the axes relate.
export function policyIdToAction(policyId: string | null | undefined): ActionTaken {
  const parsed = BuiltinPolicyId.safeParse(policyId ?? DEFAULT_PACK_POLICY_ID);
  const id: BuiltinPolicyId = parsed.success ? parsed.data : DEFAULT_PACK_POLICY_ID;
  return BUILTIN_POLICIES[id].action;
}

export const UsedByItem = z
  .object({
    id: z.string(),
    name: z.string(),
    ruleCount: z.number().int().nonnegative(),
    enabled: z.boolean(),
  })
  .meta({ id: 'UsedByItem' });
export type UsedByItem = z.infer<typeof UsedByItem>;

export const PolicyListItem = z
  .object({
    id: z.string(),
    kind: PolicyKind,
    name: z.string(),
    enabled: z.boolean(),
    usedByCount: z.number().int().nonnegative(),
  })
  .meta({ id: 'PolicyListItem' });
export type PolicyListItem = z.infer<typeof PolicyListItem>;

export const PolicyDetail = z
  .object({
    specVersion: z.literal(1),
    id: z.string(),
    kind: PolicyKind,
    name: z.string(),
    enabled: z.boolean(),
    description: z.string(),
    usedBy: z.array(UsedByItem),
  })
  .meta({ id: 'PolicyDetail' });
export type PolicyDetail = z.infer<typeof PolicyDetail>;

export const PolicyStatsResponse = z
  .object({
    policies: z.number().int().nonnegative(),
    builtin: z.number().int().nonnegative(),
    custom: z.number().int().nonnegative(),
    detectionsGoverned: z.number().int().nonnegative(),
  })
  .meta({ id: 'PolicyStatsResponse' });
export type PolicyStatsResponse = z.infer<typeof PolicyStatsResponse>;
