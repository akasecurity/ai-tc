import { z } from 'zod';

import { ExceptionBundleEntry } from './exception.ts';
import type { ActionTaken, DetectionCategory, Severity } from './finding.ts';
import {
  ACTION_TAKEN_KEYS,
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

// Which built-in policy ARCHETYPE catalog entry a row is — the axis
// PolicyListItem and PolicyDetail below are keyed on, and the one the
// policy-catalog list port filters by.
export const PolicyKind = z.enum(['builtin', 'custom']).meta({ id: 'PolicyKind' });
export type PolicyKind = z.infer<typeof PolicyKind>;

// Whether a bundle row's target was AUTHORED against this deployment, or is a
// built-in expansion the producer synthesized. A SEPARATE axis from PolicyKind
// above, and it carries its own name for that reason: the two answer different
// questions, and a device-side lock keys on this one, so a shared component
// name would let a consumer read the archetype answer as the provenance answer.
// Declared above `Policy` because `Policy` carries it.
export const PolicyProvenance = z.enum(['builtin', 'authored']).meta({ id: 'PolicyProvenance' });
export type PolicyProvenance = z.infer<typeof PolicyProvenance>;

// The canonical policy shape, and the component named 'Policy'. The local store
// and the wire PolicyBundle use it directly, and it backs the policies contract.
// Carries no scoping columns — a policy is identified by its own id.
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
    // Whether an AUTHORED policy governs this row's target — not a claim about
    // which row this is. A producer that collapses several rows onto one target
    // must carry the marker onto whichever row survives, or the collapse decides
    // the answer; a survivor may therefore be a built-in expansion still marked
    // 'authored' because an authored sibling targeted the same thing.
    // Optional so an older producer — and an older on-disk cache — still parses;
    // absent reads as 'builtin', which is the behaviour that predates the field.
    //
    // Deliberately NOT `kind`/PolicyKind: that name and that enum answer which
    // built-in archetype catalog entry a policy is, which every catalog surface
    // reads and which a caller may state. This one is a statement the PRODUCER
    // of a bundle makes about a row, and only the bundle builder ever stamps it
    // — the CRUD routes neither accept nor set it.
    //
    // A device consumes this in exactly one direction: an 'authored' policy
    // arriving from a control plane marks the rules it targets as not
    // locally re-assignable. That can only ever ADD a refusal, never relax one,
    // which is what makes it safe to honour from an unsigned cache — the same
    // test `prohibitedModels` passes and `reversibleRuleIds` fails.
    provenance: PolicyProvenance.optional(),
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
    // Rule ids whose pack is assigned a REVERSIBLE archetype (Redact & Vault).
    // A second axis over the same `redact` action, carried beside the policies
    // rather than on them: nothing writes ruleId-targeted policies to disk, so
    // widening Policy itself would change a persisted shape to express something
    // only the in-memory bundle needs. Optional so an older producer — or an
    // older on-disk cache — still parses; consumers read `?? []` and get the
    // pre-existing one-way behaviour, which is the safe direction to default.
    reversibleRuleIds: z.array(z.string()).optional(),
    // Installed pack version, keyed by ruleId, for rules in `rules` that came
    // from a versioned installed pack. Optional so older backends — and older
    // on-disk caches — that omit the field still parse; consumers fall back to
    // the rule's own spec version. NOT the bundle version above — see
    // installedRuleset's ruleVersions for the source of truth.
    ruleVersions: z.record(z.string(), z.string()).optional(),
    // Model ids (the raw `model` string a harness reports, e.g.
    // `claude-opus-4-1`) the tenant has PROHIBITED. The plugin refuses to switch
    // a session onto one (PreModelSwitch) and refuses a turn that would run on
    // one (UserPromptSubmit). Optional so an older backend — and an older
    // on-disk cache — still parses; consumers read `?? []`, which is the
    // unenforced behaviour that predates this field and the safe direction to
    // default.
    //
    // Ids, not display names: the governance decision is keyed on the exact
    // string the harness reports (`model_status_override.versionId` in the
    // control plane), so no name resolution stands between the decision and the
    // comparison.
    prohibitedModels: z.array(z.string()).optional(),
    customKeywords: z.array(z.string()),
    fetchedAt: z.iso.datetime(),
  })
  .meta({ id: 'PolicyBundle' });
export type PolicyBundle = z.infer<typeof PolicyBundle>;

/**
 * Which bundle fields THIS build understands, as one stable string.
 *
 * Derived from the schema's own keys rather than written by hand. A field added
 * above moves this value with no second edit, which is the entire point: a
 * constant somebody has to remember to bump goes stale on exactly the commit
 * that widened the shape, which is the one commit where it has to be right.
 *
 * It exists because "an older on-disk cache still parses" — said of every
 * optional field above — is only half of what an older cache does. Zod drops a
 * key the schema does not declare, so a body cached by a build that predated a
 * field is missing it, while still carrying the `version` of a served
 * representation that HAD it. The bundle is fetched conditionally, so the
 * control plane answers every later poll with 304 Not Modified and the reader
 * is handed back the same narrowed body: the field can never arrive, however
 * often the device polls and however new the plugin gets. Stamping the cache
 * lets a reader tell a body its own build produced from one an older build
 * narrowed, and pay a single unconditional refetch instead of being told
 * forever that nothing has changed.
 *
 * NESTED KEYS ARE INCLUDED, and the top level alone would not have been enough.
 * `Policy` and `ExceptionBundleEntry` are plain objects, so Zod narrows them
 * exactly as it narrows the bundle — while `policies` and `exceptions` stay one
 * unchanged key each. A build that widens `Policy` therefore moves no top-level
 * key, its stamp reads as a match, and the same 304 replays the same narrowed
 * policies: the identical trap one level down. `Policy.provenance` is the
 * worked example, and it decides whether a device may locally re-assign a rule
 * the deployment has authored.
 *
 * `PolicyTarget` is walked through its UNION MEMBERS for the same reason, and
 * it is the easiest of the three to overlook: `policies.target` is one key
 * whatever the target holds, so widening either member moves nothing the other
 * walks see. The comment above this schema records that a `{ packId }` variant
 * was considered and expressed as per-rule policies instead — the kind of
 * decision that gets revisited, which is exactly when this would matter.
 *
 * `Rule` is deliberately absent. It is a `strictObject`, so a widened rule
 * fails the parse outright instead of being narrowed in silence — a loud
 * failure needs no stamp to detect it.
 *
 * Keys, not their types. Fields here get ADDED; a field retyped under an
 * unchanged name at a depth this does not walk is not a case it separates, and
 * claiming otherwise would make it read as a schema checksum, which it is not.
 */
export const POLICY_BUNDLE_SHAPE_ID: string = [
  ...Object.keys(PolicyBundle.shape),
  ...Object.keys(Policy.shape).map((key) => `policies.${key}`),
  ...PolicyTarget.options
    // `shape` GUARDED, and the guard is the load-bearing half. This expression
    // runs at module load in a package every hook script bundles, so a union
    // member that is not a plain object would not merely go unstamped — it
    // would throw on import and take every hook with it, which is the one thing
    // this plugin may never do. A non-object member contributes nothing here
    // and is a deliberate gap for whoever adds one to close.
    .flatMap((member) => ('shape' in member ? Object.keys(member.shape) : []))
    .map((key) => `policies.target.${key}`),
  ...Object.keys(ExceptionBundleEntry.shape).map((key) => `exceptions.${key}`),
]
  .sort()
  .join(',');

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

// Single source of truth for the built-in policy ids, declared in display order
// (monitor → warn → redact → vault → block, least → most restrictive). This one runtime
// array feeds the Zod enum (BuiltinPolicyId), PATCH membership validation, the
// catalog display order (BUILTIN_ORDER), and the catalog keys (BUILTIN_POLICIES) —
// so the literal set is declared exactly once here.
export const KNOWN_BUILTIN_IDS = ['monitor', 'warn', 'redact', 'vault', 'block'] as const;

export const BuiltinPolicyId = z.enum(KNOWN_BUILTIN_IDS).meta({ id: 'BuiltinPolicyId' });
export type BuiltinPolicyId = z.infer<typeof BuiltinPolicyId>;

// What a `redact` decision degrades to on a field the host cannot rewrite in
// place (WorkspaceSettings.redactFallback).
//
// An `.extract()` over the built-in ids rather than a fresh `z.enum` of the
// same three strings, for the reason CLAUDE.md §2 gives about the harness
// vocabulary: a subset spelled again is a subset free to drift, and this one
// has to stay inside the action ladder so `strongerAction` can merge a
// control-plane value raise-only without a second rank order being invented.
// 'redact' and 'vault' are excluded because they are the thing that could not
// be carried out; the three that remain are what is left to choose between.
export const RedactFallback = BuiltinPolicyId.extract(['monitor', 'warn', 'block']).meta({
  id: 'RedactFallback',
});
export type RedactFallback = z.infer<typeof RedactFallback>;

// Display order of the built-in catalog. Aliases the canonical id set (already
// declared least → most restrictive) so display order can never drift from
// membership; kept as a named export for call sites that read it as display order.
export const BUILTIN_ORDER: readonly BuiltinPolicyId[] = KNOWN_BUILTIN_IDS;

// Name/description/action for each built-in archetype, keyed by id. The
// `Record<BuiltinPolicyId, …>` constraint forces this to stay exhaustive with
// KNOWN_BUILTIN_IDS, so adding a builtin is a single coordinated edit (id set +
// this spec) rather than three synchronized literals.
//
// `reversible` is a SECOND axis over the same enforcement action, not a third
// action. Two archetypes share `action: 'redact'` and differ only in what
// happens to the value that was stripped: Redact destroys it one-way, Redact &
// Vault keeps a recoverable encrypted copy under ~/.aka and leaves a pointer in
// its place. Modelling it here rather than as a fifth ActionTaken is deliberate
// — ActionTaken is a stored column and a wire enum switched on by if/else-if
// chains with no exhaustiveness check, so a new member falls through to allow;
// a new BuiltinPolicyId is caught by this Record at compile time.
//
// Declared with `as const satisfies` rather than a type ANNOTATION. The
// annotation widened `reversible` to `boolean`, which erased at the type level
// exactly the fact CategoryPolicyId is derived from — so the narrowing below
// compiled to the full union and enforced nothing. `satisfies` keeps the
// exhaustiveness check this comment relies on while preserving the literals.
const BUILTIN_POLICY_SPECS = {
  monitor: {
    name: 'Monitor',
    action: 'log',
    reversible: false,
    description: 'Log every match for audit. The request is allowed through untouched.',
  },
  warn: {
    name: 'Warn',
    action: 'warn',
    reversible: false,
    description: 'Allow the request, but warn the user inline before it is sent.',
  },
  redact: {
    name: 'Redact',
    action: 'redact',
    reversible: false,
    description:
      'Strip the matched value from the request and destroy it, then continue. What was ' +
      'removed cannot be recovered.',
  },
  vault: {
    name: 'Redact & Vault',
    action: 'redact',
    reversible: true,
    description:
      'Strip the matched value from the request and keep an encrypted, recoverable copy in ' +
      'the local vault, leaving a pointer in its place. Needs the vault consent granted under ' +
      'Settings; without it this behaves as Redact.',
  },
  block: {
    name: 'Block',
    action: 'block',
    reversible: false,
    description: 'Refuse the request entirely whenever any rule in this detection matches.',
  },
} as const satisfies Record<
  BuiltinPolicyId,
  { name: string; description: string; action: ActionTaken; reversible: boolean }
>;

// The archetypes that carry reversibility, derived AT THE TYPE LEVEL from the
// specs above. This is what makes CategoryPolicyId a real narrowing rather than
// an alias for the full union.
type ReversibleBuiltinId = {
  [K in BuiltinPolicyId]: (typeof BUILTIN_POLICY_SPECS)[K]['reversible'] extends true ? K : never;
}[BuiltinPolicyId];

/** A policy id the per-CATEGORY axis can express — every archetype but the reversible ones. */
export type CategoryExpressibleId = Exclude<BuiltinPolicyId, ReversibleBuiltinId>;

// Maps the palette BuiltinPolicyId (monitor/warn/redact/block) to the ActionTaken
// enum actually stored on policies.action (warn/redact/block/allow/log).
// monitor -> log; warn/redact/block are identity. Derived from
// BUILTIN_POLICY_SPECS so the mapping can never drift from the catalog.
export function builtinPolicyToAction(id: BuiltinPolicyId): ActionTaken {
  return BUILTIN_POLICY_SPECS[id].action;
}

// ─── The one enforcement-strength ladder ────────────────────────────────────
//
// WEAKEST → STRONGEST, each stored action exactly once. Three private copies of
// this ordering existed before it was named here (a worst-first array in the
// runtime's decision collapse, an identical one in the posture differ, and a
// rank map in the attached-mode merge); they are the same fact and now derive
// from this.
//
// Built in two halves rather than listed, for the reason the catalog itself is:
//
//   1. The PALETTE half is `KNOWN_BUILTIN_IDS` mapped through the catalog's own
//      `builtinPolicyToAction`, so a change to an archetype's action moves the
//      ladder with it. The mapping is MANY-TO-ONE — 'redact' and 'vault' share
//      `action: 'redact'` and differ only on the reversibility axis — so the
//      Set dedupe is load-bearing, not tidying: a repeated rung would make
//      `indexOf` answer with the first and leave the second unreachable.
//   2. Everything ActionTaken carries that the palette cannot express sits
//      BELOW the palette, derived by set difference rather than listed. That
//      keeps the ladder total over the enum BY CONSTRUCTION, and it means an
//      ActionTaken member added later lands at the weakest rung — where it
//      cannot quietly outrank enforcement nobody has ranked it against.
//
// Today that is ['allow', 'log', 'warn', 'redact', 'block'].
const PALETTE_WEAKEST_FIRST: readonly ActionTaken[] = [
  ...new Set(KNOWN_BUILTIN_IDS.map(builtinPolicyToAction)),
];

const BELOW_PALETTE: readonly ActionTaken[] = ACTION_TAKEN_KEYS.filter(
  (action) => !PALETTE_WEAKEST_FIRST.includes(action),
);

export const ACTION_STRENGTH_ORDER: readonly ActionTaken[] = [
  ...BELOW_PALETTE,
  ...PALETTE_WEAKEST_FIRST,
];

/**
 * How strong an action is; higher is more restrictive. Index into
 * ACTION_STRENGTH_ORDER, so it moves with the catalog.
 *
 * Takes `string`, not `ActionTaken`, deliberately: an action can arrive from a
 * store column with no enum constraint, and an unrecognised one must rank BELOW
 * every real action (-1) rather than throw or be coerced. A comparison against
 * an unknown then reads "weaker than anything", which is the only answer that
 * cannot silently license enforcement the value never asked for.
 */
export function actionRank(action: string): number {
  return ACTION_STRENGTH_ORDER.indexOf(action as ActionTaken);
}

/** Whether `action` is at least as restrictive as `floor`. */
export function isActionAtLeast(action: string, floor: ActionTaken): boolean {
  return actionRank(action) >= actionRank(floor);
}

/** The stronger of two actions. */
export function strongerAction(a: ActionTaken, b: ActionTaken): ActionTaken {
  return actionRank(a) >= actionRank(b) ? a : b;
}

/**
 * The weakest built-in archetype whose action is at least `floor` — the inverse
 * of `builtinPolicyToAction`, used to state a per-detection floor in the terms
 * the user actually picks from.
 *
 * Walks KNOWN_BUILTIN_IDS in its declared least → most order and takes the
 * first match, so 'redact' wins over 'vault' where both satisfy the floor: the
 * two share an action and differ only on custody, and a floor is a statement
 * about ENFORCEMENT, never a demand that a value be retained. Returns 'block'
 * when nothing satisfies the floor, which cannot happen while 'block' is the
 * strongest archetype but keeps the function total.
 */
export function weakestBuiltinAtLeast(floor: ActionTaken): BuiltinPolicyId {
  return (
    KNOWN_BUILTIN_IDS.find((id) => isActionAtLeast(builtinPolicyToAction(id), floor)) ?? 'block'
  );
}

/**
 * What a connected control plane imposes on ONE installed pack ("detection").
 *
 * Computed by the local store — it needs the machine's settings and its rule
 * snapshot — and then read by surfaces that never touch the store: the pack
 * picker greys out what is below the floor, the list marks what the
 * organization decided. Declared HERE because it is the whole of what crosses
 * between them, and a second declaration on the far side would agree only for
 * as long as someone kept it agreeing — a field added to one side compiles on
 * both while the other quietly drops it.
 *
 * The absence of a constraint is `null` at every call site, never a member of
 * this shape: a machine nothing manages has no floor, and modelling that as a
 * floor of Monitor would put an organizational statement on screen where the
 * organization made none.
 */
export const PackPolicyFloor = z
  .object({
    /**
     * The weakest archetype the device may assign. Stated as a BuiltinPolicyId
     * rather than a raw ActionTaken because that is the vocabulary the user
     * picks from — a floor a UI cannot name is one it cannot explain.
     */
    floor: BuiltinPolicyId,
    /**
     * True when the organization AUTHORED a policy governing this pack rather
     * than stating a minimum: it gave the answer, so the pack is not
     * re-assignable locally in either direction.
     */
    locked: z.boolean(),
  })
  // Deliberately NO `.meta({ id })`, for the reason the vault shapes carry: an
  // id registers the schema globally and a swagger setup emits it as an OpenAPI
  // component. This is what an attached DEVICE computes for itself from a bundle
  // it already holds — no route serves it, so publishing it would advertise a
  // component the API never returns.
  .describe('PackPolicyFloor');
export type PackPolicyFloor = z.infer<typeof PackPolicyFloor>;

// The archetypes a per-CATEGORY policy row can actually express.
//
// That row stores an ActionTaken — the enforcement verb alone — so an archetype
// whose meaning also depends on the reversibility axis cannot survive the trip:
// it would be written as its bare action and the other half silently dropped.
// Derived from the specs rather than listed, so a future reversible archetype is
// excluded automatically instead of being remembered.
//
// The PACK axis (installed_packs.policy_id) stores the BuiltinPolicyId itself and
// therefore carries every archetype; this narrowing applies only to the category
// fallback and to anything that feeds it.
export const CATEGORY_EXPRESSIBLE_IDS = KNOWN_BUILTIN_IDS.filter(
  (id) => !BUILTIN_POLICY_SPECS[id].reversible,
) as readonly CategoryExpressibleId[];

// The archetypes that axis CANNOT express — the complement, also derived, so the
// two together are exhaustive by construction.
export const CATEGORY_INEXPRESSIBLE_IDS = KNOWN_BUILTIN_IDS.filter(
  (id) => BUILTIN_POLICY_SPECS[id].reversible,
) as readonly BuiltinPolicyId[];

/**
 * A policy id valid on the per-CATEGORY axis. Rejects an archetype that axis
 * cannot store, rather than accepting it and writing something weaker — which
 * is the failure this exists to prevent: a caller asking for Redact & Vault and
 * silently getting plain Redact, with nothing recording that the choice was
 * downgraded.
 */
export const CategoryPolicyId = z
  // The element type is the DERIVED narrow union, not BuiltinPolicyId. Casting
  // to the wide one re-declared every member as the whole union, so `z.infer`
  // gave back the full set and `writeStandingSecretPosture('vault')` compiled
  // clean while the runtime refused it.
  .enum(CATEGORY_EXPRESSIBLE_IDS as [CategoryExpressibleId, ...CategoryExpressibleId[]])
  .meta({ id: 'CategoryPolicyId' });
export type CategoryPolicyId = z.infer<typeof CategoryPolicyId>;

// Whether a built-in archetype keeps the value it strips. The companion to
// builtinPolicyToAction on the second axis: `action` says what happens to the
// REQUEST, this says what happens to the VALUE. Derived from the same specs so
// the two can never disagree about an id.
export function builtinPolicyIsReversible(id: BuiltinPolicyId): boolean {
  return BUILTIN_POLICY_SPECS[id].reversible;
}

// The reversibility a PACK's assigned built-in policy resolves to — the exact
// companion of policyIdToAction below, and unknown/unassigned coalesces the same
// way (to DEFAULT_PACK_POLICY_ID, which is not reversible). Every consumer
// resolves through this, so a detection's Redact-vs-Redact & Vault choice reads
// identically on every surface.
export function policyIdIsReversible(policyId: string | null | undefined): boolean {
  const parsed = BuiltinPolicyId.safeParse(policyId ?? DEFAULT_PACK_POLICY_ID);
  const id: BuiltinPolicyId = parsed.success ? parsed.data : DEFAULT_PACK_POLICY_ID;
  return builtinPolicyIsReversible(id);
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
  {
    id: BuiltinPolicyId;
    name: string;
    description: string;
    action: ActionTaken;
    reversible: boolean;
  }
> = Object.fromEntries(
  KNOWN_BUILTIN_IDS.map((id) => [id, { id, ...BUILTIN_POLICY_SPECS[id] }]),
) as Record<
  BuiltinPolicyId,
  {
    id: BuiltinPolicyId;
    name: string;
    description: string;
    action: ActionTaken;
    reversible: boolean;
  }
>;

// The "Actively redact" onboarding preset: a per-category built-in policy id
// for every detection category, written as real policy rows via
// applyCategoryPosture.
export const FULL_ENFORCEMENT_POSTURE: Record<DetectionCategory, BuiltinPolicyId> = {
  secret: 'block',
  pii: 'redact',
  financial: 'redact',
  phi: 'redact',
  code_flaw: 'warn',
  custom: 'warn',
  code_context: 'warn',
  config: 'warn',
};

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
/**
 * A per-pack policy id as a USER reads it — the archetype's NAME from this
 * catalog. The display sibling of policyIdToAction and policyIdIsReversible,
 * coalescing identically: an unassigned pack reads as the catalog default, and
 * an id the catalog does not carry (a custom policy) is returned verbatim
 * rather than misreported as a built-in — least of all as Monitor, which would
 * read as log-only for a policy that may block.
 *
 * It lives here because four surfaces render this one value — `aka detections`,
 * and the three plugins' detection tables — and each had its own copy of the
 * resolver. That is the same defect this catalog exists to prevent, one level
 * down: a change to the coalescing rule or the custom-id fallback would have to
 * land in four files, with nothing checking that it did.
 */
export function policyDisplayName(policyId: string | null | undefined): string {
  const id = policyId ?? DEFAULT_PACK_POLICY_ID;
  const parsed = BuiltinPolicyId.safeParse(id);
  return parsed.success ? BUILTIN_POLICIES[parsed.data].name : id;
}

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

// The built-in policy catalog as a list. Lives here, beside the item shape it
// wraps, because the local store's policy-catalog port returns exactly this —
// see `getPolicyList` in @akasecurity/persistence.
export const ListPoliciesResponse = z
  .object({ items: z.array(PolicyListItem) })
  .meta({ id: 'ListPoliciesResponse' });
export type ListPoliciesResponse = z.infer<typeof ListPoliciesResponse>;

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
