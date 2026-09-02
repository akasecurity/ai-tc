/**
 * What an ATTACHED machine's control plane forbids the device to undo.
 *
 * On a standalone machine the per-detection Monitor/Warn/Redact/Block choice is
 * entirely the user's. On an attached one the organization's bundle is a FLOOR:
 * the device may raise a pack above what the control plane asks for, but never
 * set one below it, and a pack whose answer the organization has AUTHORED is not
 * locally re-assignable at all. A pack the bundle governs at ALL may not be
 * switched OFF either, whatever archetype it carries — switching a detection off
 * sits below every one of them, so it is the one move no floor could ever
 * permit. All three constraints come from what the bundle actually says — a pack
 * it never reaches stays entirely the user's, exactly as on a standalone
 * machine.
 *
 * Two properties make that floor honest rather than decorative:
 *
 *   It is computed HERE, below the device-local write paths, not on the surface
 *   that renders the picker. A refusal that lived in the dashboard would leave
 *   the CLI and every other local caller writing whatever they liked, and the
 *   attached runtime's raise-only merge would then be silently papering over a
 *   stored assignment the user believes is in force. That merge stays where it
 *   is — it is the second line of defence, and it is the only one that binds a
 *   store written before this refusal existed. It does not reach the switch-off,
 *   which is why that one is refused here or nowhere.
 *
 *   It refuses by THROWING (see PolicyFloorError). Writing a different value
 *   than the caller asked for would leave a user staring at a picker that
 *   silently snaps back, with nothing on screen able to say why.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { ActionTaken, BuiltinPolicyId, PackPolicyFloor, Policy } from '@akasecurity/schema';
import {
  builtinPolicyToAction,
  DEFAULT_PACK_POLICY_ID,
  isActionAtLeast,
  isAttached,
  PolicyBundle,
  strongerAction,
  weakestBuiltinAtLeast,
} from '@akasecurity/schema';

import { POLICY_CACHE_FILENAME } from './attached-derived.ts';
import { dataDir, defaultDataDir } from './local-layout.ts';
import { readWorkspaceSettings } from './settings.ts';

/**
 * One rule of the pack whose floor is being computed — the only two fields the
 * resolution reads. Deliberately not `Rule`: callers hand this over from a
 * stored snapshot whose rows were validated on write, and demanding the full
 * shape would make a corrupt-but-addressable row unable to contribute a floor.
 */
export interface FloorRule {
  readonly id: string;
  readonly category: string;
}

/**
 * Why a device-local write to a governed pack was refused.
 *
 * Three members rather than two, because the three have different remedies and
 * a reader who cannot tell them apart takes the wrong one. `floor` says the
 * archetype asked for is too weak — pick a stronger one. `lock` says no
 * archetype is available, because the organization wrote this detection's
 * answer. `disable` is not about an archetype at all: the write was a switch-off
 * of a governed detection, and the remedy is neither of the other two's. Folding
 * it into `floor` would send someone to a picker they never opened; folding it
 * into `lock` would claim the organization had set a policy it may only have
 * stated a minimum for.
 */
export type PolicyFloorRefusal = 'floor' | 'lock' | 'disable';

/**
 * What the control plane imposes on ONE installed pack.
 *
 * Re-exported from the schema rather than declared, because the surfaces that
 * render this constraint receive it as a plain prop and must be reading the
 * same shape this module produces — see `PackPolicyFloor` there.
 */
export type { PackPolicyFloor };

/**
 * One sentence per refusal, each naming the organization as the author of the
 * constraint. These reach a user — through a CLI's stderr as readily as through
 * a page — so none of them may read as a product fault or as this machine
 * having decided anything.
 */
function refusalMessage(
  pack: string,
  attempted: BuiltinPolicyId | null,
  floor: BuiltinPolicyId,
  refusal: PolicyFloorRefusal,
): string {
  switch (refusal) {
    case 'lock':
      return `refusing to re-assign '${pack}': its policy is set by the connected control plane`;
    case 'disable':
      // Deliberately says nothing about the floor: what forbids this is that
      // the control plane governs the detection at all, and quoting a minimum
      // here would invite the reader to satisfy it and try again.
      return `refusing to disable '${pack}': it is governed by the connected control plane`;
    case 'floor':
      return (
        `refusing to set '${pack}' to '${attempted ?? 'unassigned'}': the connected control ` +
        `plane requires at least '${floor}'`
      );
  }
}

/**
 * A refused device-local write to a governed pack, carrying everything a
 * surface needs to say why without re-deriving it.
 *
 * Modelled on ManagedFieldError, and for the same reason: a caller that cannot
 * distinguish "you may not write this" from "the write failed" has to report
 * both as breakage, and an administrative constraint reported as breakage reads
 * as a bug in the product rather than a decision by the user's own organization.
 */
export class PolicyFloorError extends Error {
  /** `namespace/packId` of the detection whose write was refused. */
  readonly pack: string;
  /**
   * The archetype the caller asked for, or null when the write named none —
   * clearing the assignment, or switching the detection off.
   */
  readonly attempted: BuiltinPolicyId | null;
  /** The weakest archetype the control plane permits for this pack. */
  readonly floor: BuiltinPolicyId;
  readonly refusal: PolicyFloorRefusal;

  constructor(
    pack: string,
    attempted: BuiltinPolicyId | null,
    floor: BuiltinPolicyId,
    refusal: PolicyFloorRefusal,
  ) {
    super(refusalMessage(pack, attempted, floor, refusal));
    this.name = 'PolicyFloorError';
    this.pack = pack;
    this.attempted = attempted;
    this.floor = floor;
    this.refusal = refusal;
  }
}

/**
 * The cached control-plane bundle, or null when there is not a usable one.
 *
 * FAIL-OPEN ON THE READ, deliberately. Absent, unreadable, truncated, written
 * by a producer this build cannot parse — every one of them yields null, which
 * means NO floor and therefore no refusal. The alternative fails a freshly
 * attached machine closed: it has no cache until its first sync lands, so a
 * missing file read as "refuse everything" would leave the user unable to
 * configure the machine they just attached, with the only fix being a sync that
 * has not happened yet. A floor that arrives one sync late is recoverable; a
 * device that cannot be configured at all is not — and the attached runtime's
 * raise-only merge still clamps enforcement in the meantime.
 */
export function readCachedPolicyBundle(base: string = defaultDataDir()): PolicyBundle | null {
  try {
    const raw = readFileSync(join(dataDir(base), POLICY_CACHE_FILENAME), 'utf8');
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return null;
    return PolicyBundle.parse((parsed as { bundle?: unknown }).bundle);
  } catch {
    // See above: no usable cache is no floor, never a closed door.
    return null;
  }
}

/**
 * Index the bundle's ENABLED policies exactly as the runtime does — two
 * separate namespaces, first-write-wins within each — so the floor this module
 * states and the action the runtime resolves cannot disagree about which policy
 * won. Disabled rows are skipped for the same reason the runtime skips them:
 * they cannot affect resolution, so they cannot impose a floor either.
 */
function indexEnabled(policies: readonly Policy[]): {
  byRuleId: Map<string, ActionTaken>;
  byCategory: Map<string, ActionTaken>;
} {
  const byRuleId = new Map<string, ActionTaken>();
  const byCategory = new Map<string, ActionTaken>();
  for (const policy of policies) {
    if (!policy.enabled) continue;
    if ('ruleId' in policy.target) {
      if (!byRuleId.has(policy.target.ruleId)) byRuleId.set(policy.target.ruleId, policy.action);
    } else if (!byCategory.has(policy.target.category)) {
      byCategory.set(policy.target.category, policy.action);
    }
  }
  return { byRuleId, byCategory };
}

/**
 * Whether an AUTHORED remote policy decides THIS pack's answer.
 *
 * Scans EVERY enabled policy rather than the first-write-wins index: an
 * authored policy sitting behind a built-in one on the same key still expresses
 * the organization's decision about this detection, and reading only the
 * index's winner would let the ordering of a bundle decide whether a pack is
 * locked.
 *
 * The two target kinds do NOT lock alike, because they do not say the same
 * thing about a pack:
 *
 *   A ruleId-targeted authored policy names a rule this pack owns. There is
 *   nothing left to interpret — the organization wrote the answer for this
 *   detection, so it locks.
 *
 *   A category-targeted one names a taxonomy, and a category spans many packs
 *   (secret → secrets, secrets-infra, and anything a user pulled or wrote
 *   themselves). Read as a lock on membership alone, one authored
 *   `{ category: 'secret' }` would take the Detections page away for every pack
 *   carrying any secret rule, including packs the control plane has never seen
 *   — greying out even the archetype already stored, under a message saying the
 *   organization set it. So it locks only where the bundle demonstrably reaches
 *   this pack: at least one of the pack's rules is named by RULE id somewhere in
 *   the bundle. That is the signal that the control plane has this detection in
 *   hand at all — a pack it governs arrives expanded into one ruleId-targeted
 *   policy per rule (see PolicyTarget in the schema) — and it is a fact about
 *   the bundle, not about which policy happens to win the index.
 *
 * Note this narrows the LOCK only. A category policy still contributes its
 * action to the floor for every rule it matches, governed or not: a minimum
 * stated per category means what it says, and raising above it stays the
 * device's to do.
 */
function hasAuthoredPolicy(
  policies: readonly Policy[],
  rules: readonly FloorRule[],
  byRuleId: ReadonlyMap<string, ActionTaken>,
): boolean {
  const ruleIds = new Set(rules.map((rule) => rule.id));
  const categories = new Set(rules.map((rule) => rule.category));
  const bundleNamesPack = rules.some((rule) => byRuleId.has(rule.id));
  return policies.some((policy) => {
    // `provenance` is optional on the wire and absent reads as 'builtin' — an
    // older producer never authored anything, so it can never lock.
    if (!policy.enabled || policy.provenance !== 'authored') return false;
    return 'ruleId' in policy.target
      ? ruleIds.has(policy.target.ruleId)
      : bundleNamesPack && categories.has(policy.target.category);
  });
}

/**
 * The floor the connected control plane imposes on one installed pack, or null
 * when it imposes none.
 *
 * Null on four counts, all of which mean "this machine is its own authority":
 * the pack contributes no rules for a policy to reach; no remote policy names
 * any rule it does contribute; the machine is not attached; or there is no
 * usable cached bundle. The attachment gate is checked even though detach
 * deletes the cache — a leftover file (an interrupted detach, a restored
 * backup, a hand copy) must not go on governing a machine nothing manages any
 * more, and the settings descriptor is the fact that says whether anything does.
 *
 * ONLY AN ACTUAL REMOTE POLICY RAISES THE FLOOR. Per rule that is a
 * ruleId-targeted policy, else a category-targeted one — the runtime's own
 * precedence, so the two cannot disagree about which policy won — and a rule
 * the bundle does not name at all contributes NOTHING. It deliberately does not
 * fall through to the compiled-in DEFAULT_ACTIONS the way the runtime's
 * resolution does, because a floor is a claim about what the ORGANIZATION
 * requires, and the compiled-in default is precisely the part the organization
 * did not say. Falling through made every attached machine refuse Monitor for
 * every secret pack the bundle never mentioned, citing a Warn the control plane
 * had not asked for — while what ran for that pack was Monitor, since the
 * runtime's raise-only merge has no remote action to raise to either.
 *
 * The pack's floor is the STRONGEST across the rules a policy does name,
 * because one pack carries one assignment and the weaker choice would leave the
 * rule the organization cares most about under-enforced.
 *
 * Note the runtime additionally clamps a remote policy UP to DEFAULT_ACTIONS
 * before enforcing it. This does not, so a bundle that names a rule with
 * something weaker than its category default yields a floor weaker than what
 * actually runs. That direction is the safe one: it refuses less, never more,
 * and the runtime — not this module — is the enforcement authority.
 */
export function controlPlanePolicyFloor(
  rules: readonly FloorRule[],
  base: string = defaultDataDir(),
): PackPolicyFloor | null {
  const floors = openControlPlaneFloors(base);
  return floors === null ? null : floors.floorFor(rules);
}

/**
 * The same resolution, prepared ONCE for a caller with several packs to answer
 * for — a page listing every detection asks per pack, and the per-pack entry
 * point above re-reads settings.json, re-reads and re-parses the whole cached
 * bundle, and rebuilds both indexes on each of those calls. That is the entire
 * cost of the answer repeated N times for one render, and again on every
 * revalidation after a write.
 *
 * Null carries exactly what the per-pack null carries — not attached, or no
 * usable bundle — decided once here rather than per pack, since neither can
 * change between packs within one answer.
 */
export function openControlPlaneFloors(base: string = defaultDataDir()): ControlPlaneFloors | null {
  if (!isAttached(readWorkspaceSettings(base))) return null;
  const bundle = readCachedPolicyBundle(base);
  if (bundle === null) return null;
  const indexes = indexEnabled(bundle.policies);
  return { floorFor: (rules) => resolveFloor(rules, bundle.policies, indexes) };
}

/** A control-plane floor resolver over one already-read bundle. */
export interface ControlPlaneFloors {
  floorFor(rules: readonly FloorRule[]): PackPolicyFloor | null;
}

function resolveFloor(
  rules: readonly FloorRule[],
  policies: readonly Policy[],
  { byRuleId, byCategory }: ReturnType<typeof indexEnabled>,
): PackPolicyFloor | null {
  let action: ActionTaken | null = null;
  for (const rule of rules) {
    // Both lookups may miss — a rule the bundle does not name, or a category
    // string a stored snapshot carries that no policy targets. A miss is not a
    // fallback here; it is the absence of anything to impose.
    const resolved = byRuleId.get(rule.id) ?? byCategory.get(rule.category);
    if (resolved === undefined) continue;
    action = action === null ? resolved : strongerAction(action, resolved);
  }
  // Nothing remote reached a single rule of this pack, so there is no floor —
  // and no lock either: an authored policy that matched would have landed in one
  // of the two indexes and left `action` set.
  if (action === null) return null;

  return {
    floor: weakestBuiltinAtLeast(action),
    locked: hasAuthoredPolicy(policies, rules, byRuleId),
  };
}

/**
 * Why `policyId` may not be assigned under `floor`, or null when it may be.
 *
 * The single definition of the refusal, so the repository that throws and the
 * surface that greys out an option can never disagree about which choices are
 * available. A null `policyId` — clearing the assignment — is judged as the
 * archetype an unassigned pack actually resolves to, not waved through: leaving
 * the column NULL enforces Monitor, and a clear that escaped the floor would be
 * the downgrade path every other write is refused for.
 */
export function policyAssignmentRefusal(
  policyId: BuiltinPolicyId | null,
  floor: PackPolicyFloor,
): PolicyFloorRefusal | null {
  if (floor.locked) return 'lock';
  const effective = policyId ?? DEFAULT_PACK_POLICY_ID;
  return isActionAtLeast(builtinPolicyToAction(effective), builtinPolicyToAction(floor.floor))
    ? null
    : 'floor';
}

/**
 * Why a pack under `floor` may not be switched to `enabled`, or null when it
 * may be.
 *
 * The asymmetry is the whole content: a DISABLE is refused for every governed
 * pack, whatever archetype the floor names, and a RE-ENABLE is never refused.
 * Disabling is not a weaker archetype, it is the absence of one — a disabled
 * pack contributes no rules to the local bundle at all, so the per-rule actions
 * the floor is stated over stop existing rather than being lowered. And what
 * covers a stored assignment that slipped below the floor does not cover this:
 * the attached runtime's raise-only merge re-supplies an ACTION for a rule, not
 * the rule itself, so a bundle carrying policies but no rules (`rules` is
 * optional on PolicyBundle) leaves a locally disabled detection simply not
 * running, with nothing left to clamp. Re-enabling moves toward what the
 * organization asked for and is therefore always the device's to do — including
 * for a LOCKED pack, whose lock is over which archetype the pack carries and
 * says nothing about whether it runs.
 *
 * Unlike `policyAssignmentRefusal` this also takes the ABSENCE of a floor and
 * answers null for it, so a surface holding an optional floor per row need not
 * spell that case out. Stated here rather than at the write path so what greys
 * the switch out and what throws cannot disagree about which way is open.
 */
export function packEnablementRefusal(
  enabled: boolean,
  floor: PackPolicyFloor | null,
): PolicyFloorRefusal | null {
  if (floor === null || enabled) return null;
  return 'disable';
}
