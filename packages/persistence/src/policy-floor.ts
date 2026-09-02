/**
 * What an ATTACHED machine's control plane forbids the device to undo.
 *
 * On a standalone machine the per-detection Monitor/Warn/Redact/Block choice is
 * entirely the user's. On an attached one the organization's bundle is a FLOOR:
 * the device may raise a pack above what the control plane asks for, but never
 * set one below it, and a pack the organization has AUTHORED a policy for is not
 * locally re-assignable at all.
 *
 * Two properties make that floor honest rather than decorative:
 *
 *   It is computed HERE, below the one write path, not on the surface that
 *   renders the picker. A refusal that lived in the dashboard would leave the
 *   CLI and every other local caller writing whatever they liked, and the
 *   attached runtime's raise-only merge would then be silently papering over a
 *   stored assignment the user believes is in force. That merge stays where it
 *   is — it is the second line of defence, and it is the only one that binds a
 *   store written before this refusal existed.
 *
 *   It refuses by THROWING (see PolicyFloorError). Writing a different value
 *   than the caller asked for would leave a user staring at a picker that
 *   silently snaps back, with nothing on screen able to say why.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { ActionTaken, BuiltinPolicyId, Policy } from '@akasecurity/schema';
import {
  builtinPolicyToAction,
  DEFAULT_ACTIONS,
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

/** Why an assignment was refused: the pack is below the floor, or it is locked. */
export type PolicyFloorRefusal = 'floor' | 'lock';

/** What the control plane imposes on ONE installed pack. */
export interface PackPolicyFloor {
  /**
   * The weakest built-in archetype the device may assign. Stated as a
   * BuiltinPolicyId rather than a raw action because that is the vocabulary the
   * user actually picks from — a floor a UI cannot name is one it cannot
   * explain.
   */
  readonly floor: BuiltinPolicyId;
  /**
   * True when an AUTHORED control-plane policy governs one of this pack's
   * rules. Such a pack is not re-assignable locally at all, in either
   * direction: the organization did not state a minimum, it stated the answer.
   */
  readonly locked: boolean;
}

/**
 * A refused pack-policy assignment, carrying everything a surface needs to say
 * why without re-deriving it.
 *
 * Modelled on ManagedFieldError, and for the same reason: a caller that cannot
 * distinguish "you may not write this" from "the write failed" has to report
 * both as breakage, and an administrative constraint reported as breakage reads
 * as a bug in the product rather than a decision by the user's own organization.
 */
export class PolicyFloorError extends Error {
  /** `namespace/packId` of the detection whose assignment was refused. */
  readonly pack: string;
  /** What the caller asked for; null is the "clear the assignment" write. */
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
    super(
      refusal === 'lock'
        ? `refusing to re-assign '${pack}': its policy is set by the connected control plane`
        : `refusing to set '${pack}' to '${attempted ?? 'unassigned'}': the connected control ` +
            `plane requires at least '${floor}'`,
    );
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
 * Whether an AUTHORED remote policy reaches any of this pack's rules.
 *
 * Scans EVERY enabled policy rather than the first-write-wins index above: an
 * authored policy sitting behind a built-in one on the same key still expresses
 * the organization's decision about this detection, and reading only the
 * index's winner would let the ordering of a bundle decide whether a pack is
 * locked. Erring toward locked only ever adds a refusal, never relaxes one.
 */
function hasAuthoredPolicy(policies: readonly Policy[], rules: readonly FloorRule[]): boolean {
  const ruleIds = new Set(rules.map((rule) => rule.id));
  const categories = new Set(rules.map((rule) => rule.category));
  return policies.some((policy) => {
    // `kind` is optional on the wire and absent reads as 'builtin' — an older
    // producer never authored anything, so it can never lock.
    if (!policy.enabled || policy.kind !== 'custom') return false;
    return 'ruleId' in policy.target
      ? ruleIds.has(policy.target.ruleId)
      : categories.has(policy.target.category);
  });
}

/**
 * The floor the connected control plane imposes on one installed pack, or null
 * when it imposes none.
 *
 * Null on three counts, all of which mean "this machine is its own authority":
 * the pack contributes no rules for a policy to reach; the machine is not
 * attached; or there is no usable cached bundle. The attachment gate is checked
 * even though detach deletes the cache — a leftover file (an interrupted
 * detach, a restored backup, a hand copy) must not go on governing a machine
 * nothing manages any more, and the settings descriptor is the fact that says
 * whether anything does.
 *
 * Resolution per rule mirrors the runtime's: a ruleId-targeted policy beats a
 * category-targeted one, and a rule no policy names falls back to the
 * compiled-in DEFAULT_ACTIONS for its category. The pack's floor is the
 * STRONGEST across its rules, because one pack carries one assignment and the
 * weaker choice would leave the rule the organization cares most about
 * under-enforced.
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
  if (rules.length === 0) return null;
  let action: ActionTaken | null = null;
  for (const rule of rules) {
    // The category comes from a stored snapshot and is therefore an arbitrary
    // string here; treat the lookup as possibly-missing so an unrecognised one
    // lands on the same 'log' fallback the runtime uses rather than undefined.
    const defaults = DEFAULT_ACTIONS as Partial<Record<string, ActionTaken>>;
    const resolved =
      byRuleId.get(rule.id) ?? byCategory.get(rule.category) ?? defaults[rule.category] ?? 'log';
    action = action === null ? resolved : strongerAction(action, resolved);
  }

  return {
    // `action` is non-null: the empty-rules case returned above.
    floor: weakestBuiltinAtLeast(action ?? 'log'),
    locked: hasAuthoredPolicy(policies, rules),
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
