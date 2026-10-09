import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { ActionTaken, Policy, Rule } from '@akasecurity/schema';
import {
  DEFAULT_ACTIONS,
  DetectionCategory,
  MOD_POLICY_SNAPSHOT_MAX_BYTES,
  MOD_POLICY_SNAPSHOT_VERSION,
  ModPolicySnapshot,
} from '@akasecurity/schema';

import { ensureDataDirSync, writeOwnerOnlyFileSync } from './paths.ts';

// The file the Claude Code prompt.submit mod reads to reach the verdict the
// UserPromptSubmit command hook would. The mod has no Node and no store, so the
// store's resolved policy is written out here whenever it changes. The shape is
// the ModPolicySnapshot contract in @akasecurity/schema.
export const MOD_POLICY_SNAPSHOT_FILENAME = 'mod-policy.json';

/** `dataDir` is the folder holding aka.db (`~/.aka/data`), as PluginConfig.dataDir names it. */
export function modPolicySnapshotPath(dataDir: string): string {
  return join(dataDir, MOD_POLICY_SNAPSHOT_FILENAME);
}

/** What a snapshot is resolved from: the policies of a bundle, plus its ruleset. */
export interface ModPolicyInput {
  /** The complete effective ruleset; absent when the bundled packs are in force. */
  rules?: readonly Rule[] | undefined;
  /** Rule- and category-targeted policies, in precedence order (first enabled wins). */
  policies: readonly Pick<Policy, 'target' | 'action' | 'enabled'>[];
  /** Rules with an active exception grant. */
  exceptionRuleIds: Iterable<string>;
}

/**
 * Resolves a bundle's policies down to the lookups the mod applies. The reading
 * is the one createPolicyResolver gives a PolicyBundle (first enabled policy
 * wins, a rule beats its category, an unpoliced category takes DEFAULT_ACTIONS);
 * the verdict-parity suite in plugins/claude-code holds the two together.
 */
export function buildModPolicySnapshot(
  input: ModPolicyInput,
  generatedAt: Date = new Date(),
): ModPolicySnapshot {
  const byRule = new Map<string, ActionTaken>();
  const byCategory = new Map<string, ActionTaken>();
  for (const policy of input.policies) {
    if (!policy.enabled) continue;
    if ('ruleId' in policy.target) {
      if (!byRule.has(policy.target.ruleId)) byRule.set(policy.target.ruleId, policy.action);
    } else if (!byCategory.has(policy.target.category)) {
      byCategory.set(policy.target.category, policy.action);
    }
  }
  const categoryActions: Record<string, ActionTaken> = {};
  for (const category of DetectionCategory.options) {
    categoryActions[category] = byCategory.get(category) ?? DEFAULT_ACTIONS[category];
  }
  return {
    version: MOD_POLICY_SNAPSHOT_VERSION,
    generatedAt: generatedAt.toISOString(),
    // `examples` is documentation the mod never reads, and a custom pack's are
    // whatever its author pasted in, so they stay behind.
    ...(input.rules !== undefined ? { rules: input.rules.map(withoutExamples) } : {}),
    ruleActions: Object.fromEntries(byRule),
    categoryActions,
    exceptionRuleIds: [...new Set(input.exceptionRuleIds)].sort(),
  };
}

/** The ruleId-targeted policies an installed-pack snapshot contributes: one per assigned rule. */
export function assignedRuleActionPolicies(installed: {
  ruleActions: ReadonlyMap<string, ActionTaken>;
  assignedRules: ReadonlySet<string>;
}): Pick<Policy, 'target' | 'action' | 'enabled'>[] {
  const out: Pick<Policy, 'target' | 'action' | 'enabled'>[] = [];
  for (const [ruleId, action] of installed.ruleActions) {
    if (installed.assignedRules.has(ruleId))
      out.push({ target: { ruleId }, action, enabled: true });
  }
  return out;
}

function withoutExamples(rule: Rule): Rule {
  const copy = { ...rule };
  delete copy.examples;
  return copy;
}

function sameContent(a: ModPolicySnapshot, b: ModPolicySnapshot): boolean {
  return JSON.stringify({ ...a, generatedAt: '' }) === JSON.stringify({ ...b, generatedAt: '' });
}

/** The snapshot on disk, or null when it is missing, oversized, unparsable or invalid. */
export function readModPolicySnapshot(dataDir: string): ModPolicySnapshot | null {
  try {
    const text = readFileSync(modPolicySnapshotPath(dataDir), 'utf8');
    if (text.length > MOD_POLICY_SNAPSHOT_MAX_BYTES) return null;
    const parsed = ModPolicySnapshot.safeParse(JSON.parse(text));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/**
 * Writes the snapshot atomically (temp file, then rename) and owner-only, and
 * leaves the file alone when nothing but the timestamp would change, so the mod's
 * mtime cache is not invalidated by a rewrite of the same policy. Returns whether
 * it wrote. A snapshot over the size the mod will read is not written: the file
 * that is there stays, and the mod falls back to its bundled defaults on a
 * missing file just as it does on an oversized one.
 */
export function writeModPolicySnapshot(dataDir: string, snapshot: ModPolicySnapshot): boolean {
  const text = JSON.stringify(snapshot);
  if (Buffer.byteLength(text) > MOD_POLICY_SNAPSHOT_MAX_BYTES) return false;
  const existing = readModPolicySnapshot(dataDir);
  if (existing !== null && sameContent(existing, snapshot)) return false;
  ensureDataDirSync(dataDir);
  writeOwnerOnlyFileSync(modPolicySnapshotPath(dataDir), text);
  return true;
}

/** The slice of the installed-pack store the snapshot reads. */
export interface ModPolicySources {
  installedRuleset(): {
    installedPacks: number;
    enabledPacks: number;
    invalidRules: number;
    rules: Rule[];
    ruleActions: ReadonlyMap<string, ActionTaken>;
    assignedRules: ReadonlySet<string>;
  };
  readPolicies(): Pick<Policy, 'target' | 'action' | 'enabled'>[];
  activeExceptionRuleIds(): string[];
  /** The cached timing verdict for a regex rule's probe key, if one was recorded. */
  probeVerdict(ruleKey: string): 'safe' | 'quarantined' | undefined;
  /** The regex matchers the running binary ships, which CI has timed. */
  bundledRegexMatchers(): { pattern: string; flags: string }[];
}

/**
 * The cache key of a regex rule's timing verdict: the sha256 of its pattern and
 * flags. It is the same key the plugin SDK's `ruleProbeKey` derives (a test in
 * plugin-runtime holds the two equal), spelled here because this package sits
 * below the SDK.
 */
export function regexProbeKey(matcher: { pattern: string; flags: string }): string {
  return createHash('sha256').update(`${matcher.pattern} ${matcher.flags}`).digest('hex');
}

/**
 * The rules safe to run unguarded in the mod. The mod scans on the host's own
 * thread, where a runaway pattern cannot be interrupted, so a regex rule enters
 * the snapshot only on evidence it is fast: it is one the binary ships (timed in
 * CI), the quarantine cache holds a `safe` verdict for it, or an earlier snapshot
 * already vetted it. A quarantined pattern never does. A keyword rule cannot
 * backtrack. A rule left out is still enforced by the command hook, which scans
 * in a worker under a deadline.
 */
export function vetRulesForMod(
  rules: readonly Rule[],
  sources: Pick<ModPolicySources, 'probeVerdict' | 'bundledRegexMatchers'>,
  previouslyVetted: ReadonlySet<string> = new Set(),
): Rule[] {
  const bundled = new Set(sources.bundledRegexMatchers().map(regexProbeKey));
  return rules.filter((rule) => {
    if (rule.matcher.type !== 'regex') return true;
    const key = regexProbeKey(rule.matcher);
    const verdict = sources.probeVerdict(key);
    if (verdict === 'quarantined') return false;
    return verdict === 'safe' || bundled.has(key) || previouslyVetted.has(key);
  });
}

/**
 * The effective ruleset the store alone decides, with the same fallbacks the
 * standalone gateway applies: no installed packs, an unusable snapshot or an
 * empty one all leave the bundled packs in force (`rules` absent, no per-pack
 * actions); every pack disabled is a complete, empty ruleset.
 */
export function modPolicyInputFromStore(
  sources: ModPolicySources,
  previouslyVetted: ReadonlySet<string> = new Set(),
): ModPolicyInput {
  const policies = sources.readPolicies();
  const snapshot = sources.installedRuleset();
  const usable =
    snapshot.installedPacks > 0 &&
    (snapshot.enabledPacks === 0 || (snapshot.invalidRules === 0 && snapshot.rules.length > 0));
  const empty = snapshot.installedPacks > 0 && snapshot.enabledPacks === 0;
  return {
    ...(usable
      ? { rules: empty ? [] : vetRulesForMod(snapshot.rules, sources, previouslyVetted) }
      : {}),
    policies: [...policies, ...(usable && !empty ? assignedRuleActionPolicies(snapshot) : [])],
    exceptionRuleIds: sources.activeExceptionRuleIds(),
  };
}

/** Rebuilds the snapshot from the store and writes it. Never throws: a hook path calls this. */
export function refreshModPolicySnapshot(dataDir: string, sources: ModPolicySources): void {
  try {
    writeModPolicySnapshot(dataDir, buildModPolicySnapshot(modPolicyInputFromStore(sources)));
  } catch {
    // Fail-open: a snapshot that cannot be written leaves the mod on its last one.
  }
}
