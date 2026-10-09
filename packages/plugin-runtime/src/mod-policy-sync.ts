import type { ModPolicyInput } from '@akasecurity/persistence';
import { buildModPolicySnapshot, writeModPolicySnapshot } from '@akasecurity/persistence';
import type { DataGateway } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { PolicyBundle } from '@akasecurity/schema';

/**
 * What the effective policy bundle says, in the shape a mod snapshot is built
 * from. `rulesComplete` marks the bundle's rules as the whole ruleset; without
 * it the bundled packs run beside whatever rules the bundle carries, so a bundle
 * that carries none leaves the mod on the packs it ships.
 */
export function modPolicyInputFromBundle(bundle: PolicyBundle): ModPolicyInput {
  const extra = bundle.rules ?? [];
  const rules = bundle.rulesComplete
    ? extra
    : extra.length > 0
      ? [...bundledDetections().flatMap((pack) => pack.rules), ...extra]
      : undefined;
  return {
    rules,
    policies: bundle.policies,
    exceptionRuleIds: (bundle.exceptions ?? []).map((entry) => entry.ruleId),
  };
}

/**
 * Writes the Claude Code mod's policy snapshot from the gateway's effective
 * bundle, which on an attached machine includes the organization's policies the
 * store alone does not hold. The store layer rewrites the same file on every
 * local change; this is how an existing install gets its first one and how a
 * pulled organization policy reaches it. Leaves the file alone when nothing
 * changed. Never throws.
 */
export async function syncModPolicySnapshot(gateway: DataGateway, dataDir: string): Promise<void> {
  try {
    const bundle = await gateway.getPolicyBundle();
    writeModPolicySnapshot(dataDir, buildModPolicySnapshot(modPolicyInputFromBundle(bundle)));
  } catch {
    // Fail-open: the mod keeps the snapshot it has, or its bundled defaults.
  }
}
