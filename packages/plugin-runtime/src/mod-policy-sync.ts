import type { ModPolicyInput } from '@akasecurity/persistence';
import { buildModPolicySnapshot, writeModPolicySnapshot } from '@akasecurity/persistence';
import type { DataGateway } from '@akasecurity/plugin-sdk';
import {
  bundledDetections,
  createIsolatedScanner,
  filterUnsafeRules,
  ruleProbeKey,
} from '@akasecurity/plugin-sdk';
import type { PolicyBundle, Rule } from '@akasecurity/schema';

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
 * The rules of a ruleset that are safe to run unguarded in the mod, which scans
 * on the host's own thread where a runaway pattern cannot be interrupted. The
 * command hook scans in a worker under a deadline; the mod cannot, so a regex
 * rule enters the snapshot only if it is one the binary ships (timed in CI) and
 * not quarantined, or it passes the existing timing gate (`filterUnsafeRules`,
 * measured in a thread that can be killed, with the verdict cached for every
 * later process). A rule left out is still enforced by the command hook.
 */
export async function vetRulesForModFromGateway(
  rules: readonly Rule[],
  gateway: DataGateway,
): Promise<Rule[]> {
  const bundledKeys = new Set(
    bundledDetections()
      .flatMap((pack) => pack.rules)
      .map(ruleProbeKey),
  );
  const shipped: Rule[] = [];
  const unproven: Rule[] = [];
  for (const rule of rules) {
    const key = ruleProbeKey(rule);
    if (key === undefined) shipped.push(rule);
    else if (bundledKeys.has(key)) {
      const verdict = await gateway.getRuleProbeVerdict(key).catch(() => undefined);
      if (verdict?.verdict !== 'quarantined') shipped.push(rule);
    } else unproven.push(rule);
  }
  let prober: ReturnType<typeof createIsolatedScanner> | undefined;
  const passed = new Set(
    await filterUnsafeRules(unproven, gateway, {
      prober: {
        probe: (rule) => {
          prober ??= createIsolatedScanner({ verified: [], unverified: [] });
          return prober.probe(rule);
        },
      },
    }),
  );
  await prober?.close();
  const keep = new Set<Rule>([...shipped, ...passed]);
  return rules.filter((rule) => keep.has(rule));
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
    const input = modPolicyInputFromBundle(await gateway.getPolicyBundle());
    const rules =
      input.rules === undefined ? undefined : await vetRulesForModFromGateway(input.rules, gateway);
    writeModPolicySnapshot(dataDir, buildModPolicySnapshot({ ...input, rules }));
  } catch {
    // Fail-open: the mod keeps the snapshot it has, or its bundled defaults.
  }
}
