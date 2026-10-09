import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { readModPolicySnapshot, regexProbeKey } from '@akasecurity/persistence';
import type { DataGateway } from '@akasecurity/plugin-sdk';
import { bundledDetections, ruleProbeKey } from '@akasecurity/plugin-sdk';
import type { PolicyBundle, Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { modPolicyInputFromBundle, syncModPolicySnapshot } from '../src/mod-policy-sync.ts';
import { StandaloneDataGateway } from '../src/standalone-gateway.ts';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-mod-sync-'));
});

afterEach(() => {
  removeTree(dir);
});

function bundle(extra: Partial<PolicyBundle> = {}): PolicyBundle {
  return {
    version: 'test',
    policies: [],
    customKeywords: [],
    fetchedAt: '2026-10-09T00:00:00.000Z',
    ...extra,
  };
}

const CUSTOM_RULE: Rule = {
  specVersion: 1,
  id: 'acme/one',
  name: 'Acme',
  category: 'custom',
  severity: 'high',
  matcher: { type: 'keyword', keywords: ['marker'], caseSensitive: false },
};

describe('modPolicyInputFromBundle', () => {
  it('takes a complete bundle’s rules as the whole ruleset', () => {
    const input = modPolicyInputFromBundle(bundle({ rulesComplete: true, rules: [CUSTOM_RULE] }));

    expect(input.rules?.map((r) => r.id)).toEqual(['acme/one']);
  });

  it('puts the bundled packs beside rules a bundle that is not complete adds', () => {
    const input = modPolicyInputFromBundle(bundle({ rules: [CUSTOM_RULE] }));
    const bundled = bundledDetections().flatMap((p) => p.rules).length;

    expect(input.rules).toHaveLength(bundled + 1);
    expect(input.rules?.at(-1)?.id).toBe('acme/one');
  });

  it('leaves the bundled packs in force when the bundle carries no rules', () => {
    expect(modPolicyInputFromBundle(bundle()).rules).toBeUndefined();
    expect(modPolicyInputFromBundle(bundle({ rules: [] })).rules).toBeUndefined();
  });

  it('names the rules of active exceptions', () => {
    const input = modPolicyInputFromBundle(
      bundle({
        exceptions: [
          {
            id: randomUUID(),
            ruleId: 'acme/one',
            valueFingerprint: 'f'.repeat(64),
            keyVersion: 1,
            capability: 'suppress',
            expiresAt: null,
            maxUses: null,
            useCount: 0,
            conditions: null,
          },
        ],
      }),
    );

    expect([...input.exceptionRuleIds]).toEqual(['acme/one']);
  });
});

describe('syncModPolicySnapshot', () => {
  const gatewayOf = (get: () => Promise<PolicyBundle>): DataGateway =>
    ({ getPolicyBundle: get }) as unknown as DataGateway;

  it('writes the snapshot of the gateway’s effective policy', async () => {
    await syncModPolicySnapshot(
      gatewayOf(() =>
        Promise.resolve(
          bundle({
            policies: [
              {
                id: randomUUID(),
                scope: 'global',
                target: { ruleId: 'acme/one' },
                action: 'redact',
                enabled: true,
              },
            ],
          }),
        ),
      ),
      dir,
    );

    expect(readModPolicySnapshot(dir)?.ruleActions).toEqual({ 'acme/one': 'redact' });
  });

  it('never throws, and leaves the last snapshot, when the policy cannot be read', async () => {
    await syncModPolicySnapshot(
      gatewayOf(() => Promise.resolve(bundle())),
      dir,
    );
    const before = readModPolicySnapshot(dir);

    await expect(
      syncModPolicySnapshot(
        gatewayOf(() => Promise.reject(new Error('store gone'))),
        dir,
      ),
    ).resolves.toBeUndefined();

    expect(readModPolicySnapshot(dir)).toEqual(before);
  });
});

describe('only rules safe to run unguarded reach the snapshot', () => {
  const rule = (id: string, pattern: string): Rule => ({
    specVersion: 1,
    id,
    name: id,
    category: 'custom',
    severity: 'high',
    matcher: { type: 'regex', pattern, flags: 'g', captureGroup: undefined },
  });

  // A custom pack is an installed row the available mirror does not hold.
  function gatewayWithCustom(rules: Rule[]): StandaloneDataGateway {
    const gateway = new StandaloneDataGateway(dir, bundledDetections());
    const raw = new DatabaseSync(join(dir, 'aka.db'));
    try {
      raw
        .prepare(
          `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, policy_id, created_at, updated_at)
           VALUES ('c1', 'acme', 'custom', '1.0.0', 'custom', :rulesJson, 1, NULL, 1, 1)`,
        )
        .run({ rulesJson: JSON.stringify(rules) });
    } finally {
      raw.close();
    }
    return gateway;
  }

  const ids = (): string[] => (readModPolicySnapshot(dir)?.rules ?? []).map((r) => r.id);

  it('derives the probe key the SDK derives', () => {
    const r = rule('acme/one', 'ACME-[0-9]{6}');
    expect(regexProbeKey({ pattern: 'ACME-[0-9]{6}', flags: 'g' })).toBe(ruleProbeKey(r));
  });

  it('never carries a catastrophic custom regex, and carries a safe one once timed', async () => {
    const gateway = gatewayWithCustom([
      rule('acme/redos', '(a+)+$'),
      rule('acme/ticket', 'ACME-[0-9]{6}'),
    ]);
    try {
      await syncModPolicySnapshot(gateway, dir);
    } finally {
      await gateway.close();
    }

    expect(ids()).toContain('acme/ticket');
    expect(ids()).not.toContain('acme/redos');
    // The bundled packs the binary ships are all still there.
    expect(ids()).toContain('secrets/twilio-key');
  });

  it('never carries a rule the quarantine cache holds', async () => {
    const gateway = gatewayWithCustom([rule('acme/ticket', 'ACME-[0-9]{6}')]);
    await gateway.setRuleProbeVerdict(
      regexProbeKey({ pattern: 'ACME-[0-9]{6}', flags: 'g' }),
      'quarantined',
      5000,
    );
    try {
      await syncModPolicySnapshot(gateway, dir);
    } finally {
      await gateway.close();
    }

    expect(ids()).not.toContain('acme/ticket');
  });

  it('never carries a shipped rule that has been quarantined', async () => {
    const gateway = new StandaloneDataGateway(dir, bundledDetections());
    const twilio = bundledDetections()
      .flatMap((p) => p.rules)
      .find((r) => r.id === 'secrets/twilio-key');
    if (twilio?.matcher.type !== 'regex') throw new Error('expected a regex rule');
    await gateway.setRuleProbeVerdict(
      regexProbeKey({ pattern: twilio.matcher.pattern, flags: twilio.matcher.flags }),
      'quarantined',
      5000,
    );
    try {
      await syncModPolicySnapshot(gateway, dir);
    } finally {
      await gateway.close();
    }

    expect(ids()).not.toContain('secrets/twilio-key');
  });
});
