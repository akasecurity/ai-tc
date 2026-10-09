import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { readModPolicySnapshot } from '@akasecurity/persistence';
import type { DataGateway } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { PolicyBundle, Rule } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { modPolicyInputFromBundle, syncModPolicySnapshot } from '../src/mod-policy-sync.ts';

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
