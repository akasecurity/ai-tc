// The control-plane floor at the ONE device-local write path for a detection's
// policy assignment. Every case here drives a real store in a real temp `~/.aka`
// with a real settings.json and a real policy-cache.json, because the whole
// subject is how those three files combine — a stubbed reader would assert the
// wiring this suite exists to check.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { InstalledPackInput, Policy, PolicyBundle, Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { POLICY_CACHE_FILENAME } from '../src/attached-derived.ts';
import { controlPlanePolicyFloor, PolicyFloorError } from '../src/policy-floor.ts';
import { SETTINGS_FILENAME } from '../src/settings.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-policy-floor-', { migrated: true });

function rule(id: string, category: Rule['category'] = 'secret'): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category,
    severity: 'high',
    matcher: { type: 'regex', pattern: 'x', flags: 'g' },
  };
}

function pack(packId: string, rules: Rule[]): InstalledPackInput {
  return { namespace: 'aka', packId, version: '1.0.0', name: packId, rules };
}

// Distinct guids per policy: Policy.id is `z.guid()`, so a placeholder string
// would fail the parse this suite is meant to get past.
let policySeq = 0;
function policy(partial: Omit<Policy, 'id' | 'scope' | 'enabled'> & Partial<Policy>): Policy {
  policySeq += 1;
  return {
    id: `00000000-0000-4000-8000-${String(policySeq).padStart(12, '0')}`,
    scope: 'global',
    enabled: true,
    ...partial,
  };
}

/** Attach the temp machine: both halves, since `isAttached` demands both. */
function writeAttachedSettings(): void {
  mkdirSync(store.settingsDir, { recursive: true });
  writeFileSync(
    join(store.settingsDir, SETTINGS_FILENAME),
    JSON.stringify({
      specVersion: 1,
      runMode: 'attached',
      controlPlane: {
        endpoint: 'https://cp.example.internal',
        attachedAt: new Date(0).toISOString(),
      },
    }),
  );
}

/** Write settings.json describing a machine nothing manages. */
function writeStandaloneSettings(): void {
  mkdirSync(store.settingsDir, { recursive: true });
  writeFileSync(
    join(store.settingsDir, SETTINGS_FILENAME),
    JSON.stringify({ specVersion: 1, runMode: 'standalone' }),
  );
}

/** The on-disk shape the sync child publishes: the bundle plus its freshness. */
function writePolicyCache(policies: Policy[]): void {
  const bundle: PolicyBundle = {
    version: '1',
    policies,
    customKeywords: [],
    fetchedAt: new Date(0).toISOString(),
  };
  writeFileSync(
    join(store.dataDir, POLICY_CACHE_FILENAME),
    JSON.stringify({ bundle, fetchedAtMs: 0 }),
  );
}

/** The policy_id actually stored for a pack, read outside the repository. */
function storedPolicyId(packId: string): string | null {
  const raw = store.openRaw();
  const row = raw
    .prepare(`SELECT policy_id AS policyId FROM installed_packs WHERE pack_id = ?`)
    .get(packId) as { policyId: string | null } | undefined;
  raw.close();
  return row?.policyId ?? null;
}

describe('control-plane floor on setPolicy', () => {
  it('refuses a downgrade below what the control plane requires, and writes nothing', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'block' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'block')).toBe(true);

    let caught: unknown;
    try {
      db.installedPacks.setPolicy('aka', 'secrets', 'monitor');
    } catch (err) {
      caught = err;
    }
    db.close();

    expect(caught).toBeInstanceOf(PolicyFloorError);
    const error = caught as PolicyFloorError;
    expect(error.pack).toBe('aka/secrets');
    expect(error.attempted).toBe('monitor');
    expect(error.floor).toBe('block');
    expect(error.refusal).toBe('floor');
    // The refusal is a refusal, not a substitution: the stored value is the one
    // that was already there.
    expect(storedPolicyId('secrets')).toBe('block');
  });

  it('allows an upgrade above the floor', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'redact' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.setPolicy('aka', 'secrets', 'block')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('block');
  });

  it('allows setting exactly the floor', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'redact' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.setPolicy('aka', 'secrets', 'redact')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('redact');
  });

  it('treats Redact & Vault as meeting a redact floor — reversibility is a second axis', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'redact' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.setPolicy('aka', 'secrets', 'vault')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('vault');
  });

  it('refuses a CLEAR that would drop the pack below the floor', () => {
    // Clearing leaves policy_id NULL, which resolves to Monitor — so on a
    // redact floor it is the same downgrade as asking for Monitor outright.
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'redact' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);
    db.installedPacks.setPolicy('aka', 'secrets', 'block');

    expect(() => db.installedPacks.setPolicy('aka', 'secrets', null)).toThrow(PolicyFloorError);
    db.close();
    expect(storedPolicyId('secrets')).toBe('block');
  });

  it('lets a ruleId-targeted policy outrank the category one, exactly as the runtime resolves', () => {
    writeAttachedSettings();
    writePolicyCache([
      policy({ target: { ruleId: 'secrets/aws' }, action: 'log' }),
      policy({ target: { category: 'secret' }, action: 'block' }),
    ]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    // The rule the pack owns is named directly, so the category policy never
    // reaches it and the pack carries no floor above Monitor.
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'monitor')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('monitor');
  });

  it('takes the STRONGEST floor across the rules one pack owns', () => {
    writeAttachedSettings();
    writePolicyCache([
      policy({ target: { ruleId: 'secrets/aws' }, action: 'log' }),
      policy({ target: { ruleId: 'secrets/gh' }, action: 'block' }),
    ]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws'), rule('secrets/gh')])]);

    expect(() => db.installedPacks.setPolicy('aka', 'secrets', 'redact')).toThrow(PolicyFloorError);
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'block')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('block');
  });

  it('ignores a DISABLED remote policy, which the runtime never indexes either', () => {
    writeAttachedSettings();
    writePolicyCache([
      // Ahead of the enabled row on the same key, so if disabled rows were
      // indexed this one would WIN first-write-wins and the floor would be block.
      policy({ target: { category: 'secret' }, action: 'block', enabled: false }),
      policy({ target: { category: 'secret' }, action: 'warn' }),
    ]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.policyFloor('aka', 'secrets')).toEqual({
      floor: 'warn',
      locked: false,
    });
    expect(() => db.installedPacks.setPolicy('aka', 'secrets', 'monitor')).toThrow(
      PolicyFloorError,
    );
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'warn')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('warn');
  });

  it('imposes NOTHING on a pack no remote policy names', () => {
    // The bundle is about other detections entirely. A pack it never reaches is
    // the user's, exactly as on a standalone machine — the compiled-in category
    // default is not something the organization asked for, and enforcement does
    // not raise this pack either.
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'pii' }, action: 'block' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.policyFloor('aka', 'secrets')).toBeNull();
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'monitor')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('monitor');
  });

  it('imposes nothing at all when the bundle carries no policies', () => {
    writeAttachedSettings();
    writePolicyCache([]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.policyFloor('aka', 'secrets')).toBeNull();
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'monitor')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('monitor');
  });

  it('refuses ANY re-assignment of a pack a custom-kind remote policy targets', () => {
    writeAttachedSettings();
    writePolicyCache([
      policy({ target: { ruleId: 'secrets/aws' }, action: 'redact', kind: 'custom' }),
    ]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    let caught: unknown;
    try {
      // Even an UPGRADE is refused: the organization authored the answer, it
      // did not state a minimum.
      db.installedPacks.setPolicy('aka', 'secrets', 'block');
    } catch (err) {
      caught = err;
    }
    db.close();

    expect(caught).toBeInstanceOf(PolicyFloorError);
    expect((caught as PolicyFloorError).refusal).toBe('lock');
    expect(storedPolicyId('secrets')).toBeNull();
  });

  it('locks through the CATEGORY on a pack the bundle names by rule id', () => {
    // The ruleId row is how a governed pack arrives — the bundle builder
    // expands each pack's assignment into one per rule it owns — so its
    // presence is what says the control plane has this detection in hand. With
    // it, the authored category policy is a statement about THIS pack.
    writeAttachedSettings();
    writePolicyCache([
      policy({ target: { ruleId: 'secrets/aws' }, action: 'warn' }),
      policy({ target: { category: 'secret' }, action: 'warn', kind: 'custom' }),
    ]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.policyFloor('aka', 'secrets')?.locked).toBe(true);
    expect(() => db.installedPacks.setPolicy('aka', 'secrets', 'block')).toThrow(PolicyFloorError);
    db.close();
  });

  it('does NOT lock a pack the bundle never names, on category membership alone', () => {
    // A category spans many packs, including ones the user pulled or wrote
    // themselves that the control plane has never seen. Locking on membership
    // would take the whole Detections page away — every pack owning any secret
    // rule, greyed out under a message saying the organization set it. The
    // authored policy still floors the pack; it just does not own its answer.
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'warn', kind: 'custom' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('home-grown', [rule('home-grown/token')])]);

    expect(db.installedPacks.policyFloor('aka', 'home-grown')).toEqual({
      floor: 'warn',
      locked: false,
    });
    // Raising above the stated minimum stays the device's to do…
    expect(db.installedPacks.setPolicy('aka', 'home-grown', 'block')).toBe(true);
    // …and the minimum itself is still refused from below.
    expect(() => db.installedPacks.setPolicy('aka', 'home-grown', 'monitor')).toThrow(
      PolicyFloorError,
    );
    db.close();
    expect(storedPolicyId('home-grown')).toBe('block');
  });

  it('leaves a pack alone when the custom policy targets a category it does not own', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'pii' }, action: 'block', kind: 'custom' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.setPolicy('aka', 'secrets', 'warn')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('warn');
  });

  it('imposes no floor when the machine has no cached bundle yet', () => {
    // A machine attached moments ago has settings but no cache until its first
    // sync lands, and it must still be configurable.
    writeAttachedSettings();
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.policyFloor('aka', 'secrets')).toBeNull();
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'monitor')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('monitor');
  });

  it('imposes no floor when the cached bundle is corrupt', () => {
    writeAttachedSettings();
    writeFileSync(join(store.dataDir, POLICY_CACHE_FILENAME), '{ not json');
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.policyFloor('aka', 'secrets')).toBeNull();
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'monitor')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('monitor');
  });

  it('imposes no floor on a machine that is not attached, even with a cache left behind', () => {
    // Detach deletes the cache, so this is the leftover case: an interrupted
    // detach, a restored backup, a hand copy. The settings descriptor is what
    // decides, not the file.
    writeStandaloneSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'block' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.policyFloor('aka', 'secrets')).toBeNull();
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'monitor')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('monitor');
  });

  it('imposes no floor when runMode says attached but no descriptor backs it', () => {
    mkdirSync(store.settingsDir, { recursive: true });
    writeFileSync(
      join(store.settingsDir, SETTINGS_FILENAME),
      JSON.stringify({ specVersion: 1, runMode: 'attached' }),
    );
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'block' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    expect(db.installedPacks.setPolicy('aka', 'secrets', 'monitor')).toBe(true);
    db.close();
    expect(storedPolicyId('secrets')).toBe('monitor');
  });

  it('still rejects an unknown policy id before it ever consults the floor', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'block' })]);
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', [rule('secrets/aws')])]);

    // Not a PolicyFloorError: a caller sending a value outside the enum has a
    // bug, not an administrative constraint, and the two must stay tellable
    // apart by the surface that reports them.
    let caught: unknown;
    try {
      db.installedPacks.setPolicy('aka', 'secrets', 'obliterate');
    } catch (err) {
      caught = err;
    }
    db.close();
    expect(caught).toBeInstanceOf(Error);
    expect(caught).not.toBeInstanceOf(PolicyFloorError);
  });
});

describe('controlPlanePolicyFloor', () => {
  it('reports no floor for a pack that contributes no rules', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'block' })]);
    expect(controlPlanePolicyFloor([], store.home)).toBeNull();
  });

  it('states the floor as the archetype a user picks from', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'redact' })]);
    // 'redact' and 'vault' share the action; the floor names the weaker of the
    // two, because a floor is a statement about enforcement and never a demand
    // that a value be kept.
    expect(
      controlPlanePolicyFloor([{ id: 'secrets/aws', category: 'secret' }], store.home),
    ).toEqual({ floor: 'redact', locked: false });
  });

  it('reports no floor for a rule no remote policy names', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'pii' }, action: 'block' })]);
    // DEFAULT_ACTIONS.secret is 'warn', and reporting that here would state a
    // requirement the control plane never made — and one stronger than what
    // this machine actually enforces for the pack.
    expect(controlPlanePolicyFloor([{ id: 'secrets/aws', category: 'secret' }], store.home)).toBe(
      null,
    );
  });

  it('reports no floor for a category nothing recognises', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { category: 'secret' }, action: 'block' })]);
    expect(controlPlanePolicyFloor([{ id: 'x/y', category: 'not-a-category' }], store.home)).toBe(
      null,
    );
  });

  it('takes the floor from the rules a policy names, ignoring the pack rules it does not', () => {
    writeAttachedSettings();
    writePolicyCache([policy({ target: { ruleId: 'secrets/gh' }, action: 'log' })]);
    // One of the two rules is named, with something WEAKER than what
    // DEFAULT_ACTIONS.secret ('warn') would have contributed for the other. The
    // unnamed rule contributes nothing, so the answer is the named rule's alone
    // — dragging the default in would raise this to Warn on a bundle that asked
    // for log.
    expect(
      controlPlanePolicyFloor(
        [
          { id: 'secrets/aws', category: 'secret' },
          { id: 'secrets/gh', category: 'secret' },
        ],
        store.home,
      ),
    ).toEqual({ floor: 'monitor', locked: false });
  });
});
