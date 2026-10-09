import { mkdirSync, readdirSync, readFileSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import type { InstalledPackInput } from '@akasecurity/schema';
import {
  DEFAULT_ACTIONS,
  DetectionCategory,
  MOD_POLICY_SNAPSHOT_MAX_BYTES,
  ModPolicySnapshot,
  Rule,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  buildModPolicySnapshot,
  MOD_POLICY_SNAPSHOT_FILENAME,
  modPolicySnapshotPath,
  readModPolicySnapshot,
  writeModPolicySnapshot,
} from '../src/mod-policy-snapshot.ts';
import { useTempStore } from './helpers/temp-store.ts';

const store = useTempStore('aka-mod-policy-');

const NOW = new Date('2026-10-09T00:00:00.000Z');

function packRule(id: string, extra: Record<string, unknown> = {}): Rule {
  return Rule.parse({
    specVersion: 1,
    id,
    name: id,
    category: 'custom',
    severity: 'high',
    matcher: { type: 'keyword', keywords: ['marker'] },
    ...extra,
  });
}

function pack(packId: string, rules: Rule[]): InstalledPackInput {
  return { namespace: 'acme', packId, version: '1.0.0', name: packId, rules };
}

describe('buildModPolicySnapshot', () => {
  it('resolves a rule over its category over the default, first enabled policy winning', () => {
    const snapshot = buildModPolicySnapshot(
      {
        policies: [
          { target: { ruleId: 'a/one' }, action: 'redact', enabled: true },
          { target: { ruleId: 'a/one' }, action: 'block', enabled: true },
          { target: { ruleId: 'a/off' }, action: 'block', enabled: false },
          { target: { category: 'pii' }, action: 'warn', enabled: true },
          { target: { category: 'pii' }, action: 'block', enabled: true },
          { target: { category: 'phi' }, action: 'block', enabled: false },
        ],
        exceptionRuleIds: [],
      },
      NOW,
    );

    expect(snapshot.ruleActions).toEqual({ 'a/one': 'redact' });
    expect(snapshot.categoryActions.pii).toBe('warn');
    // A disabled policy, and a category with none, take the default.
    expect(snapshot.categoryActions.phi).toBe(DEFAULT_ACTIONS.phi);
    expect(snapshot.categoryActions.secret).toBe(DEFAULT_ACTIONS.secret);
  });

  it('resolves every category, so the reader needs no default table', () => {
    const snapshot = buildModPolicySnapshot({ policies: [], exceptionRuleIds: [] }, NOW);

    expect(Object.keys(snapshot.categoryActions).sort()).toEqual(
      [...DetectionCategory.options].sort(),
    );
  });

  it('carries the ruleset when it is given and omits it when the bundled packs run', () => {
    const rules = [packRule('acme/one')];

    expect(
      buildModPolicySnapshot({ rules, policies: [], exceptionRuleIds: [] }, NOW).rules?.map(
        (r) => r.id,
      ),
    ).toEqual(['acme/one']);
    expect('rules' in buildModPolicySnapshot({ policies: [], exceptionRuleIds: [] }, NOW)).toBe(
      false,
    );
  });

  it('leaves a rule pack author’s examples behind', () => {
    const pasted = 'a-value-the-author-pasted-as-an-example';
    const snapshot = buildModPolicySnapshot(
      {
        rules: [packRule('acme/one', { examples: [pasted] })],
        policies: [],
        exceptionRuleIds: [],
      },
      NOW,
    );

    expect(JSON.stringify(snapshot)).not.toContain(pasted);
  });

  it('lists exception rule ids once, sorted', () => {
    const snapshot = buildModPolicySnapshot(
      { policies: [], exceptionRuleIds: ['b/two', 'a/one', 'b/two'] },
      NOW,
    );

    expect(snapshot.exceptionRuleIds).toEqual(['a/one', 'b/two']);
  });

  it('builds what the contract accepts', () => {
    const snapshot = buildModPolicySnapshot(
      { rules: [packRule('acme/one')], policies: [], exceptionRuleIds: ['acme/one'] },
      NOW,
    );

    expect(ModPolicySnapshot.safeParse(JSON.parse(JSON.stringify(snapshot))).success).toBe(true);
  });
});

describe('writeModPolicySnapshot', () => {
  const snapshot = (): ModPolicySnapshot =>
    buildModPolicySnapshot({ policies: [], exceptionRuleIds: [] }, NOW);

  it('writes the file under the data dir, owner-only, with no temp file left behind', () => {
    expect(writeModPolicySnapshot(store.dataDir, snapshot())).toBe(true);

    const file = modPolicySnapshotPath(store.dataDir);
    expect(file).toBe(join(store.dataDir, MOD_POLICY_SNAPSHOT_FILENAME));
    expect(readModPolicySnapshot(store.dataDir)).toEqual(snapshot());
    if (process.platform !== 'win32') expect(statSync(file).mode & 0o777).toBe(0o600);
    expect(readdirSync(store.dataDir).filter((n) => n.endsWith('.tmp'))).toEqual([]);
  });

  it('creates the data dir when it is missing', () => {
    const dir = join(store.home, 'elsewhere', 'data');

    expect(writeModPolicySnapshot(dir, snapshot())).toBe(true);
    expect(readModPolicySnapshot(dir)).not.toBeNull();
  });

  it('leaves the file alone when only the timestamp would change', () => {
    writeModPolicySnapshot(store.dataDir, snapshot());
    const file = modPolicySnapshotPath(store.dataDir);
    const past = new Date('2020-01-01T00:00:00.000Z');
    utimesSync(file, past, past);

    const later = buildModPolicySnapshot(
      { policies: [], exceptionRuleIds: [] },
      new Date('2026-10-10T00:00:00.000Z'),
    );
    expect(writeModPolicySnapshot(store.dataDir, later)).toBe(false);
    expect(statSync(file).mtime.getTime()).toBe(past.getTime());
  });

  it('replaces a corrupt file', () => {
    mkdirSync(store.dataDir, { recursive: true });
    writeFileSync(modPolicySnapshotPath(store.dataDir), '{"version":');

    expect(writeModPolicySnapshot(store.dataDir, snapshot())).toBe(true);
    expect(readModPolicySnapshot(store.dataDir)).not.toBeNull();
  });

  it('does not write a snapshot the mod would refuse to read', () => {
    const rules = Array.from({ length: 40 }, (_, i) =>
      packRule(`acme/r${String(i)}`, {
        matcher: { type: 'keyword', keywords: ['k'.repeat(MOD_POLICY_SNAPSHOT_MAX_BYTES / 40)] },
      }),
    );
    const big = buildModPolicySnapshot({ rules, policies: [], exceptionRuleIds: [] }, NOW);

    expect(writeModPolicySnapshot(store.dataDir, big)).toBe(false);
    expect(readModPolicySnapshot(store.dataDir)).toBeNull();
  });

  it('reads a missing, corrupt or invalid file as null', () => {
    expect(readModPolicySnapshot(store.dataDir)).toBeNull();
    mkdirSync(store.dataDir, { recursive: true });
    const file = modPolicySnapshotPath(store.dataDir);
    writeFileSync(file, 'not json');
    expect(readModPolicySnapshot(store.dataDir)).toBeNull();
    writeFileSync(file, JSON.stringify({ version: 2 }));
    expect(readModPolicySnapshot(store.dataDir)).toBeNull();
  });
});

describe('the store keeps the snapshot current', () => {
  const read = (): ModPolicySnapshot => {
    const snapshot = readModPolicySnapshot(store.dataDir);
    if (snapshot === null) throw new Error('no snapshot was written');
    return snapshot;
  };

  it('writes one when a store is first opened', () => {
    store.open();

    expect(read().categoryActions).toEqual(
      Object.fromEntries(DetectionCategory.options.map((c) => [c, 'log'])),
    );
  });

  it('follows a category policy', () => {
    const db = store.open();

    db.policies.upsertCategoryAction('pii', 'redact');

    expect(read().categoryActions.pii).toBe('redact');
  });

  it('follows the cap on warn-era block and redact categories', () => {
    const db = store.open();
    db.policies.upsertCategoryAction('pii', 'block');

    db.policies.capCategoryActions();

    expect(read().categoryActions.pii).toBe('warn');
  });

  it('follows the install of a pack, its policy, its switch and its update', () => {
    const db = store.open();
    const rule = packRule('acme/one');

    db.installedPacks.recordInventory([pack('tickets', [rule])]);
    expect(read().rules?.map((r) => r.id)).toEqual(['acme/one']);
    expect(read().ruleActions).toEqual({});

    db.installedPacks.setPolicy('acme', 'tickets', 'redact');
    expect(read().ruleActions).toEqual({ 'acme/one': 'redact' });

    db.installedPacks.setEnabled('acme', 'tickets', false);
    expect(read().rules).toEqual([]);
    expect(read().ruleActions).toEqual({});

    db.installedPacks.setEnabled('acme', 'tickets', true);
    db.installedPacks.recordInventory([
      { ...pack('tickets', [rule, packRule('acme/two')]), version: '1.1.0' },
    ]);
    expect(read().rules?.map((r) => r.id)).toEqual(['acme/one']);
    db.installedPacks.applyUpdate('acme', 'tickets');
    expect(
      read()
        .rules?.map((r) => r.id)
        .sort(),
    ).toEqual(['acme/one', 'acme/two']);
  });

  it('follows an exception grant and its revocation', async () => {
    const db = store.open();
    const grant = await db.exceptions.create({
      ruleId: 'acme/one',
      category: 'secret',
      valueFingerprint: 'a'.repeat(64),
      keyVersion: 1,
      maskedValue: 'AK******Q',
      scope: 'once',
      expiresAt: null,
      maxUses: 1,
      justification: 'test grant',
      conditions: null,
      createdBy: 'alice',
      createdVia: 'cli-approve',
    });
    expect(read().exceptionRuleIds).toEqual(['acme/one']);

    await db.exceptions.revoke(grant.id, 'alice');

    expect(read().exceptionRuleIds).toEqual([]);
  });

  it('does not rewrite the file on a write that changes nothing', () => {
    const db = store.open();
    db.policies.upsertCategoryAction('pii', 'redact');
    const file = modPolicySnapshotPath(store.dataDir);
    const past = new Date('2020-01-01T00:00:00.000Z');
    utimesSync(file, past, past);

    db.policies.upsertCategoryAction('pii', 'redact');

    expect(statSync(file).mtime.getTime()).toBe(past.getTime());
  });

  it('names the rule of a grant and nothing of the value it matched', async () => {
    const db = store.open();
    await db.exceptions.create({
      ruleId: 'acme/one',
      category: 'secret',
      valueFingerprint: 'f'.repeat(64),
      keyVersion: 1,
      maskedValue: 'masked-preview-text',
      scope: 'once',
      expiresAt: null,
      maxUses: 1,
      justification: 'justification text',
      conditions: null,
      createdBy: 'alice',
      createdVia: 'cli-approve',
    });

    const text = readFileSync(modPolicySnapshotPath(store.dataDir), 'utf8');

    expect(text).toContain('acme/one');
    expect(text).not.toContain('f'.repeat(64));
    expect(text).not.toContain('masked-preview-text');
    expect(text).not.toContain('justification text');
  });
});
