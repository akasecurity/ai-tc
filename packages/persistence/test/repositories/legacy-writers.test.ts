// ─── The legacy-writers suite (prevention P1) ────────────────────────────────
//
// CONVENTION: any change to installed_packs / available_packs WRITE SEMANTICS
// must extend this suite. It replays FROZEN legacy SQL against a current store
// and asserts the invariants hold. The two fixtures differ in provenance:
//   - LEGACY_ALPHA5_UPSERT is a REAL historical path — ≤alpha.5 hooks ran it
//     unconditionally on every gateway open, byte-exact from Claude Code's
//     plugin cache; the replay is exactly what a stale session still executes.
//   - LEGACY_ALPHA6_MIRROR_UPSERT is a SYNTHETIC worst-case probe — every
//     shipped mirror-writing generation (alpha.6+) runs isMirrorDowngrade in
//     front of this SQL, so no binary ever executed it guard-less; replaying
//     it raw pins the blast radius IF the app-level guard were ever absent.
// App-level guards do not bind code that is already on disk (the alpha.6 field
// bug: old-session hooks silently reverted manually applied pack updates), so
// every invariant here must hold at the DATABASE level or be explicitly
// documented as an accepted, data-guarded gap.
//
// Invariants pinned:
//   1. installed_packs content (version/name/rules_json) changes ONLY through
//      applyUpdate — every other UPDATE is silently ignored by the migration
//      0006 write-gate trigger (fail-open for the legacy writer: no error).
//   2. INSERTs stay open from ALL binary generations — new packs auto-install.
//   3. The available_packs mirror has NO gate (it is metadata, not enforcement
//      state) — its protection is the data-level downgrade guard inside every
//      recordInventory generation that writes it (alpha.6+). A raw legacy
//      writer bypassing that guard can at worst mis-advertise an update; it
//      cannot change what scans.
//   4. installed_packs.policy_id is APP-guarded, not gated: on an attached
//      machine the current repository refuses to write a pack below what the
//      control plane requires, and the trigger above deliberately does not
//      cover the column (BEFORE UPDATE OF version, name, rules_json). So a raw
//      pre-floor writer can still store a weaker assignment — an accepted,
//      bounded gap, because the assignment is not what enforces: the attached
//      runtime merges the control plane's bundle over the local one raise-only
//      on every hook, so the weaker row is clamped back before it decides
//      anything.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { InstalledPackInput, Policy, PolicyBundle, Rule } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { POLICY_CACHE_FILENAME } from '../../src/attached-derived.ts';
import { DB_FILENAME } from '../../src/paths.ts';
import { PolicyFloorError } from '../../src/policy-floor.ts';
import { SETTINGS_FILENAME } from '../../src/settings.ts';
import { useTempStore } from '../helpers/temp-store.ts';

// The temp tree is the harness's; the raw connections below are deliberately
// NOT. `store.openRaw()` keeps every handle it hands out open until teardown,
// and what this suite replays is a legacy PROCESS: one connection, opened for a
// single statement and closed again, never overlapping another. Tracking them
// would leave several live at once, which is a shape no shipped binary ever
// produced and is the opposite of the sequence under test.
const store = useTempStore('aka-legacy-writers-');

function rule(id: string): Rule {
  return {
    specVersion: 1,
    id,
    name: id,
    category: 'secret',
    severity: 'high',
    matcher: { type: 'regex', pattern: 'x', flags: 'g' },
  };
}

function pack(packId: string, version: string, ruleIds: string[]): InstalledPackInput {
  return { namespace: 'aka', packId, version, name: packId, rules: ruleIds.map(rule) };
}

// ─── Frozen fixtures — the exact SQL legacy binaries execute ─────────────────

// ╔═══════════════════════════════════════════════════════════════════════╗
// ║ DO NOT EDIT — PINNED ARTIFACT. Vendored VERBATIM from git               ║
// ║ (installed-packs.ts at 93fc55f, the pre-#296 tree). The whole point is  ║
// ║ byte-exactness with what shipped binaries execute; any reformat — even  ║
// ║ whitespace — silently voids the guarantee while the test stays green.   ║
// ╚═══════════════════════════════════════════════════════════════════════╝
// The ≤0.0.2-alpha.5 installed_packs auto-sync upsert. This is the statement
// that clobbered applied updates in the field; it must never work again.
const LEGACY_ALPHA5_UPSERT = `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
       VALUES (:id, :namespace, :packId, :version, :name, :rulesJson, 1, :now, :now)
       ON CONFLICT (namespace, pack_id) DO UPDATE SET
         version = excluded.version,
         name = excluded.name,
         rules_json = excluded.rules_json,
         updated_at = excluded.updated_at
       WHERE installed_packs.version <> excluded.version
          OR installed_packs.name <> excluded.name
          OR installed_packs.rules_json <> excluded.rules_json`;

// ╔═══════════════════════════════════════════════════════════════════════╗
// ║ DO NOT EDIT — PINNED ARTIFACT. Vendored VERBATIM from git               ║
// ║ (installed-packs.ts at e1f4098). Byte-exactness is the guarantee; any   ║
// ║ reformat silently voids it while the test stays green.                  ║
// ╚═══════════════════════════════════════════════════════════════════════╝
// The 0.0.2-alpha.6 available_packs mirror upsert. NOTE: no shipped binary
// runs this guard-less (alpha.6+ always fronts it with isMirrorDowngrade) —
// the raw replay below is a synthetic worst-case probe of invariant 3's
// boundary, not a historical path. See the mirror describe block.
const LEGACY_ALPHA6_MIRROR_UPSERT = `INSERT INTO available_packs (id, namespace, pack_id, version, name, rules_json, updated_at)
       VALUES (:id, :namespace, :packId, :version, :name, :rulesJson, :now)
       ON CONFLICT (namespace, pack_id) DO UPDATE SET
         version = excluded.version,
         name = excluded.name,
         rules_json = excluded.rules_json,
         updated_at = excluded.updated_at
       WHERE available_packs.version <> excluded.version
          OR available_packs.name <> excluded.name
          OR available_packs.rules_json <> excluded.rules_json`;

// Run a frozen statement exactly as a legacy process would: its own raw
// connection, no repository code in the loop.
function replayRaw(
  statement: string,
  packRow: { packId: string; version: string; ruleIds: string[] },
): void {
  const legacy = new DatabaseSync(join(store.dataDir, DB_FILENAME));
  try {
    legacy.prepare(statement).run({
      id: `legacy-${packRow.packId}-${packRow.version}`,
      namespace: 'aka',
      packId: packRow.packId,
      version: packRow.version,
      name: packRow.packId,
      rulesJson: JSON.stringify(packRow.ruleIds.map(rule)),
      now: Date.now(),
    });
  } finally {
    legacy.close();
  }
}

function installedRow(packId: string): { version: string; rules: number } {
  const raw = new DatabaseSync(join(store.dataDir, DB_FILENAME));
  const row = raw
    .prepare(
      `SELECT version, json_array_length(rules_json) AS rules FROM installed_packs WHERE pack_id = ?`,
    )
    .get(packId) as { version: string; rules: number };
  raw.close();
  return row;
}

function mirrorRow(packId: string): { version: string; rules: number } {
  const raw = new DatabaseSync(join(store.dataDir, DB_FILENAME));
  const row = raw
    .prepare(
      `SELECT version, json_array_length(rules_json) AS rules FROM available_packs WHERE pack_id = ?`,
    )
    .get(packId) as { version: string; rules: number };
  raw.close();
  return row;
}

// ─── Invariant 1: installed content moves only through applyUpdate ───────────

describe('legacy alpha.5 upsert vs installed_packs (write gate)', () => {
  it('cannot clobber a manually applied update — and raises no error', () => {
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    db.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);
    expect(db.installedPacks.applyUpdate('aka', 'secrets')).toBe(true);
    db.close();
    expect(installedRow('secrets')).toEqual({ version: '2.5.0', rules: 2 });

    expect(() => {
      replayRaw(LEGACY_ALPHA5_UPSERT, {
        packId: 'secrets',
        version: '2.1.0',
        ruleIds: ['secrets/aws'],
      });
    }).not.toThrow();
    expect(installedRow('secrets')).toEqual({ version: '2.5.0', rules: 2 });
  });

  it('cannot rewrite an installed pack even when no update was ever applied', () => {
    // The gate is unconditional, not "only after applyUpdate": a legacy binary
    // must not auto-sync installed content in EITHER direction (up or down).
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    db.close();

    // no-throw is part of the invariant here too (same RAISE(IGNORE) path as
    // the clobber test): the legacy writer must be silently ignored, not
    // crashed — a crash in a shipped hook breaks the user's session.
    expect(() => {
      replayRaw(LEGACY_ALPHA5_UPSERT, {
        packId: 'secrets',
        version: '9.9.9',
        ruleIds: ['secrets/aws', 'secrets/gh', 'secrets/slack'],
      });
    }).not.toThrow();
    expect(installedRow('secrets')).toEqual({ version: '2.0.0', rules: 1 });
  });

  it('still auto-installs a brand-new pack (INSERTs stay open to every generation)', () => {
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    db.close();

    replayRaw(LEGACY_ALPHA5_UPSERT, {
      packId: 'legacy-pack',
      version: '1.0.0',
      ruleIds: ['legacy/a'],
    });
    expect(installedRow('legacy-pack')).toEqual({ version: '1.0.0', rules: 1 });
  });
});

// ─── Invariant 3: the mirror is data-guarded, not gated ──────────────────────

describe('legacy alpha.6 mirror upsert vs available_packs (downgrade guard boundary)', () => {
  it('current-generation recordInventory refuses a mirror downgrade (the app-level guard holds)', () => {
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);
    // An older binary re-records its narrower inventory through the CURRENT
    // repository code — the isMirrorDowngrade guard must leave the mirror alone.
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    db.close();
    expect(mirrorRow('secrets')).toEqual({ version: '2.5.0', rules: 2 });
    // And the installed side (what actually scans) is equally untouched — a
    // guard regression that also corrupted installed_packs would be the worse
    // bug, so pin both rows like the raw-replay test below does.
    expect(installedRow('secrets')).toEqual({ version: '2.5.0', rules: 2 });
  });

  it('a RAW alpha.6 mirror upsert can still rewrite the mirror — the documented, bounded gap', () => {
    // The guard lives in each generation's app code, and every mirror-writing
    // generation (alpha.6+) ships it — this raw replay simulates a hypothetical
    // guard-less writer to pin the blast radius: the mirror mis-advertises,
    // but installed_packs (what actually scans) is untouched, and applying the
    // "update" would need a deliberate user action.
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', '2.5.0', ['secrets/aws', 'secrets/gh'])]);
    db.close();

    replayRaw(LEGACY_ALPHA6_MIRROR_UPSERT, {
      packId: 'secrets',
      version: '2.0.0',
      ruleIds: ['secrets/aws'],
    });
    expect(mirrorRow('secrets')).toEqual({ version: '2.0.0', rules: 1 }); // the gap
    expect(installedRow('secrets')).toEqual({ version: '2.5.0', rules: 2 }); // the bound
  });
});

// ─── Invariant 4: policy_id is app-guarded, not gated ────────────────────────

// ╔═══════════════════════════════════════════════════════════════════════╗
// ║ DO NOT EDIT — PINNED ARTIFACT. Vendored VERBATIM from the pre-floor     ║
// ║ setPolicy. Byte-exactness with what shipped binaries execute is the     ║
// ║ guarantee; any reformat silently voids it while the test stays green.   ║
// ╚═══════════════════════════════════════════════════════════════════════╝
const LEGACY_POLICY_ASSIGN = `UPDATE installed_packs SET policy_id = :policyId, updated_at = :now
         WHERE namespace = :namespace AND pack_id = :packId`;

// Attach the temp machine and give it a control plane that demands Block for
// every secret rule — the smallest bundle that makes a floor exist at all.
function attachWithSecretBlockFloor(): void {
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
  const blockSecrets: Policy = {
    id: '00000000-0000-4000-8000-00000000f100',
    scope: 'global',
    target: { category: 'secret' },
    action: 'block',
    enabled: true,
  };
  const bundle: PolicyBundle = {
    version: '1',
    policies: [blockSecrets],
    customKeywords: [],
    fetchedAt: new Date(0).toISOString(),
  };
  writeFileSync(
    join(store.dataDir, POLICY_CACHE_FILENAME),
    JSON.stringify({ bundle, fetchedAtMs: 0 }),
  );
}

function policyIdRow(packId: string): string | null {
  const raw = new DatabaseSync(join(store.dataDir, DB_FILENAME));
  const row = raw
    .prepare(`SELECT policy_id AS policyId FROM installed_packs WHERE pack_id = ?`)
    .get(packId) as { policyId: string | null } | undefined;
  raw.close();
  return row?.policyId ?? null;
}

describe('legacy policy_id writer vs installed_packs (floor boundary)', () => {
  it('the CURRENT repository refuses a below-floor assignment (the app-level guard holds)', () => {
    attachWithSecretBlockFloor();
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    db.installedPacks.setPolicy('aka', 'secrets', 'block');

    expect(() => db.installedPacks.setPolicy('aka', 'secrets', 'monitor')).toThrow(
      PolicyFloorError,
    );
    db.close();
    expect(policyIdRow('secrets')).toBe('block');
  });

  it('a RAW pre-floor assignment can still downgrade the row — the documented, bounded gap', () => {
    // The write gate covers version/name/rules_json only, so nothing at the
    // DATABASE level stops this, and nothing could: an app-level guard does not
    // bind code already on disk. The bound is that the row is not the
    // enforcement — an attached runtime re-derives the effective action from
    // the control plane's bundle raise-only on every hook, so the downgraded
    // row cannot weaken what actually runs.
    attachWithSecretBlockFloor();
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    db.installedPacks.setPolicy('aka', 'secrets', 'block');
    db.close();

    const legacy = new DatabaseSync(join(store.dataDir, DB_FILENAME));
    try {
      legacy.prepare(LEGACY_POLICY_ASSIGN).run({
        policyId: 'monitor',
        now: Date.now(),
        namespace: 'aka',
        packId: 'secrets',
      });
    } finally {
      legacy.close();
    }
    expect(policyIdRow('secrets')).toBe('monitor'); // the gap
    // And the bound: the pack's own content is untouched, so the ruleset the
    // control plane's bundle is merged against is exactly what it was.
    expect(installedRow('secrets')).toEqual({ version: '2.0.0', rules: 1 });
  });

  it('a raw assignment stays open on a machine no control plane governs', () => {
    // No settings descriptor, no cache: the floor exists only for an attached
    // machine, and a standalone one keeps the assignment entirely its own.
    const db = store.open();
    db.installedPacks.recordInventory([pack('secrets', '2.0.0', ['secrets/aws'])]);
    expect(db.installedPacks.setPolicy('aka', 'secrets', 'monitor')).toBe(true);
    db.close();
    expect(policyIdRow('secrets')).toBe('monitor');
  });
});
