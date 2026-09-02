import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import type { VaultDerefReason } from '@akasecurity/schema';
import { DEFAULT_VAULT_INVENTORY_LIMIT, MAX_VAULT_PAGE_LIMIT } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { VaultRowInsert } from '../../src/repositories/secret-vault.ts';
import { SqliteSecretVaultRepository } from '../../src/repositories/secret-vault.ts';
import { useTempStore } from '../helpers/temp-store.ts';

const NOW = Date.parse('2026-06-29T12:00:00.000Z');

// The package's shared store harness owns the temp tree and closes every handle
// it hands out at teardown.
const store = useTempStore('aka-vault-', { migrated: true });
let raw: DatabaseSync;
let vault: SqliteSecretVaultRepository;

beforeEach(() => {
  // Applies the migrations; the repository under test runs on a second
  // connection to the same migrated file.
  store.open();
  raw = store.openRaw();
  vault = new SqliteSecretVaultRepository(raw);
});

const FINGERPRINT_A = 'a'.repeat(64);
const FINGERPRINT_B = 'b'.repeat(64);

function entry(overrides: Partial<VaultRowInsert> = {}): VaultRowInsert {
  return {
    pointerId: 'pointer-a',
    valueFingerprint: FINGERPRINT_A,
    fingerprintKeyVersion: 1,
    keyVersion: 1,
    category: 'secret',
    ruleId: 'aka.secret.aws-key',
    maskedMatch: 'AKIA…XYZQ',
    provider: 'aws',
    ciphertext: 'Y2lwaGVy',
    nonce: 'bm9uY2U=',
    authTag: 'dGFn',
    ...overrides,
  };
}

// A distinct 64-char hex fingerprint per pointer, DERIVED from the pointer id
// rather than counted out: a sequence would have to be reset between tests, and
// a seed helper that forgot would fold two rows into one by fingerprint.
function fingerprintFor(pointerId: string): string {
  return Buffer.from(pointerId).toString('hex').padEnd(64, '0');
}

// One detection of the value behind `pointerId`. The first call mints the row;
// every later call with the same pointer id bumps its occurrence count and
// last_seen, because `upsert` keys on the fingerprint.
function detect(pointerId: string, at: number): void {
  vault.upsert(entry({ pointerId, valueFingerprint: fingerprintFor(pointerId) }), at);
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

describe('SqliteSecretVaultRepository.upsert', () => {
  it('bumps the existing row instead of minting a second one', () => {
    const first = vault.upsert(entry(), NOW);
    const second = vault.upsert(entry(), NOW + 1_000);

    expect(first.minted).toBe(true);
    expect(second.minted).toBe(false);
    expect(vault.countEntries()).toBe(1);
    expect(second.row.pointerId).toBe(first.row.pointerId);
    expect(second.row.occurrenceCount).toBe(2);
    expect(second.row.firstSeen).toBe(NOW);
    expect(second.row.lastSeen).toBe(NOW + 1_000);
  });

  it('keeps the minted category, pointer and ciphertext on a repeat sighting', () => {
    const first = vault.upsert(entry(), NOW);
    const second = vault.upsert(
      entry({
        pointerId: 'pointer-second-attempt',
        category: 'pii',
        ruleId: 'aka.pii.email',
        ciphertext: 'ZGlmZmVyZW50',
        nonce: 'ZGlmZmVyZW50Tg==',
        authTag: 'ZGlmZmVyZW50VA==',
        keyVersion: 7,
      }),
      NOW + 1_000,
    );

    expect(second.row.pointerId).toBe(first.row.pointerId);
    expect(second.row.category).toBe('secret');
    expect(second.row.ciphertext).toBe(first.row.ciphertext);
    expect(second.row.nonce).toBe(first.row.nonce);
    expect(second.row.authTag).toBe(first.row.authTag);
    expect(second.row.keyVersion).toBe(1);
    // The discarded pointer never becomes addressable.
    expect(vault.byPointerId('pointer-second-attempt')).toBeNull();
  });

  it('mints a separate row per distinct fingerprint', () => {
    const a = vault.upsert(entry(), NOW);
    const b = vault.upsert(entry({ pointerId: 'pointer-b', valueFingerprint: FINGERPRINT_B }), NOW);

    expect(b.minted).toBe(true);
    expect(vault.countEntries()).toBe(2);
    expect(b.row.pointerId).not.toBe(a.row.pointerId);
    expect(vault.listAll().map((r) => r.pointerId)).toEqual(['pointer-a', 'pointer-b']);
  });
});

describe('SqliteSecretVaultRepository lookups', () => {
  it('round-trips a full row by pointer id and by fingerprint', () => {
    const { row } = vault.upsert(entry(), NOW);

    expect(vault.byPointerId('pointer-a')).toEqual(row);
    expect(vault.byValueFingerprint(FINGERPRINT_A)).toEqual(row);
    expect(row).toMatchObject({
      pointerId: 'pointer-a',
      valueFingerprint: FINGERPRINT_A,
      fingerprintKeyVersion: 1,
      keyVersion: 1,
      category: 'secret',
      ruleId: 'aka.secret.aws-key',
      maskedMatch: 'AKIA…XYZQ',
      provider: 'aws',
      ciphertext: 'Y2lwaGVy',
      nonce: 'bm9uY2U=',
      authTag: 'dGFn',
      occurrenceCount: 1,
      firstSeen: NOW,
      lastSeen: NOW,
    });
  });

  it('returns null on a miss', () => {
    expect(vault.byPointerId('nope')).toBeNull();
    expect(vault.byValueFingerprint(FINGERPRINT_B)).toBeNull();
  });
});

describe('SqliteSecretVaultRepository.recordDeref', () => {
  it('writes an audit row carrying neither the raw value nor the ciphertext', () => {
    vault.upsert(entry(), NOW);
    vault.recordDeref({
      id: randomUUID(),
      pointerId: 'pointer-a',
      at: NOW,
      target: 'model',
      reason: 'model-input',
      outcome: 'revealed',
      grantId: 'grant-1',
    });

    const rows = raw.prepare('SELECT * FROM secret_vault_deref').all();
    expect(rows).toHaveLength(1);
    const stored = rows[0] as Record<string, unknown>;
    expect(stored).toMatchObject({
      pointer_id: 'pointer-a',
      at: NOW,
      target: 'model',
      reason: 'model-input',
      outcome: 'revealed',
      grant_id: 'grant-1',
      // Unbatched crossings count one pointer.
      pointer_count: 1,
    });
    const columns = Object.keys(stored);
    expect(columns).not.toContain('ciphertext');
    expect(columns).not.toContain('value_fingerprint');
    expect(JSON.stringify(stored)).not.toContain('Y2lwaGVy');
  });

  it('stores a supplied batched pointer count as given', () => {
    vault.recordDeref({
      id: randomUUID(),
      pointerId: 'pointer-a',
      at: NOW,
      target: 'human',
      reason: 'display',
      outcome: 'revealed',
      pointerCount: 4,
    });

    const stored = raw
      .prepare('SELECT pointer_count AS n, grant_id AS g FROM secret_vault_deref')
      .get();
    expect(stored).toMatchObject({ n: 4, g: null });
  });
});

describe('SqliteSecretVaultRepository re-key writes', () => {
  it('replaceCiphertext changes only the sealed fields', () => {
    const { row } = vault.upsert(entry(), NOW);
    vault.replaceCiphertext('pointer-a', {
      keyVersion: 2,
      ciphertext: 'cmVzZWFsZWQ=',
      nonce: 'bmV3bm9uY2U=',
      authTag: 'bmV3dGFn',
    });

    expect(vault.byPointerId('pointer-a')).toEqual({
      ...row,
      keyVersion: 2,
      ciphertext: 'cmVzZWFsZWQ=',
      nonce: 'bmV3bm9uY2U=',
      authTag: 'bmV3dGFn',
    });
  });

  it('refreshFingerprint changes only the fingerprint fields', () => {
    const { row } = vault.upsert(entry(), NOW);
    vault.refreshFingerprint('pointer-a', {
      valueFingerprint: FINGERPRINT_B,
      fingerprintKeyVersion: 3,
    });

    expect(vault.byPointerId('pointer-a')).toEqual({
      ...row,
      valueFingerprint: FINGERPRINT_B,
      fingerprintKeyVersion: 3,
    });
  });
});

describe('SqliteSecretVaultRepository.purgeAll', () => {
  it('destroys every value and leaves the deref audit standing', () => {
    vault.upsert(entry(), NOW);
    vault.upsert(entry({ pointerId: 'pointer-b', valueFingerprint: FINGERPRINT_B }), NOW);
    vault.recordDeref({
      id: randomUUID(),
      pointerId: 'pointer-a',
      at: NOW,
      target: 'human',
      reason: 'explicit-reveal',
      outcome: 'revealed',
    });

    expect(vault.purgeAll()).toBe(2);
    expect(vault.countEntries()).toBe(0);
    expect(vault.listAll()).toEqual([]);
    expect(vault.byPointerId('pointer-a')).toBeNull();
    // The record that a de-reference happened outlives the values.
    expect(raw.prepare('SELECT COUNT(*) AS n FROM secret_vault_deref').get()).toMatchObject({
      n: 1,
    });
    expect(vault.purgeAll()).toBe(0);
  });
});

// The provenance marker: the row's record that a PERSON asked for this value to
// be replaced, rather than a pack enforcing its assignment. It matters here
// rather than in the caller because one value is ONE row — every path that
// vaults the same value lands on it — so the store is the only place that can
// keep the two statements from overwriting each other.
describe('SqliteSecretVaultRepository.upsert — userAuthorized', () => {
  it('defaults to false, which is what an enforcing path writes', () => {
    expect(vault.upsert(entry(), NOW).row.userAuthorized).toBe(false);
    // And a row written before the column existed reads the same way: the
    // migration's default is the enforcing path, not the user one.
    expect(vault.byPointerId('pointer-a')?.userAuthorized).toBe(false);
  });

  it('records the marker when the user path mints the row', () => {
    const minted = vault.upsert(entry({ userAuthorized: true }), NOW);

    expect(minted.minted).toBe(true);
    expect(minted.row.userAuthorized).toBe(true);
    expect(vault.byPointerId('pointer-a')?.userAuthorized).toBe(true);
  });

  it('sets the marker when the user strikes a value already vaulted automatically', () => {
    vault.upsert(entry(), NOW);

    // Same value, so the same row — this is the shape the surfaced-secrets
    // Redact button produces for a value the transcript scrub had already taken.
    const struck = vault.upsert(entry({ userAuthorized: true }), NOW + 1_000);

    expect(struck.minted).toBe(false);
    expect(struck.row.userAuthorized).toBe(true);
    expect(struck.row.occurrenceCount).toBe(2);
  });

  it('keeps the marker when an automatic path vaults the same value afterwards', () => {
    vault.upsert(entry({ userAuthorized: true }), NOW);

    // The sticky half, and the one an ordinary assignment would break: this
    // call carries no marker, and assigning it would erase what the user said.
    const again = vault.upsert(entry(), NOW + 1_000);

    expect(again.row.userAuthorized).toBe(true);
    expect(vault.byPointerId('pointer-a')?.userAuthorized).toBe(true);
    // The control on the same call: it really did write, so the assertion above
    // is not passing because nothing happened.
    expect(again.row.occurrenceCount).toBe(2);
    expect(again.row.lastSeen).toBe(NOW + 1_000);
  });

  it('leaves the marker of a neighbouring value alone', () => {
    vault.upsert(entry({ userAuthorized: true }), NOW);
    vault.upsert(entry({ pointerId: 'pointer-b', valueFingerprint: FINGERPRINT_B }), NOW);

    expect(vault.byPointerId('pointer-a')?.userAuthorized).toBe(true);
    expect(vault.byPointerId('pointer-b')?.userAuthorized).toBe(false);
  });
});

describe('SqliteSecretVaultRepository.deleteByPointerIds', () => {
  it('destroys only the named entries and leaves the deref audit standing', () => {
    vault.upsert(entry(), NOW);
    vault.upsert(entry({ pointerId: 'pointer-b', valueFingerprint: FINGERPRINT_B }), NOW);
    vault.recordDeref({
      id: randomUUID(),
      pointerId: 'pointer-a',
      at: NOW,
      target: 'human',
      reason: 'remediation',
      outcome: 'revealed',
    });

    expect(vault.deleteByPointerIds(['pointer-a'])).toEqual(['pointer-a']);
    expect(vault.byPointerId('pointer-a')).toBeNull();
    // The scope is the whole point: everything not named survives.
    expect(vault.byPointerId('pointer-b')).not.toBeNull();
    expect(vault.countEntries()).toBe(1);
    // Same rule as the purge: the record that a de-reference happened outlives
    // the value it was against.
    expect(raw.prepare('SELECT COUNT(*) AS n FROM secret_vault_deref').get()).toMatchObject({
      n: 1,
    });
  });

  it('reports only rows that were really there, and takes an empty set', () => {
    vault.upsert(entry(), NOW);

    expect(vault.deleteByPointerIds([])).toEqual([]);
    expect(vault.countEntries()).toBe(1);
    // An id the store does not hold is not an error — a caller assembling a set
    // from an earlier read may name one that has since gone. It is also not
    // part of the answer: the caller's next act is an audit row per destroyed
    // entry, and a purge recorded for a row this call did not destroy is a
    // false record of destruction. `pointer-a` alongside it is the positive
    // control — the id that WAS there still comes back.
    expect(vault.deleteByPointerIds(['pointer-a', 'pointer-ghost'])).toEqual(['pointer-a']);
    expect(vault.countEntries()).toBe(0);
  });

  it('leaves every row standing when one delete in the set throws', () => {
    vault.upsert(entry(), NOW);
    vault.upsert(entry({ pointerId: 'pointer-b', valueFingerprint: FINGERPRINT_B }), NOW);

    // A pointer id node:sqlite refuses to bind at all: the run throws partway
    // through the loop, after the first delete has already executed. Without
    // one transaction over the set that first row is gone and the caller is
    // told nothing. (A number would bind cleanly — SQLite columns carry no type
    // affinity here — and simply match nothing.)
    expect(() => vault.deleteByPointerIds(['pointer-a', {} as unknown as string])).toThrow();

    expect(vault.countEntries()).toBe(2);
    expect(vault.byPointerId('pointer-a')).not.toBeNull();
    // The failure must not strand an open transaction on the handle either.
    expect(raw.isTransaction).toBe(false);
  });
});

// The inventory's revealable badge and the actual crossing must share ONE
// definition of "an active reveal grant". The crossing (activeRevealGrant)
// fails closed on a grant with conditions — the reveal path does not evaluate
// them, and ignoring a narrowing clause would widen the grant — so the badge
// must refuse the same grant, or the dashboard says "revealable" where the
// de-reference then refuses.
describe('SqliteSecretVaultRepository.listInventory grant badge', () => {
  function grantRow(overrides: { conditions?: string | null } = {}): void {
    raw
      .prepare(
        `INSERT INTO exceptions (
           id, rule_id, category, value_fingerprint, key_version, masked_value,
           capability, scope, expires_at, max_uses, use_count, last_used_at,
           justification, conditions, created_by, created_via, created_at,
           updated_at, revoked_at, revoked_by, revoke_reason
         ) VALUES (
           :id, 'aka.secret.aws-key', 'secret', :fp, 1, 'AKIA…XYZQ',
           'reveal_to_model', 'permanent', NULL, NULL, 0, NULL,
           'test', :conditions, 'tester', 'cli-add', :now,
           :now, NULL, NULL, NULL
         )`,
      )
      .run({
        id: randomUUID(),
        fp: FINGERPRINT_A,
        conditions: overrides.conditions ?? null,
        now: NOW,
      });
  }

  it('badges a clean active reveal grant', () => {
    vault.upsert(entry(), NOW);
    grantRow();
    expect(vault.listInventory({}, NOW).items[0]?.revealGrantId).not.toBeNull();
  });

  it('refuses to badge a conditioned grant, exactly as the crossing refuses it', () => {
    vault.upsert(entry(), NOW);
    grantRow({ conditions: JSON.stringify({ repo: 'github.com/example/app' }) });
    expect(vault.listInventory({}, NOW).items[0]?.revealGrantId).toBeNull();
  });
});

// The three dashboard lists are keyset-paged rather than loaded whole. What a
// walk holds that a single-page assertion cannot: a cursor minted from the extra
// probe row, or an ORDER BY that leaves ties unresolved, drops a row SILENTLY —
// every page still looks well-formed, and only the concatenation is short.
describe('SqliteSecretVaultRepository.listInventory paging', () => {
  // Newest-first insertion, with `ptr-04a` written BEFORE `ptr-04b` at the same
  // last_seen: pointer_id DESC is therefore not insertion order, so an ordering
  // that falls back to the table's own is visible.
  const SEED: readonly (readonly [string, number])[] = [
    ['ptr-06', NOW + 6_000],
    ['ptr-05', NOW + 5_000],
    ['ptr-04a', NOW + 4_000],
    ['ptr-04b', NOW + 4_000],
    ['ptr-03', NOW + 3_000],
    ['ptr-02', NOW + 2_000],
    ['ptr-01', NOW + 1_000],
  ];

  // last_seen DESC, pointer_id DESC. Written out rather than derived by sorting
  // SEED — a comparator here would be free to carry the same defect the read
  // has. The tied pair sits at indices 2 and 3, so with limit 3 it straddles the
  // first page boundary: an unresolved tie does not merely reorder the pair, it
  // mints a cursor that excludes one of them from every later page.
  const EXPECTED_ORDER = ['ptr-06', 'ptr-05', 'ptr-04b', 'ptr-04a', 'ptr-03', 'ptr-02', 'ptr-01'];

  function seed(): void {
    for (const [pointerId, at] of SEED) detect(pointerId, at);
  }

  interface Walk {
    pointerIds: string[];
    totals: number[];
    cursors: (string | null)[];
  }

  function walk(limit: number): Walk {
    const pointerIds: string[] = [];
    const totals: number[] = [];
    const cursors: (string | null)[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 20; page += 1) {
      const res = vault.listInventory({ limit, ...(cursor === undefined ? {} : { cursor }) }, NOW);
      pointerIds.push(...res.items.map((i) => i.pointerId));
      totals.push(res.totals.values);
      cursors.push(res.nextCursor);
      if (res.nextCursor === null) break;
      cursor = res.nextCursor;
    }
    return { pointerIds, totals, cursors };
  }

  it('walks every row exactly once, newest first, with pointer_id breaking ties', () => {
    seed();
    const walked = walk(3);

    expect(walked.pointerIds).toEqual(EXPECTED_ORDER);
    // Against the store rather than against the literal above: a row the walk
    // never reached is a hole this catches even if both were edited together.
    expect(walked.pointerIds).toHaveLength(vault.countEntries());
    // Pages of 3 / 3 / 1 — only the last one ends the walk.
    expect(walked.cursors).toHaveLength(3);
    expect(walked.cursors[0]).not.toBeNull();
    expect(walked.cursors[1]).not.toBeNull();
    expect(walked.cursors[2]).toBeNull();
  });

  it('reports totals.values over the whole store on every page', () => {
    seed();
    const walked = walk(3);

    expect(walked.totals).toEqual([SEED.length, SEED.length, SEED.length]);
    expect(vault.countEntries()).toBe(SEED.length);
  });

  it('restarts from the top on an undecodable cursor', () => {
    seed();
    const fresh = vault.listInventory({ limit: 3 }, NOW);
    const restarted = vault.listInventory({ limit: 3, cursor: 'not-a-cursor' }, NOW);

    // The positive control: without it both sides could be empty and agree.
    expect(fresh.items.map((i) => i.pointerId)).toEqual(EXPECTED_ORDER.slice(0, 3));
    expect(restarted.items.map((i) => i.pointerId)).toEqual(fresh.items.map((i) => i.pointerId));
  });

  // A cursor that fails at JSON.parse — the case above — never reaches the
  // decoder's type predicate, so it cannot tell `typeof x === 'number'` from
  // `Number.isInteger(x)`. These do: each decodes cleanly and carries a number
  // SQLite will bind without complaint. Under the looser check they produce an
  // empty page with a null cursor, which every caller reads as "end of list" —
  // the list silently truncated by a hand-edited request, and the one outcome
  // "restarts from the top" must never mean. (`1e999` is valid JSON; `NaN` is
  // not, so it cannot arrive this way.)
  it.each([
    ['positive infinity', '1e999'],
    ['negative infinity', '-1e999'],
    ['a fraction', '1.5'],
  ])('restarts from the top on a decodable cursor carrying %s', (_label, literal) => {
    seed();
    const cursor = Buffer.from(`{"startedAtMs":${literal},"id":"zzz"}`).toString('base64url');

    const fresh = vault.listInventory({ limit: 3 }, NOW);
    const restarted = vault.listInventory({ limit: 3, cursor }, NOW);

    expect(fresh.items.map((i) => i.pointerId)).toEqual(EXPECTED_ORDER.slice(0, 3));
    expect(restarted.items.map((i) => i.pointerId)).toEqual(fresh.items.map((i) => i.pointerId));
    expect(restarted.nextCursor).not.toBeNull();
  });

  it('pages at DEFAULT_VAULT_INVENTORY_LIMIT when the query omits a limit', () => {
    const total = DEFAULT_VAULT_INVENTORY_LIMIT + 5;
    for (let i = 0; i < total; i += 1) {
      detect(`bulk-${String(i).padStart(3, '0')}`, NOW + i * 1_000);
    }

    const res = vault.listInventory();

    expect(res.items).toHaveLength(DEFAULT_VAULT_INVENTORY_LIMIT);
    expect(res.nextCursor).not.toBeNull();
    expect(res.totals.values).toBe(total);
  });

  // The Server Actions already cap `limit`, so this is about the OTHER callers —
  // the repository is exported, and a page is hydrated through one `IN (…)` with
  // a bind variable per row, which SQLite refuses to prepare past 32766 of.
  //
  // The fixture has to straddle the cap. Seeded below it, a clamped and an
  // unclamped read return exactly the same page, and the case passes whether or
  // not the clamp is there.
  it('clamps an over-large limit to MAX_VAULT_PAGE_LIMIT', () => {
    const total = MAX_VAULT_PAGE_LIMIT + 5;
    for (let i = 0; i < total; i += 1) {
      detect(`cap-${String(i).padStart(4, '0')}`, NOW + i * 1_000);
    }

    const res = vault.listInventory({ limit: 5_000 });

    expect(res.items).toHaveLength(MAX_VAULT_PAGE_LIMIT);
    // Not the end of the list: the clamp bounded the page, it did not truncate
    // the walk. Without this a clamp to zero rows would satisfy the length check.
    expect(res.nextCursor).not.toBeNull();
    expect(res.totals.values).toBe(total);
  });

  // The reachability the dashboard's empty-page handling rests on, pinned at the
  // layer that decides it. A bump moves a row toward page 1 — ABOVE a cursor
  // already handed out — so re-detecting the only row past a full page leaves
  // the next page with nothing on it, while `totals` still counts it. The client
  // renders whatever this returns, and an empty later page used to strand the
  // reader on a view with no pager.
  it('returns an empty later page when the only unwalked row is bumped above the cursor', () => {
    for (let i = 0; i < 4; i += 1) detect(`bump-${String(i)}`, NOW + i * 1_000);

    const first = vault.listInventory({ limit: 3 });
    expect(first.items.map((i) => i.pointerId)).toEqual(['bump-3', 'bump-2', 'bump-1']);
    expect(first.nextCursor).not.toBeNull();

    // `bump-0` is the whole of page 2. Detecting it again stamps last_seen to a
    // time above the cursor page 1 just minted.
    detect('bump-0', NOW + 9_000);

    const second = vault.listInventory({ limit: 3, cursor: first.nextCursor ?? undefined });

    expect(second.items).toEqual([]);
    expect(second.nextCursor).toBeNull();
    // Counted over the store, not the walk — which is what makes the shortfall
    // visible rather than silent.
    expect(second.totals.values).toBe(4);
  });

  // A floor as well as a ceiling. `limit: 0` binds `LIMIT 1`, keeps none of it
  // (`slice(0, 0)`), and reports no next cursor — an empty page that reads as
  // the end of a list which is not empty.
  it('floors a zero limit rather than serving an empty terminal page', () => {
    for (let i = 0; i < 3; i += 1) detect(`floor-${String(i)}`, NOW + i * 1_000);

    const res = vault.listInventory({ limit: 0 });

    expect(res.items).toHaveLength(1);
    expect(res.nextCursor).not.toBeNull();
  });

  // The boundary the walks above cannot reach: they end on a SHORT page, where
  // `rows.length > limit` and `rows.length >= limit` agree. Only a terminal page
  // exactly `limit` rows long separates them — and off by one there costs no
  // rows, so every other assertion here stays green while the last real page
  // hands back a cursor and the dashboard renders a button that fetches nothing.
  it('ends the walk when the last page is exactly `limit` rows', () => {
    for (const [pointerId, at] of SEED.slice(0, 6)) detect(pointerId, at);
    expect(vault.countEntries()).toBe(6);

    const walked = walk(3);

    expect(walked.pointerIds).toHaveLength(6);
    // Two requests, not three: the second page fills exactly and still ends it.
    expect(walked.cursors).toEqual([expect.any(String), null]);
  });

  // The raw-free claim these two reads make is asserted nowhere else: the
  // fingerprint is keyed correlation material and the ciphertext is the value
  // itself, and both now cross a Server Action to the browser.
  //
  // The gate is `toInventoryEntries`' field-by-field mapping, NOT the SELECT
  // list — measured: widening INVENTORY_COLUMNS to select value_fingerprint
  // leaves this suite green, because the extra column reaches no response field.
  // So this asserts the RESPONSE's key set, which is where the property lives;
  // aim a mutation at the mapping to see it fail.
  it('carries no fingerprint and no sealed columns', () => {
    vault.upsert(entry(), NOW);
    vault.recordSighting({ pointerId: 'pointer-a', location: 'a.ts', kind: 'file' }, NOW);
    vault.upsert(entry({ pointerId: 'pointer-b', valueFingerprint: FINGERPRINT_B }), NOW);
    vault.upsert(entry({ pointerId: 'pointer-b', valueFingerprint: FINGERPRINT_B }), NOW + 1);

    for (const items of [vault.listInventory({}, NOW).items, vault.listReuse({}, NOW).items]) {
      // The positive control: an empty list satisfies every absence below.
      expect(items.length).toBeGreaterThan(0);
      const serialized = JSON.stringify(items);
      for (const secret of [FINGERPRINT_A, FINGERPRINT_B, 'Y2lwaGVy', 'bm9uY2U=', 'dGFn']) {
        expect(serialized).not.toContain(secret);
      }
      for (const item of items) {
        expect(Object.keys(item).sort()).toEqual(
          [
            'category',
            'firstSeen',
            'lastSeen',
            'maskedMatch',
            'occurrences',
            'pointerId',
            'provider',
            'revealGrantId',
            'sightings',
          ].sort(),
        );
      }
    }
  });
});

// The N+1 read this replaced asked one query per row, so misattribution was
// impossible by construction. One batched query grouped in JS can cross-wire
// instead — which is invisible to a count, and visible only to an assertion that
// names each row's OWN locations.
describe('SqliteSecretVaultRepository.listInventory sightings', () => {
  it('gives each row exactly its own locations, and an empty array for none', () => {
    detect('sight-a', NOW + 3_000);
    detect('sight-b', NOW + 2_000);
    detect('sight-c', NOW + 1_000);

    vault.recordSighting({ pointerId: 'sight-a', location: 'src/one.ts', kind: 'file' }, NOW + 100);
    vault.recordSighting({ pointerId: 'sight-a', location: 'src/two.ts', kind: 'file' }, NOW + 200);
    vault.recordSighting({ pointerId: 'sight-c', location: 'Bash', kind: 'tool-input' }, NOW + 300);

    const items = vault.listInventory({ limit: 10 }, NOW).items;
    const byPointer = new Map(items.map((i) => [i.pointerId, i.sightings]));

    expect(items.map((i) => i.pointerId)).toEqual(['sight-a', 'sight-b', 'sight-c']);
    expect(byPointer.get('sight-a')).toEqual([
      { location: 'src/two.ts', kind: 'file', firstSeen: iso(NOW + 200), lastSeen: iso(NOW + 200) },
      { location: 'src/one.ts', kind: 'file', firstSeen: iso(NOW + 100), lastSeen: iso(NOW + 100) },
    ]);
    // Present and empty, never absent — the caller must not have to tell the
    // two apart.
    expect(byPointer.get('sight-b')).toEqual([]);
    expect(byPointer.get('sight-c')).toEqual([
      { location: 'Bash', kind: 'tool-input', firstSeen: iso(NOW + 300), lastSeen: iso(NOW + 300) },
    ]);
  });

  it("orders a row's sightings by last_seen, newest first", () => {
    detect('sight-a', NOW);
    vault.recordSighting({ pointerId: 'sight-a', location: 'src/one.ts', kind: 'file' }, NOW + 100);
    vault.recordSighting({ pointerId: 'sight-a', location: 'src/two.ts', kind: 'file' }, NOW + 200);
    // Re-sighting the FIRST location last: it now sorts first on last_seen and
    // last on first_seen, so ordering on the wrong column reverses the pair.
    vault.recordSighting({ pointerId: 'sight-a', location: 'src/one.ts', kind: 'file' }, NOW + 400);

    expect(vault.listInventory({ limit: 10 }, NOW).items[0]?.sightings).toEqual([
      { location: 'src/one.ts', kind: 'file', firstSeen: iso(NOW + 100), lastSeen: iso(NOW + 400) },
      { location: 'src/two.ts', kind: 'file', firstSeen: iso(NOW + 200), lastSeen: iso(NOW + 200) },
    ]);
  });
});

describe('SqliteSecretVaultRepository.listReuse', () => {
  // occurrence_count DESC, pointer_id DESC. `reuse-mid-a` is written before
  // `reuse-mid-b` at the same count, so pointer_id DESC is not insertion order,
  // and with limit 1 the tied pair straddles a page boundary.
  const EXPECTED_REUSE = ['reuse-hi', 'reuse-mid-b', 'reuse-mid-a', 'reuse-spread'];

  function seedReuse(): void {
    // Detected three times.
    detect('reuse-hi', NOW + 1_000);
    detect('reuse-hi', NOW + 1_100);
    detect('reuse-hi', NOW + 1_200);

    // Detected twice, each.
    detect('reuse-mid-a', NOW + 2_000);
    detect('reuse-mid-a', NOW + 2_100);
    detect('reuse-mid-b', NOW + 3_000);
    detect('reuse-mid-b', NOW + 3_100);

    // Detected ONCE, but its pointer was written in two places — reuse by
    // spread rather than by count.
    detect('reuse-spread', NOW + 4_000);
    vault.recordSighting({ pointerId: 'reuse-spread', location: 'a.ts', kind: 'file' }, NOW);
    vault.recordSighting({ pointerId: 'reuse-spread', location: 'b.ts', kind: 'file' }, NOW);

    // Detected once, written in one place — not reuse.
    detect('reuse-solo', NOW + 5_000);
    vault.recordSighting({ pointerId: 'reuse-solo', location: 'c.ts', kind: 'file' }, NOW);
  }

  it('lists exactly the reused values, most-reused first', () => {
    seedReuse();
    const res = vault.listReuse({ limit: 10 }, NOW);

    expect(res.items.map((i) => i.pointerId)).toEqual(EXPECTED_REUSE);
    expect(res.items.map((i) => i.occurrences)).toEqual([3, 2, 2, 1]);
    // The excluded row is in the store — otherwise the exclusion above holds
    // because nothing was seeded.
    expect(vault.countEntries()).toBe(EXPECTED_REUSE.length + 1);
    expect(vault.byPointerId('reuse-solo')).not.toBeNull();
    expect(res.totals.reused).toBe(EXPECTED_REUSE.length);
  });

  it('walks every reused value once and keeps totals.reused page-independent', () => {
    seedReuse();
    const pointerIds: string[] = [];
    const totals: number[] = [];
    const cursors: (string | null)[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 20; page += 1) {
      const res = vault.listReuse({ limit: 1, ...(cursor === undefined ? {} : { cursor }) }, NOW);
      pointerIds.push(...res.items.map((i) => i.pointerId));
      totals.push(res.totals.reused);
      cursors.push(res.nextCursor);
      if (res.nextCursor === null) break;
      cursor = res.nextCursor;
    }

    expect(pointerIds).toEqual(EXPECTED_REUSE);
    expect(totals).toEqual([4, 4, 4, 4]);
    expect(vault.countReused()).toBe(EXPECTED_REUSE.length);
    expect(cursors[cursors.length - 1]).toBeNull();
    expect(cursors.slice(0, -1).every((c) => c !== null)).toBe(true);
    expect(cursors).toHaveLength(EXPECTED_REUSE.length);
  });

  it('restarts from the top on an undecodable cursor', () => {
    seedReuse();
    const fresh = vault.listReuse({ limit: 2 }, NOW);
    const restarted = vault.listReuse({ limit: 2, cursor: 'not-a-cursor' }, NOW);

    expect(fresh.items.map((i) => i.pointerId)).toEqual(EXPECTED_REUSE.slice(0, 2));
    expect(restarted.items.map((i) => i.pointerId)).toEqual(fresh.items.map((i) => i.pointerId));
  });

  // This list has its OWN decoder, so the inventory's copy of this case does
  // not cover it — see the note there for why a well-formed cursor carrying a
  // non-integer is the one that separates the two type checks.
  it.each([
    ['positive infinity', '1e999'],
    ['negative infinity', '-1e999'],
    ['a fraction', '1.5'],
  ])('restarts from the top on a decodable cursor carrying %s', (_label, literal) => {
    seedReuse();
    const cursor = Buffer.from(`{"occurrences":${literal},"pointerId":"zzz"}`).toString(
      'base64url',
    );

    const fresh = vault.listReuse({ limit: 2 }, NOW);
    const restarted = vault.listReuse({ limit: 2, cursor }, NOW);

    expect(fresh.items.map((i) => i.pointerId)).toEqual(EXPECTED_REUSE.slice(0, 2));
    expect(restarted.items.map((i) => i.pointerId)).toEqual(fresh.items.map((i) => i.pointerId));
    expect(restarted.nextCursor).not.toBeNull();
  });
});

describe('SqliteSecretVaultRepository.listDerefs', () => {
  // A guid whose lexical order the caller chooses. The trail orders on
  // (at DESC, id DESC), so a randomUUID would exercise the tie-break only by
  // luck — and would agree with insertion order half the time.
  function derefId(n: number): string {
    return `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`;
  }

  // THREE rows share `at`, and their ids resolve the tie into an order that is
  // neither the insertion order (31, 33, 32) nor its reverse (32, 33, 31): a
  // two-row tie cannot separate those two, and the table's own order is one of
  // them whichever way SQLite scans.
  const TRAIL: readonly { n: number; at: number; reason: VaultDerefReason }[] = [
    { n: 31, at: NOW + 700, reason: 'explicit-reveal' },
    { n: 95, at: NOW + 850, reason: 'display' },
    { n: 33, at: NOW + 700, reason: 'model-input' },
    { n: 10, at: NOW + 900, reason: 'explicit-reveal' },
    { n: 75, at: NOW + 750, reason: 'view-render' },
    { n: 32, at: NOW + 700, reason: 'explicit-reveal' },
    { n: 40, at: NOW + 600, reason: 'model-input' },
    { n: 65, at: NOW + 650, reason: 'display' },
    { n: 20, at: NOW + 800, reason: 'model-input' },
    { n: 55, at: NOW + 550, reason: 'view-render' },
  ];

  const EXPECTED_VISIBLE = [10, 20, 33, 32, 31, 40].map(derefId);
  const EXPECTED_ALL = [10, 95, 20, 75, 33, 32, 31, 65, 40, 55].map(derefId);
  const BATCHED_TOTAL = 4;

  function seedTrail(): void {
    for (const row of TRAIL) {
      vault.recordDeref({
        id: derefId(row.n),
        pointerId: 'pointer-a',
        at: row.at,
        target: row.reason === 'model-input' ? 'model' : 'human',
        reason: row.reason,
        outcome: 'revealed',
      });
    }
  }

  interface TrailWalk {
    ids: string[];
    reasons: string[];
    hidden: number[];
    cursors: (string | null)[];
  }

  function walkTrail(limit: number, includeBatched: boolean): TrailWalk {
    const ids: string[] = [];
    const reasons: string[] = [];
    const hidden: number[] = [];
    const cursors: (string | null)[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 20; page += 1) {
      const res = vault.listDerefs({
        limit,
        ...(includeBatched ? { includeBatched: true } : {}),
        ...(cursor === undefined ? {} : { cursor }),
      });
      ids.push(...res.items.map((i) => i.id));
      reasons.push(...res.items.map((i) => i.reason));
      hidden.push(res.hiddenBatched);
      cursors.push(res.nextCursor);
      if (res.nextCursor === null) break;
      cursor = res.nextCursor;
    }
    return { ids, reasons, hidden, cursors };
  }

  it('hides the batched reasons and walks the rest newest-first, ids breaking ties', () => {
    seedTrail();
    const walked = walkTrail(2, false);

    expect(walked.ids).toEqual(EXPECTED_VISIBLE);
    expect(walked.reasons).not.toContain('display');
    expect(walked.reasons).not.toContain('view-render');
    // Pages of 2 / 2 / 2 — the tie group straddles the second boundary.
    expect(walked.cursors).toHaveLength(3);
    expect(walked.cursors[0]).not.toBeNull();
    expect(walked.cursors[1]).not.toBeNull();
    expect(walked.cursors[2]).toBeNull();
  });

  it('counts hiddenBatched over the whole trail, unchanged as the reader pages', () => {
    seedTrail();
    const walked = walkTrail(2, false);

    // Every page is batched-free, so a count taken over the PAGE reads 0 while
    // the trail holds four.
    expect(walked.hidden).toEqual([BATCHED_TOTAL, BATCHED_TOTAL, BATCHED_TOTAL]);
    expect(
      raw
        .prepare(
          `SELECT COUNT(*) AS n FROM secret_vault_deref WHERE reason IN ('display', 'view-render')`,
        )
        .get(),
    ).toMatchObject({ n: BATCHED_TOTAL });
  });

  it('includes the batched rows and hides nothing when includeBatched is set', () => {
    seedTrail();
    const res = vault.listDerefs({ includeBatched: true, limit: 20 });

    expect(res.items.map((i) => i.id)).toEqual(EXPECTED_ALL);
    expect(res.items.map((i) => i.reason)).toContain('display');
    expect(res.items.map((i) => i.reason)).toContain('view-render');
    expect(res.hiddenBatched).toBe(0);
    expect(res.nextCursor).toBeNull();
  });

  it('walks the batched-inclusive trail exactly once across pages', () => {
    seedTrail();
    const walked = walkTrail(2, true);

    expect(walked.ids).toEqual(EXPECTED_ALL);
    expect(walked.ids).toHaveLength(TRAIL.length);
    expect(walked.hidden).toEqual([0, 0, 0, 0, 0]);
    expect(walked.cursors[walked.cursors.length - 1]).toBeNull();
    expect(walked.cursors.slice(0, -1).every((c) => c !== null)).toBe(true);
  });

  it('restarts from the top on an undecodable cursor', () => {
    seedTrail();
    const fresh = vault.listDerefs({ limit: 3 });
    const restarted = vault.listDerefs({ limit: 3, cursor: 'not-a-cursor' });

    expect(fresh.items.map((i) => i.id)).toEqual(EXPECTED_VISIBLE.slice(0, 3));
    expect(restarted.items.map((i) => i.id)).toEqual(fresh.items.map((i) => i.id));
  });

  // Both reads are index-only, and they use DIFFERENT indexes. The default page
  // filters out the two high-volume reasons, so `(at, id)` orders it but does
  // not narrow it — the walk would fetch each row and discard most of them. The
  // partial index carries the same predicate; the full one still serves the
  // toggle, where the partial does not apply. Asserting the plan rather than a
  // duration: the timing is single-digit ms either way on a small store, so
  // only the plan can tell an index-only read from a filtered scan.
  describe('query plans', () => {
    function planOf(sql: string): string {
      return (raw.prepare(`EXPLAIN QUERY PLAN ${sql}`).all() as { detail: string }[])
        .map((p) => p.detail)
        .join(' | ');
    }

    it('serves the default page from the partial index and the toggle from the full one', () => {
      seedTrail();

      const visible = planOf(
        `SELECT id, pointer_id, at, target, reason, outcome, grant_id, pointer_count
           FROM secret_vault_deref
          WHERE reason NOT IN ('display', 'view-render')
          ORDER BY at DESC, id DESC LIMIT 4`,
      );
      const all = planOf(
        `SELECT id, pointer_id, at, target, reason, outcome, grant_id, pointer_count
           FROM secret_vault_deref
          ORDER BY at DESC, id DESC LIMIT 4`,
      );

      expect(visible).toContain('idx_secret_vault_deref_signal');
      expect(all).toContain('idx_secret_vault_deref_at');
      // Neither sorts: a temp B-tree here would mean the index is ordering
      // nothing and the LIMIT is applied after the whole trail is read.
      expect(visible).not.toContain('TEMP B-TREE');
      expect(all).not.toContain('TEMP B-TREE');
    });
  });
});
