import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  applyOnboarding,
  createKeyProvider,
  dataDir,
  dbPath,
  EXCEPTION_KEY_FILENAME,
  keysDir,
  loadOrCreateFingerprintKey,
  type LocalDatabase,
  openLocalDatabase,
  readWorkspaceSettings,
  SecretVault,
} from '@akasecurity/persistence';
import type { VaultInventoryEntry } from '@akasecurity/schema';
import { isVaultConsentValid, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { grantRevealFromPointer, rotateKey } from '../../app/(app)/exceptions/actions.ts';
import {
  purgeVault,
  revealEntry,
  revokeRevealGrant,
  rotateVaultKey,
} from '../../app/(app)/vault/actions.ts';

// The vault manage surface: reveal-by-row-id, grant revocation, the purge, and
// the key rotation. The suite pins the audit and survival properties — one
// explicit-reveal deref row per reveal, an audit trail that outlives a purge,
// and pointers that keep resolving across a key rotation. A real node:sqlite
// store and real key files — no vault mocking (house style).
//
// The actions resolve the store from `homedir()` (never process.env), so the
// whole test is redirected into a temp home by mocking `node:os`; `next/cache`
// is stubbed because revalidatePath needs a Next render context that does not
// exist under vitest.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

// Not secret-shaped on purpose: tokenize never scans, and a plain string keeps
// secret-looking literals out of this public file.
const RAW = 'vaulted-value-for-web-manage-test';

let home: string;

// web-ui memoizes the open DB handle on globalThis (app/lib/db.ts). Close and
// drop it between tests so the next action reopens against the fresh home.
function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-vault-manage-'));
  osHome.dir = home;
  // Vaulting (tokenize) is consent-gated; grant it for the seeding step.
  applyOnboarding({
    vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION },
  });
});

afterEach(() => {
  resetSingleton();
  rmSync(home, { recursive: true, force: true });
});

// The construction every action performs — the vault over the local store with
// the settings-named key custody and live consent.
function buildVault(db: LocalDatabase): SecretVault {
  return new SecretVault({
    repo: db.secretVault,
    keys: createKeyProvider(readWorkspaceSettings().vaultKeyCustody, keysDir()),
    isConsented: () => isVaultConsentValid(readWorkspaceSettings().vaultConsent),
  });
}

// Seed one vaulted value through the real persistence SecretVault and return
// its wire pointer token.
async function seedPointer(): Promise<string> {
  const db = openLocalDatabase(dataDir());
  try {
    const pointer = await buildVault(db).tokenize(
      RAW,
      {
        ruleId: 'secrets/test-rule',
        category: 'secret',
        provider: 'aws',
        maskedMatch: 'vau…est',
      },
      () => loadOrCreateFingerprintKey(dataDir()),
    );
    if (typeof pointer !== 'string') throw new Error('seeding tokenize was refused');
    return pointer;
  } finally {
    db.close();
  }
}

function inventory(): VaultInventoryEntry[] {
  const db = openLocalDatabase(dataDir());
  try {
    return db.secretVault.listInventory().items;
  } finally {
    db.close();
  }
}

function seededPointerId(): string {
  const entry = inventory()[0];
  if (entry === undefined) throw new Error('no vault entry seeded');
  return entry.pointerId;
}

interface DerefRow {
  reason: string;
  outcome: string;
  target: string;
}

function derefRows(): DerefRow[] {
  const raw = new DatabaseSync(dbPath(), { readOnly: true });
  try {
    return raw
      .prepare('SELECT reason, outcome, target FROM secret_vault_deref ORDER BY rowid')
      .all() as unknown as DerefRow[];
  } finally {
    raw.close();
  }
}

function entryCount(): number {
  const raw = new DatabaseSync(dbPath(), { readOnly: true });
  try {
    const row = raw.prepare('SELECT COUNT(*) AS n FROM secret_vault').get() as { n: number };
    return row.n;
  } finally {
    raw.close();
  }
}

describe('revealEntry', () => {
  it('returns the raw value and writes exactly one explicit-reveal deref row', async () => {
    await seedPointer();
    const result = await revealEntry({ pointerId: seededPointerId() });

    expect(result).toEqual({ ok: true, value: RAW });
    expect(derefRows()).toEqual([
      { reason: 'explicit-reveal', outcome: 'revealed', target: 'human' },
    ]);
  });
});

describe('revokeRevealGrant', () => {
  it('flips the inventory row activeRevealGrant to null', async () => {
    const pointer = await seedPointer();
    const granted = await grantRevealFromPointer({
      pointer,
      scope: '1h',
      justification: 'integration test needs the live key',
    });
    expect(granted.ok).toBe(true);

    const before = inventory()[0];
    expect(before?.revealGrantId).not.toBeNull();
    if (before?.revealGrantId == null) throw new Error('unreachable');

    const result = await revokeRevealGrant({ grantId: before.revealGrantId });
    expect(result).toEqual({ ok: true });
    expect(inventory()[0]?.revealGrantId).toBeNull();
  });
});

// Fingerprint-key rotation invalidates GRANTS by design; it must never split
// the vault. Rotation re-keys every stored fingerprint under the new epoch, so
// the same value detected again still finds its row — otherwise it would
// fingerprint under the new key, miss dedup, and mint a second pointer for a
// secret that already has one in circulation.
describe('rotateKey keeps the vault whole', () => {
  it('re-keys stored fingerprints so a re-detection reuses the pointer', async () => {
    const pointer = await seedPointer();
    expect(entryCount()).toBe(1);

    expect(await rotateKey('rotate')).toEqual({ ok: true });
    resetSingleton();

    const again = await seedPointer();
    expect(again).toBe(pointer);
    expect(entryCount()).toBe(1);
  });
});

describe('purgeVault', () => {
  it('rejects anything but the typed confirmation, touching nothing', async () => {
    await seedPointer();
    const result = await purgeVault({ confirmation: 'Purge' });

    expect(result.ok).toBe(false);
    expect(entryCount()).toBe(1);
    expect(derefRows()).toEqual([]);
  });

  it('destroys every entry while the deref audit survives', async () => {
    await seedPointer();
    const pointerId = seededPointerId();
    // A reveal first, so the purge must preserve a pre-existing audit row too.
    await revealEntry({ pointerId });

    const result = await purgeVault({ confirmation: 'purge' });
    expect(result).toEqual({ ok: true, destroyed: 1 });
    expect(entryCount()).toBe(0);

    // The audit outlives the values: the earlier reveal row plus the purge's
    // own record.
    expect(derefRows()).toEqual([
      { reason: 'explicit-reveal', outcome: 'revealed', target: 'human' },
      { reason: 'purge', outcome: 'unavailable', target: 'human' },
    ]);

    // Every pointer is now permanently unresolvable.
    const after = await revealEntry({ pointerId });
    expect(after).toEqual({ ok: true, value: null });
  });
});

// The exception fingerprint key is a WRITE dependency: it keys the ledger, and
// none of these surfaces writes a fingerprint. A dashboard left open is a
// long-lived process serving every one of them, so any of them re-minting a
// deleted key would silently undo the fresh start the corrupt-key guidance
// tells an operator to take — and leave the next approve reporting a rotation
// that never happened.
describe('fingerprint key footprint', () => {
  const keyFile = (): string => join(dataDir(), EXCEPTION_KEY_FILENAME);

  // Seed, then take the key away exactly as the corrupt-key guidance says to,
  // so what each action does next is the only thing under test.
  async function seedThenDropKey(): Promise<string> {
    const pointer = await seedPointer();
    rmSync(keyFile());
    resetSingleton();
    return pointer;
  }

  it('revealEntry mints nothing', async () => {
    await seedThenDropKey();
    const result = await revealEntry({ pointerId: seededPointerId() });

    // Positive control on every case here: the action really ran. Without one,
    // the absence would hold just as well for an action that failed early.
    expect(result).toEqual({ ok: true, value: RAW });
    expect(existsSync(keyFile())).toBe(false);
  });

  it('grantRevealFromPointer mints nothing', async () => {
    const pointer = await seedThenDropKey();
    const granted = await grantRevealFromPointer({
      pointer,
      scope: '1h',
      justification: 'no key on this store',
    });

    expect(granted.ok).toBe(true);
    // The grant really landed, keyed to the vault row's own epoch — which the
    // row carries, so no current key was needed to write it.
    expect(inventory()[0]?.revealGrantId).not.toBeNull();
    expect(existsSync(keyFile())).toBe(false);
  });

  it('purgeVault mints nothing', async () => {
    await seedThenDropKey();
    const result = await purgeVault({ confirmation: 'purge' });

    expect(result).toEqual({ ok: true, destroyed: 1 });
    expect(entryCount()).toBe(0);
    expect(existsSync(keyFile())).toBe(false);
  });

  it('rotateVaultKey mints nothing', async () => {
    await seedThenDropKey();
    const result = await rotateVaultKey();

    // Rotating the VAULT key touches a different key entirely — the one under
    // keys/, not exception.key.
    expect(result).toMatchObject({ ok: true, reEncrypted: 1 });
    expect(existsSync(keyFile())).toBe(false);
  });
});

describe('rotateVaultKey', () => {
  it('bumps the epoch, re-encrypts, and pre-rotation pointers still resolve', async () => {
    const pointer = await seedPointer();

    const result = await rotateVaultKey();
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('unreachable');
    expect(result.version).toBeGreaterThan(1);
    expect(result.reEncrypted).toBe(1);

    // The survival property: a pointer minted under the previous epoch keeps
    // detokenizing — its tag verifies against the historical epoch it names.
    const db = openLocalDatabase(dataDir());
    try {
      const value = await buildVault(db).detokenize(pointer, {
        target: 'human',
        reason: 'explicit-reveal',
      });
      expect(value).toBe(RAW);
    } finally {
      db.close();
    }
  });
});
