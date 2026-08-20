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
import { isVaultConsentValid, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { revealPointer } from '../../app/(app)/vault/actions.ts';
import { emptyStore } from '../helpers/store-templates.ts';

// `revealPointer` is the dashboard's reveal surface. It must return the raw
// value ONLY for a pointer this machine minted (auditing the reveal), return
// `value: null` for a shape-valid forgery WITHOUT writing a 'revealed' audit
// row, and reject malformed input before it ever reaches the vault. A real
// node:sqlite store and real key files — no vault mocking (house style).
//
// The action resolves the store from `homedir()` (never process.env), so the
// whole test is redirected into a temp home by mocking `node:os`.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

// Not secret-shaped on purpose: tokenize never scans, and a plain string keeps
// secret-looking literals out of this public file.
const RAW = 'vaulted-value-for-web-reveal-test';

let home: string;

// web-ui memoizes the open DB handle on globalThis (app/lib/db.ts). Close and
// drop it between tests so the next action reopens against the fresh home.
function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-vault-'));
  osHome.dir = home;
  // Schema by file copy rather than a migration this test would only repeat.
  emptyStore.seed(dataDir());
  // Vaulting (tokenize) is consent-gated; grant it for the seeding step.
  applyOnboarding({
    vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION },
  });
});

afterEach(() => {
  resetSingleton();
  removeTree(home);
});

// Seed one vaulted value through the real persistence SecretVault — the same
// construction the action performs — and return its pointer.
async function seedPointer(): Promise<string> {
  const db = openLocalDatabase(dataDir());
  try {
    const vault = new SecretVault({
      repo: db.secretVault,
      keys: createKeyProvider(readWorkspaceSettings().vaultKeyCustody, keysDir()),
      isConsented: () => isVaultConsentValid(readWorkspaceSettings().vaultConsent),
    });
    const pointer = await vault.tokenize(
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

// Flip one tag character so the token stays pointer-shaped but can no longer
// verify — the vault must treat it exactly like a forgery.
function forge(pointer: string): string {
  const tagStart = pointer.length - ']]'.length - 16;
  const original = pointer[tagStart];
  const flipped = original === 'A' ? 'B' : 'A';
  return pointer.slice(0, tagStart) + flipped + pointer.slice(tagStart + 1);
}

describe('revealPointer', () => {
  it('returns the raw value plus descriptor and audits the reveal', async () => {
    const pointer = await seedPointer();
    const result = await revealPointer({ pointer });

    expect(result).toMatchObject({ ok: true, value: RAW });
    if (!result.ok) throw new Error('unreachable');
    expect(result.descriptor).toMatchObject({
      category: 'secret',
      provider: 'aws',
      maskedMatch: 'vau…est',
      occurrences: 1,
    });

    expect(derefRows()).toEqual([
      { reason: 'explicit-reveal', outcome: 'revealed', target: 'human' },
    ]);
  });

  it('rejects malformed input before the vault, writing no deref row', async () => {
    await seedPointer();
    const result = await revealPointer({ pointer: 'not-a-pointer' });
    expect(result.ok).toBe(false);
    expect(derefRows()).toEqual([]);
  });

  it('resolves a shape-valid forged pointer to nothing, with no revealed row', async () => {
    const pointer = await seedPointer();
    const result = await revealPointer({ pointer: forge(pointer) });

    // Unresolvable, not an error: the caller renders the unavailable state.
    expect(result).toEqual({ ok: true, value: null, descriptor: null });
    // A token nobody can vouch for is unattributable: no audit row at all —
    // and in particular nothing claiming a reveal happened.
    expect(derefRows().filter((r) => r.outcome === 'revealed')).toEqual([]);
    expect(derefRows()).toEqual([]);
  });

  // A reveal reads. The exception fingerprint key is a different key from the
  // vault's — opening a stored value never consults it — so a reveal on a store
  // without one must resolve normally and leave the key footprint alone.
  it('mints no fingerprint key', async () => {
    const pointer = await seedPointer();
    // Seeding tokenized, which mints legitimately. Take the key away exactly as
    // the dashboard's own corrupt-key guidance tells an operator to.
    const keyFile = join(dataDir(), EXCEPTION_KEY_FILENAME);
    rmSync(keyFile);

    const result = await revealPointer({ pointer });

    // Positive control: the reveal really ran. Without it the absence below
    // would hold just as well for an action that failed before the vault.
    expect(result).toMatchObject({ ok: true, value: RAW });
    expect(existsSync(keyFile)).toBe(false);
  });
});
