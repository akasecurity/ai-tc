import { createHmac } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  applyOnboarding,
  createKeyProvider,
  dataDir,
  dbPath,
  keysDir,
  loadOrCreateFingerprintKey,
  type LocalDatabase,
  openLocalDatabase,
  readWorkspaceSettings,
  SecretVault,
} from '@akasecurity/persistence';
import type { DetectionException } from '@akasecurity/schema';
import { isVaultConsentValid, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { grantRevealFromPointer } from '../../app/(app)/exceptions/actions.ts';

// `grantRevealFromPointer` mints the strictly-stronger capability: while the
// grant is active the model may receive the value's raw form at tool
// boundaries. The suite pins that a grant binds to the vault row's raw-free
// identity (rule + keyed fingerprint + key version) with the descriptor's
// masked preview, that `activeRevealGrant` — the query the tool-boundary seam
// reads — finds it, and that every rejection path writes no row. A real
// node:sqlite store and real key files — no vault mocking (house style).
//
// The action resolves the store from `homedir()` (never process.env), so the
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
const RAW = 'vaulted-value-for-reveal-grant-test';
const RULE_ID = 'secrets/test-rule';
const MASKED = 'vau…est';

let home: string;

// web-ui memoizes the open DB handle on globalThis (app/lib/db.ts). Close and
// drop it between tests so the next action reopens against the fresh home.
function resetSingleton(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-web-reveal-'));
  osHome.dir = home;
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
        ruleId: RULE_ID,
        category: 'secret',
        provider: 'aws',
        maskedMatch: MASKED,
      },
      () => loadOrCreateFingerprintKey(dataDir()),
    );
    if (typeof pointer !== 'string') throw new Error('seeding tokenize was refused');
    return pointer;
  } finally {
    db.close();
  }
}

// Every grant ever written, including terminal rows — a rejection that wrongly
// wrote a row is caught even if that row is already expired.
async function grants(): Promise<DetectionException[]> {
  const db = openLocalDatabase(dataDir());
  try {
    return await db.exceptions.list({ includeTerminal: true });
  } finally {
    db.close();
  }
}

function derefRowCount(): number {
  const raw = new DatabaseSync(dbPath(), { readOnly: true });
  try {
    const row = raw.prepare('SELECT COUNT(*) AS n FROM secret_vault_deref').get() as { n: number };
    return row.n;
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

describe('grantRevealFromPointer', () => {
  it('creates a reveal_to_model grant bound to the vault row identity', async () => {
    const pointer = await seedPointer();
    const result = await grantRevealFromPointer({
      pointer,
      scope: '1h',
      justification: 'integration test needs the live key',
    });

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('unreachable');

    const all = await grants();
    expect(all).toHaveLength(1);
    const grant = all[0];
    expect(grant?.id.slice(0, 8)).toBe(result.grantIdPrefix);
    expect(grant?.capability).toBe('reveal_to_model');
    expect(grant?.ruleId).toBe(RULE_ID);
    expect(grant?.category).toBe('secret');
    expect(grant?.maskedValue).toBe(MASKED);
    expect(grant?.scope).toBe('temporary');
    expect(grant?.expiresAt).not.toBeNull();
    expect(grant?.createdBy).toBe('dashboard');
    expect(grant?.createdVia).toBe('web-approve');

    // The identity the grant matches on is the keyed HMAC of the raw value
    // under exception.key — the very fingerprint the vault row carries.
    const key = loadOrCreateFingerprintKey(dataDir());
    const fingerprint = createHmac('sha256', key.material).update(RAW, 'utf8').digest('hex');
    expect(grant?.valueFingerprint).toBe(fingerprint);
    expect(grant?.keyVersion).toBe(key.version);

    // The query the tool-boundary reveal seam reads must find this grant.
    const db = openLocalDatabase(dataDir());
    try {
      const active = await db.exceptions.activeRevealGrant(RULE_ID, fingerprint, key.version);
      expect(active?.id).toBe(grant?.id);
    } finally {
      db.close();
    }

    // Minting a grant identifies the row without de-referencing the value —
    // no audit row claims a reveal happened here.
    expect(derefRowCount()).toBe(0);
  });

  it('rejects a duplicate active grant with a friendly message, keeping one row', async () => {
    const pointer = await seedPointer();
    const first = await grantRevealFromPointer({ pointer, scope: '1h', justification: 'a' });
    expect(first.ok).toBe(true);

    const second = await grantRevealFromPointer({ pointer, scope: '1h', justification: 'b' });
    expect(second.ok).toBe(false);
    if (second.ok) throw new Error('unreachable');
    expect(second.error).toMatch(/already exists/i);
    expect(await grants()).toHaveLength(1);
  });

  it('rejects a malformed pointer before the vault, writing no row', async () => {
    await seedPointer();
    const result = await grantRevealFromPointer({
      pointer: 'not-a-pointer',
      scope: '1h',
      justification: 'x',
    });
    expect(result.ok).toBe(false);
    expect(await grants()).toHaveLength(0);
  });

  it('rejects a shape-valid forged pointer as unresolvable, writing no row', async () => {
    const pointer = await seedPointer();
    const result = await grantRevealFromPointer({
      pointer: forge(pointer),
      scope: '1h',
      justification: 'x',
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('unreachable');
    expect(result.error).toMatch(/could not be resolved/i);
    expect(await grants()).toHaveLength(0);
  });

  it('rejects an empty justification — it is the audit trail', async () => {
    const pointer = await seedPointer();
    const result = await grantRevealFromPointer({ pointer, scope: '1h', justification: '   ' });
    expect(result.ok).toBe(false);
    expect(await grants()).toHaveLength(0);
  });

  it('rejects a temporary duration over the 24h cap, writing no row', async () => {
    const pointer = await seedPointer();
    const result = await grantRevealFromPointer({ pointer, scope: '25h', justification: 'x' });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('unreachable');
    // parseDuration's own cap message — the scope vocabulary is shared with
    // the CLI, not re-implemented here.
    expect(result.error).toMatch(/24h maximum/i);
    expect(await grants()).toHaveLength(0);
  });

  it('accepts the once scope with server-stamped columns', async () => {
    const pointer = await seedPointer();
    const once = await grantRevealFromPointer({ pointer, scope: 'once', justification: 'x' });
    expect(once.ok).toBe(true);

    const all = await grants();
    expect(all).toHaveLength(1);
    // once → the 30-minute backstop expiry plus a single-use budget.
    expect(all[0]?.scope).toBe('once');
    expect(all[0]?.maxUses).toBe(1);
    expect(all[0]?.expiresAt).not.toBeNull();
  });

  // A permanent reveal is a never-expiring authorization for raw to reach the
  // model — it takes the same value-specific typed confirmation every other
  // permanent grant does, re-checked server-side.
  it('refuses a permanent reveal without the typed confirmation', async () => {
    const pointer = await seedPointer();
    const missing = await grantRevealFromPointer({
      pointer,
      scope: 'permanent',
      justification: 'x',
    });
    expect(missing.ok).toBe(false);
    if (!missing.ok) expect(missing.error).toContain('confirmed by retyping');

    const wrong = await grantRevealFromPointer({
      pointer,
      scope: 'permanent',
      justification: 'x',
      confirmation: 'not-the-mask',
    });
    expect(wrong.ok).toBe(false);
    expect(await grants()).toHaveLength(0);
  });

  it('accepts a permanent reveal confirmed with the masked value', async () => {
    const pointer = await seedPointer();
    const granted = await grantRevealFromPointer({
      pointer,
      scope: 'permanent',
      justification: 'x',
      confirmation: MASKED,
    });
    expect(granted.ok).toBe(true);
    const all = await grants();
    expect(all[0]?.scope).toBe('permanent');
    expect(all[0]?.capability).toBe('reveal_to_model');
  });
});
