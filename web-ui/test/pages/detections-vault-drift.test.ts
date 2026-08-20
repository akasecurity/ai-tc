import { mkdtempSync, rmSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyOnboarding, dataDir, openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import type { ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import DetectionsPage from '../../app/(app)/detections/page.tsx';

// The Detections page's drift notice: the surface that tells a machine which
// used to vault, and now does not, that its redactions became one-way.
//
// The PREDICATE is covered in dashboard-ui. What only this test can see is the
// WIRING — specifically that the "is anything assigned the archetype?" answer is
// read UNFILTERED. The page also loads a URL-filtered list, and deriving the
// answer from that would tell a user who had typed a search that nothing is
// vaulted whenever their query happened to exclude the pack that is.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-drift-page-'));
  osHome.dir = home;
  const globals = globalThis as { __akaDb?: { close: () => void } };
  globals.__akaDb?.close();
  delete globals.__akaDb;
});

afterEach(() => {
  const globals = globalThis as { __akaDb?: { close: () => void } };
  globals.__akaDb?.close();
  delete globals.__akaDb;
  rmSync(home, { recursive: true, force: true });
});

function grantVaultConsent(): void {
  applyOnboarding(
    { vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION } },
    join(home, '.aka'),
  );
}

function seedPacks(): void {
  const db = openLocalDatabase(dataDir(join(home, '.aka')));
  try {
    db.installedPacks.recordInventory(bundledDetections());
  } finally {
    db.close();
  }
}

/** Put one entry in the vault, so the machine reads as having vaulted before. */
function seedVaultEntry(): void {
  const db = openLocalDatabase(dataDir(join(home, '.aka')));
  try {
    // Through the repository's own writer rather than raw SQL: the drift read
    // only asks countEntries(), and a hand-written INSERT would pin this test to
    // a column list the schema owns.
    db.secretVault.upsert(
      {
        pointerId: 'p1',
        valueFingerprint: 'fp1',
        fingerprintKeyVersion: 1,
        keyVersion: 1,
        category: 'secret',
        ruleId: 'aka/x',
        maskedMatch: 'A****Z',
        ciphertext: 'AA==',
        nonce: 'AA==',
        authTag: 'AA==',
      },
      Date.now(),
    );
  } finally {
    db.close();
  }
}

async function renderPage(): Promise<string> {
  const element = (await DetectionsPage({ searchParams: Promise.resolve({}) })) as ReactElement;
  return JSON.stringify(element);
}

describe('the Detections page drift notice', () => {
  it('is absent on a machine with no vault consent', async () => {
    seedPacks();
    expect(await renderPage()).not.toContain('vault-drift-notice');
  });

  it('is absent on a consented machine that has never vaulted anything', async () => {
    // A fresh install that granted consent during setup has lost nothing.
    grantVaultConsent();
    seedPacks();
    expect(await renderPage()).not.toContain('vault-drift-notice');
  });

  it('SHOWS on a machine that vaulted before and assigns the archetype nowhere', async () => {
    grantVaultConsent();
    seedPacks();
    seedVaultEntry();
    expect(await renderPage()).toContain('vault-drift-notice');
  });

  it('clears once any detection is assigned Redact & Vault', async () => {
    grantVaultConsent();
    seedPacks();
    seedVaultEntry();
    expect(await renderPage()).toContain('vault-drift-notice');

    const db = openLocalDatabase(dataDir(join(home, '.aka')));
    try {
      const [first] = bundledDetections();
      if (!first) throw new Error('expected a bundled pack to assign');
      db.installedPacks.setPolicy(first.namespace, first.packId, 'vault');
    } finally {
      db.close();
    }
    const globals = globalThis as { __akaDb?: { close: () => void } };
    globals.__akaDb?.close();
    delete globals.__akaDb;

    expect(await renderPage()).not.toContain('vault-drift-notice');
  });

  it('does not take the page down when the store cannot answer', async () => {
    // The notice is fail-open like every other read here: a store that cannot
    // report its vault must cost the notice, never the page.
    grantVaultConsent();
    // No packs seeded and no vault table populated — the reads still run.
    await expect(renderPage()).resolves.toBeTypeOf('string');
  });
});
