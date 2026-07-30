import { mkdtempSync, rmSync } from 'node:fs';
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
  openLocalDatabase,
  readWorkspaceSettings,
  SecretVault,
} from '@akasecurity/persistence';
import { isVaultConsentValid, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runVault } from '../../src/commands/vault.ts';
import type { Prompter } from '../../src/lib/prompter.ts';

// `aka vault show` is the terminal reveal surface: it must print the raw value
// for a pointer this machine minted, write the explicit-reveal audit row while
// doing so, and resolve NOTHING for a forged pointer — silently, with no audit
// row, exactly as the vault core promises. The suite exercises the REAL
// node:sqlite store and REAL key files (no vault mocking), mirroring
// exception.test.ts.

// Not secret-shaped on purpose: tokenize never scans, and a plain string keeps
// secret-looking literals out of this public file.
const RAW = 'vaulted-value-for-cli-reveal-test';

// Scripted, non-interactive Prompter with captured output.
function scriptedIo(): Prompter & { output: () => string } {
  const chunks: string[] = [];
  return {
    output: () => chunks.join(''),
    out: (text) => {
      chunks.push(text);
    },
    err: (text) => {
      chunks.push(text);
    },
    isInteractive: false,
    ask: () => Promise.reject(new Error('non-interactive test io')),
    askHidden: () => Promise.reject(new Error('non-interactive test io')),
    readAllStdin: () => Promise.resolve(''),
  };
}

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-cli-vault-'));
  // Vaulting (tokenize) is consent-gated; grant it for the seeding step.
  applyOnboarding(
    {
      vaultConsent: { acknowledgedAt: new Date().toISOString(), version: VAULT_CONSENT_VERSION },
    },
    home,
  );
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

// Seed one vaulted value through the real persistence SecretVault — the same
// construction the command performs — and return its pointer.
async function seedPointer(): Promise<string> {
  const dir = dataDir(home);
  const db = openLocalDatabase(dir);
  try {
    const vault = new SecretVault({
      repo: db.secretVault,
      keys: createKeyProvider(readWorkspaceSettings(home).vaultKeyCustody, keysDir(home)),
      fingerprintKey: loadOrCreateFingerprintKey(dir),
      isConsented: () => isVaultConsentValid(readWorkspaceSettings(home).vaultConsent),
    });
    const pointer = await vault.tokenize(RAW, {
      ruleId: 'secrets/test-rule',
      category: 'secret',
      maskedMatch: 'vau…est',
    });
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
  const raw = new DatabaseSync(dbPath(home), { readOnly: true });
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

describe('aka vault show', () => {
  it('prints the raw value plus a descriptor line and audits the reveal', async () => {
    const pointer = await seedPointer();
    const io = scriptedIo();
    await runVault(['show', pointer, '--home', home], io);

    // The raw value on its own (first) line, then the one-line descriptor.
    expect(io.output().startsWith(`${RAW}\n`)).toBe(true);
    expect(io.output()).toContain('secret · seen 1×');

    expect(derefRows()).toEqual([
      { reason: 'explicit-reveal', outcome: 'revealed', target: 'human' },
    ]);
  });

  it('refuses a forged pointer with the unavailable message and writes no audit row', async () => {
    const pointer = await seedPointer();
    const io = scriptedIo();
    await expect(runVault(['show', forge(pointer), '--home', home], io)).rejects.toThrow(
      /could not be resolved/,
    );
    // The raw value never reached the output.
    expect(io.output()).not.toContain(RAW);
    // A token nobody can vouch for is unattributable: no audit row at all.
    expect(derefRows()).toEqual([]);
  });

  it('rejects a non-pointer argument before touching the vault', async () => {
    await seedPointer();
    await expect(runVault(['show', 'not-a-pointer', '--home', home], scriptedIo())).rejects.toThrow(
      /not a vault pointer/,
    );
    expect(derefRows()).toEqual([]);
  });

  it('prints usage for bare `aka vault`', async () => {
    const io = scriptedIo();
    await runVault([], io);
    expect(io.output()).toContain('aka vault show');
  });
});
