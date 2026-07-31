import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  createKeyProvider,
  dataDir,
  fingerprintValue,
  keysDir,
  loadOrCreateFingerprintKey,
  openLocalDatabase,
  readWorkspaceSettings,
  rotateFingerprintKey,
  SecretVault,
} from '@akasecurity/persistence';
import type { DetectionException } from '@akasecurity/schema';
import { isVaultConsentValid, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { runException } from '../../src/commands/exception.ts';
import type { Prompter } from '../../src/lib/prompter.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// `aka exception approve <pointer> --reveal` is the sanctioned door for "the
// agent legitimately needs this raw value": it mints a reveal_to_model grant
// keyed to the vault row's identity, which the plugin resolver later finds via
// activeRevealGrant. The suite runs against the REAL node:sqlite store and
// REAL key files (no vault mocking), mirroring vault.test.ts.

// Two constraints meet here. Not secret-SHAPED, because tokenize never scans
// and a credential-looking literal has no business in a public file; but still
// high-ENTROPY, because the absence check below slides an eight-character
// window over this value, and against an English-phrase fixture those windows
// are ordinary words that collide with the message's own wording instead of
// catching a leak. Random-looking and rule-shaped for nothing satisfies both.
const RAW = 'zq7vk2mx9tw4hb6njf3pd8sr5gc1ly';
const RULE_ID = 'secrets/test-rule';
// Derived so the two cannot drift apart. Seven characters, which is shorter
// than the echo window on purpose: this preview is stored and shown, so it must
// never be able to fill it.
const MASKED = `${RAW.slice(0, 3)}…${RAW.slice(-3)}`;

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
  home = mkdtempSync(join(tmpdir(), 'aka-cli-exc-reveal-'));
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
      ruleId: RULE_ID,
      category: 'secret',
      maskedMatch: MASKED,
    });
    if (typeof pointer !== 'string') throw new Error('seeding tokenize was refused');
    return pointer;
  } finally {
    db.close();
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

function approveArgs(selector: string, ...extra: string[]): string[] {
  return ['approve', selector, ...extra, '--home', home];
}

describe('aka exception approve <pointer> --reveal', () => {
  it('mints a reveal_to_model grant from the vault identity and states the consequence', async () => {
    const pointer = await seedPointer();
    const io = scriptedIo();
    await runException(
      approveArgs(pointer, '--reveal', '--for', '1h', '--reason', 'agent needs the live key'),
      io,
    );

    const rows = await openAndList();
    expect(rows).toHaveLength(1);
    const grant = rows[0];
    if (!grant) throw new Error('grant row missing');

    const dir = dataDir(home);
    const key = loadOrCreateFingerprintKey(dir);
    expect(grant.capability).toBe('reveal_to_model');
    expect(grant.ruleId).toBe(RULE_ID);
    expect(grant.valueFingerprint).toBe(fingerprintValue(key, RAW));
    expect(grant.keyVersion).toBe(key.version);
    expect(grant.maskedValue).toBe(MASKED);
    expect(grant.category).toBe('secret');
    expect(grant.scope).toBe('temporary');
    expect(grant.justification).toBe('agent needs the live key');
    expect(grant.createdVia).toBe('cli-approve');

    // The confirmation names the consequence, the audit, and the way back.
    const out = io.output();
    expect(out).toContain(`Reveal grant ${grant.id.slice(0, 6)}`);
    expect(out).toContain('RAW form');
    expect(out).toContain('audited');
    expect(out).toContain(`aka exception revoke ${grant.id.slice(0, 6)}`);
    // The raw value itself never reaches the output — not even a run of it.
    // This is the confirmation for the grant that lets the model receive the
    // value raw later, so the one surface that must not show it now is this one.
    // The four assertions above are its positive control: the capture is live
    // and full, so an absence within it means something.
    expectNoEchoOf(out, RAW);
  });

  it('rejects a pointer without --reveal and creates nothing', async () => {
    const pointer = await seedPointer();
    await expect(
      runException(approveArgs(pointer, '--once', '--reason', 'x'), scriptedIo()),
    ).rejects.toThrow(/--reveal/);
    expect(await openAndList()).toHaveLength(0);
  });

  // A non-pointer selector with the reveal opt-in routes to the ledger flow:
  // a value blocked minutes ago can be granted reveal directly from its ref,
  // no pointer in hand needed.
  it('mints a reveal grant from a blocked-detections ledger ref', async () => {
    const key = loadOrCreateFingerprintKey(dataDir(home));
    const db = openLocalDatabase(dataDir(home));
    try {
      await db.exceptions.recordBlocked({
        reference: '3f2a91',
        ruleId: 'secrets/aws-access-key',
        category: 'secret',
        valueFingerprint: fingerprintValue(key, RAW),
        keyVersion: key.version,
        maskedValue: 'A******E',
        sessionId: 'sess-1',
        repo: null,
      });
    } finally {
      db.close();
    }
    const io = scriptedIo();
    await runException(
      approveArgs('3f2a91', '--reveal-to-model', '--once', '--reason', 'ledger reveal'),
      io,
    );
    const grants = await openAndList();
    expect(grants).toHaveLength(1);
    expect(grants[0]?.capability).toBe('reveal_to_model');
    expect(io.output()).toContain('RAW form at tool boundaries');
  });

  it('the shorthand --reveal still works on a pointer selector', async () => {
    const pointer = await seedPointer();
    await runException(
      approveArgs(pointer, '--reveal', '--once', '--reason', 'shorthand'),
      scriptedIo(),
    );
    const grants = await openAndList();
    expect(grants[0]?.capability).toBe('reveal_to_model');
  });

  it('rejects a forged pointer with --reveal and creates nothing', async () => {
    const pointer = await seedPointer();
    await expect(
      runException(
        approveArgs(forge(pointer), '--reveal', '--once', '--reason', 'x'),
        scriptedIo(),
      ),
    ).rejects.toThrow(/unknown here/);
    expect(await openAndList()).toHaveLength(0);
  });

  it('rejects a duplicate active reveal grant, keeping exactly one row', async () => {
    const pointer = await seedPointer();
    await runException(
      approveArgs(pointer, '--reveal', '--for', '1h', '--reason', 'first'),
      scriptedIo(),
    );
    await expect(
      runException(
        approveArgs(pointer, '--reveal', '--for', '1h', '--reason', 'second'),
        scriptedIo(),
      ),
    ).rejects.toThrow(/active exception already exists/);
    expect(await openAndList()).toHaveLength(1);
  });

  it('is found by activeRevealGrant — the exact lookup the plugin resolver uses', async () => {
    const pointer = await seedPointer();
    await runException(
      approveArgs(pointer, '--reveal', '--for', '1h', '--reason', 'bridge contract'),
      scriptedIo(),
    );

    const dir = dataDir(home);
    const key = loadOrCreateFingerprintKey(dir);
    const db = openLocalDatabase(dir);
    try {
      const rows = await db.exceptions.list({ includeTerminal: true });
      const granted = rows[0];
      if (!granted) throw new Error('grant row missing');
      const hit = await db.exceptions.activeRevealGrant(
        RULE_ID,
        fingerprintValue(key, RAW),
        key.version,
      );
      expect(hit).toEqual({ id: granted.id });
    } finally {
      db.close();
    }
  });

  // The only friction on a never-expiring reveal is the deliberate
  // confirmation; non-interactively that means --yes or nothing.
  it('refuses --permanent non-interactively without --yes, creating nothing', async () => {
    const pointer = await seedPointer();
    await expect(
      runException(approveArgs(pointer, '--reveal', '--permanent', '--reason', 'x'), scriptedIo()),
    ).rejects.toThrow(/--yes|interactive/);
    expect(await openAndList()).toHaveLength(0);
  });

  it('accepts --permanent with --yes', async () => {
    const pointer = await seedPointer();
    await runException(
      approveArgs(pointer, '--reveal', '--permanent', '--yes', '--reason', 'x'),
      scriptedIo(),
    );
    const grants = await openAndList();
    expect(grants[0]?.scope).toBe('permanent');
    expect(grants[0]?.capability).toBe('reveal_to_model');
  });

  // The one place the pointer and ledger paths deliberately disagree, and the
  // only case in either suite that rotates the key to show it.
  //
  // A ledger row keyed to a rotated-away version is refused, because enforcement
  // there fingerprints under the CURRENT key and scopes its bundle query to that
  // version — a grant from such a row could never match. A vault row is the
  // opposite: its identity IS the row's own triple, and every crossing resolves
  // that same triple, so the row's version is the correct version even once it is
  // no longer current. Refusing on the current key here would refuse a grant that
  // does enforce, and would make reveal permanently un-approvable for any row a
  // re-key skipped.
  describe('a rotated fingerprint key does not invalidate a reveal grant', () => {
    it("mints under the vault row's key version, not the current one", async () => {
      const pointer = await seedPointer();
      const dir = dataDir(home);
      const rowKey = loadOrCreateFingerprintKey(dir);

      // Rotate the key WITHOUT the vault re-key that `aka exception rotate-key`
      // attempts afterwards — that pass is per-row best-effort and warn-only, so
      // this is the state it leaves behind for a row it could not refresh. The
      // row keeps its old fingerprint and old version together, which is exactly
      // why its grant still resolves.
      const rotated = rotateFingerprintKey(dir);
      expect(rotated.version).toBeGreaterThan(rowKey.version);

      await runException(
        approveArgs(pointer, '--reveal', '--for', '1h', '--reason', 'after rotation'),
        scriptedIo(),
      );

      const grant = (await openAndList())[0];
      if (!grant) throw new Error('grant row missing — the reveal approve was refused');
      expect(grant.capability).toBe('reveal_to_model');
      expect(grant.keyVersion).toBe(rowKey.version);
      expect(grant.keyVersion).not.toBe(rotated.version);
      expect(grant.valueFingerprint).toBe(fingerprintValue(rowKey, RAW));

      // And it is reachable by the lookup the crossing actually performs, under
      // the stale version — the assertion that makes the divergence load-bearing
      // rather than cosmetic.
      const db = openLocalDatabase(dir);
      try {
        const hit = await db.exceptions.activeRevealGrant(
          RULE_ID,
          fingerprintValue(rowKey, RAW),
          rowKey.version,
        );
        expect(hit).toEqual({ id: grant.id });
      } finally {
        db.close();
      }
    });
  });
});

// Read every exception row (including terminal) from the store.
async function openAndList(): Promise<DetectionException[]> {
  const db = openLocalDatabase(dataDir(home));
  try {
    return await db.exceptions.list({ includeTerminal: true });
  } finally {
    db.close();
  }
}
