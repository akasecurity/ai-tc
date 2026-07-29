import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { MatchResult } from '@akasecurity/detections';
import { applyOnboarding, openLocalDatabase } from '@akasecurity/persistence';
import { PointerToken, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { dataDir } from '../src/data-dir.ts';
import type { VaultCore, VaultGlue } from '../src/tokenize.ts';
import { createVaultGlue, POINTER_UNAVAILABLE_TEXT } from '../src/tokenize.ts';

const SECRET = 'AKIAIOSFODNN7EXAMPLE';
const OTHER = 'AKIAI44QH8DHBEXAMPLE';

function finding(overrides: Partial<MatchResult> & { span: MatchResult['span'] }): MatchResult {
  return {
    ruleId: 'aws-access-key',
    category: 'secret',
    severity: 'critical',
    rawMatch: SECRET,
    confidence: 0.9,
    ...overrides,
  };
}

describe('vault glue', () => {
  let base: string;
  let glue: VaultGlue;

  const grantConsent = (): void => {
    applyOnboarding(
      {
        vaultConsent: {
          acknowledgedAt: new Date().toISOString(),
          version: VAULT_CONSENT_VERSION,
        },
      },
      base,
    );
  };

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-glue-'));
    grantConsent();
    glue = createVaultGlue({ base });
  });

  afterEach(() => {
    // Windows will not remove a directory that still holds an open store
    // handle, so the glue must release before the temp base is cleared.
    glue.close();
    rmSync(base, { recursive: true, force: true });
  });

  describe('tokenizeText with findings', () => {
    it('replaces exactly the enforced spans and preserves everything else', async () => {
      const text = `key=${SECRET} and other=${OTHER} end`;
      const result = await glue.tokenizeText(text, {
        findings: [
          finding({ span: { start: 4, end: 4 + SECRET.length } }),
          finding({
            span: { start: 4 + SECRET.length + 11, end: 4 + SECRET.length + 11 + OTHER.length },
            rawMatch: OTHER,
          }),
        ],
      });
      expect(result.pointers).toHaveLength(2);
      for (const pointer of result.pointers) {
        expect(PointerToken.safeParse(pointer).success).toBe(true);
      }
      const [first, second] = result.pointers;
      if (first === undefined || second === undefined) throw new Error('expected two pointers');
      expect(result.text).toBe(`key=${first} and other=${second} end`);
      expect(result.text).not.toContain(SECRET);
      expect(result.text).not.toContain(OTHER);
    });

    it('round-trips through detokenizeText for a human', async () => {
      const text = `deploy with ${SECRET} now`;
      const tokenized = await glue.tokenizeText(text, {
        findings: [finding({ span: { start: 12, end: 12 + SECRET.length } })],
      });
      const back = await glue.detokenizeText(tokenized.text, {
        target: 'human',
        reason: 'explicit-reveal',
      });
      expect(back.text).toBe(text);
      expect(back.revealed).toBe(1);
    });

    it('emits the same pointer for the same value across texts', async () => {
      const a = await glue.tokenizeText(SECRET, {
        findings: [finding({ span: { start: 0, end: SECRET.length } })],
      });
      const b = await glue.tokenizeText(`x ${SECRET}`, {
        findings: [finding({ span: { start: 2, end: 2 + SECRET.length } })],
      });
      expect(a.pointers[0]).toBe(b.pointers[0]);
    });

    // Overlapping spans cannot each map to one vaulted value — the shared
    // characters belong to both findings — so the merged region is destroyed
    // one-way rather than vaulted ambiguously.
    it('degrades an overlapping span group to one-way redaction', async () => {
      const text = `${SECRET}TRAILER`;
      const result = await glue.tokenizeText(text, {
        findings: [
          finding({ span: { start: 0, end: SECRET.length } }),
          finding({
            span: { start: 10, end: SECRET.length + 7 },
            rawMatch: text.slice(10),
            category: 'pii',
            severity: 'low',
          }),
        ],
      });
      expect(result.pointers).toHaveLength(0);
      expect(result.text).toBe('[REDACTED:SECRET]');
      const db = openLocalDatabase(dataDir(base));
      expect(db.secretVault.countEntries()).toBe(0);
      db.close();
    });

    // A span that no longer slices to its finding's rawMatch is stale; vaulting
    // the sliced text would store something detection never saw.
    it('degrades a stale span one-way instead of vaulting it', async () => {
      const result = await glue.tokenizeText('short', {
        findings: [finding({ span: { start: 0, end: 5 }, rawMatch: SECRET })],
      });
      expect(result.text).toBe('[REDACTED:SECRET]');
      expect(result.pointers).toHaveLength(0);
    });

    it('returns clean text untouched', async () => {
      const result = await glue.tokenizeText('nothing sensitive here', { findings: [] });
      expect(result).toEqual({ text: 'nothing sensitive here', pointers: [], degraded: [] });
    });

    it('reports each degraded group truthfully', async () => {
      const text = `${SECRET}TRAILER`;
      const result = await glue.tokenizeText(text, {
        findings: [
          finding({ span: { start: 0, end: SECRET.length } }),
          finding({
            span: { start: 10, end: SECRET.length + 7 },
            rawMatch: text.slice(10),
            category: 'pii',
            severity: 'low',
          }),
        ],
      });
      expect(result.degraded).toEqual([{ category: 'secret' }]);
    });
  });

  describe('tokenizeText self-scan', () => {
    it('finds and tokenizes a value the bundled packs detect', async () => {
      const result = await glue.tokenizeText(`aws_access_key_id = ${SECRET}`);
      expect(result.text).not.toContain(SECRET);
      expect(result.pointers.length).toBeGreaterThan(0);
      const back = await glue.detokenizeText(result.text, {
        target: 'human',
        reason: 'explicit-reveal',
      });
      expect(back.text).toContain(SECRET);
    });
  });

  describe('consent gate', () => {
    it('degrades one-way without a grant, storing nothing', async () => {
      const bare = mkdtempSync(join(tmpdir(), 'aka-glue-nc-'));
      try {
        const ungranted = createVaultGlue({ base: bare });
        const result = await ungranted.tokenizeText(SECRET, {
          findings: [finding({ span: { start: 0, end: SECRET.length } })],
        });
        expect(result.text).toBe('[REDACTED:SECRET]');
        expect(result.pointers).toHaveLength(0);
        await expect(
          ungranted.tokenizeValue(SECRET, {
            ruleId: 'aws-access-key',
            category: 'secret',
            maskedMatch: 'A******E',
          }),
        ).resolves.toBe('[REDACTED:SECRET]');
        const db = openLocalDatabase(dataDir(bare));
        expect(db.secretVault.countEntries()).toBe(0);
        db.close();
        ungranted.close();
      } finally {
        rmSync(bare, { recursive: true, force: true });
      }
    });
  });

  // The glue opens a store handle; whoever outlives it has to be able to give
  // that handle back. Nothing in a hook needs this (the process exits), but a
  // test does — and on Windows an unreleased handle blocks removal of the very
  // temp directory the test is cleaning up, which fails the run somewhere far
  // from the cause.
  describe('close', () => {
    it('releases the store handle it opened', async () => {
      const owned = createVaultGlue({ base });
      await owned.tokenizeValue(SECRET, {
        ruleId: 'aws-access-key',
        category: 'secret',
        maskedMatch: 'A******E',
      });
      owned.close();

      // The handle is really gone: a write through the closed connection can no
      // longer reach the store, so the glue degrades one-way instead of
      // vaulting. Never raw, whatever happens to the handle.
      await expect(
        owned.tokenizeValue(OTHER, {
          ruleId: 'aws-access-key',
          category: 'secret',
          maskedMatch: 'A******E',
        }),
      ).resolves.toBe('[REDACTED:SECRET]');
    });

    it('is idempotent, and a no-op on a glue that opened nothing', () => {
      const owned = createVaultGlue({ base });
      owned.close();
      expect(() => {
        owned.close();
      }).not.toThrow();

      // A glue over an injected vault owns no handle — closing must not reach
      // for one it never took.
      const injected = createVaultGlue({
        vault: {
          tokenize: () => Promise.resolve(Symbol('unused')),
          detokenize: () => Promise.resolve(Symbol('unused')),
          describePointer: () => Promise.resolve(null),
        },
      });
      expect(() => {
        injected.close();
      }).not.toThrow();
    });
  });

  describe('fail-secure degrade', () => {
    const failingVault: VaultCore = {
      tokenize: () => Promise.reject(new Error('store locked')),
      detokenize: () => Promise.reject(new Error('store locked')),
      describePointer: () => Promise.reject(new Error('store locked')),
    };

    it('a tokenize fault destroys the value one-way', async () => {
      const faulty = createVaultGlue({ vault: failingVault });
      await expect(
        faulty.tokenizeValue(SECRET, {
          ruleId: 'r',
          category: 'secret',
          maskedMatch: 'A******E',
        }),
      ).resolves.toBe('[REDACTED:SECRET]');
      const result = await faulty.tokenizeText(`k=${SECRET}`, {
        findings: [finding({ span: { start: 2, end: 2 + SECRET.length } })],
      });
      expect(result.text).toBe('k=[REDACTED:SECRET]');
      expect(result.pointers).toHaveLength(0);
    });

    it('a detokenize fault renders the pointer unavailable, never raw', async () => {
      const token = (
        await glue.tokenizeText(SECRET, {
          findings: [finding({ span: { start: 0, end: SECRET.length } })],
        })
      ).pointers[0];
      if (token === undefined) throw new Error('expected a pointer');
      const faulty = createVaultGlue({ vault: failingVault });
      const result = await faulty.detokenizeText(`v=${token}`, {
        target: 'human',
        reason: 'explicit-reveal',
      });
      expect(result.text).toBe(`v=${POINTER_UNAVAILABLE_TEXT}`);
      expect(result.revealed).toBe(0);
    });

    it('an unopenable store degrades construction, not the session', async () => {
      const fileAsBase = join(mkdtempSync(join(tmpdir(), 'aka-glue-bad-')), 'not-a-dir');
      writeFileSync(fileAsBase, 'occupied');
      const degraded = createVaultGlue({ base: fileAsBase });
      await expect(
        degraded.tokenizeValue(SECRET, {
          ruleId: 'r',
          category: 'pii',
          maskedMatch: 'A******E',
        }),
      ).resolves.toBe('[REDACTED:PII]');
    });
  });

  describe('detokenizeText audit shape', () => {
    it('resolves a repeated pointer once, counting its occurrences', async () => {
      const token = (
        await glue.tokenizeText(SECRET, {
          findings: [finding({ span: { start: 0, end: SECRET.length } })],
        })
      ).pointers[0];
      if (token === undefined) throw new Error('expected a pointer');

      const result = await glue.detokenizeText(`a=${token} b=${token}`, {
        target: 'human',
        reason: 'view-render',
      });
      expect(result.text).toBe(`a=${SECRET} b=${SECRET}`);
      expect(result.revealed).toBe(2);

      // One audit row for the distinct pointer, carrying both occurrences.
      const db = new DatabaseSync(join(dataDir(base), 'aka.db'));
      const rows = db
        .prepare(
          `SELECT reason, pointer_count AS pointerCount
           FROM secret_vault_deref WHERE reason = 'view-render'`,
        )
        .all() as { reason: string; pointerCount: number }[];
      db.close();
      expect(rows).toEqual([{ reason: 'view-render', pointerCount: 2 }]);
    });

    it('passes pointer-free text through untouched', async () => {
      const result = await glue.detokenizeText('no pointers here', {
        target: 'human',
        reason: 'view-render',
      });
      expect(result).toEqual({ text: 'no pointers here', revealed: 0 });
    });
  });
});
