import { randomUUID } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { MatchResult } from '@akasecurity/detections';
import {
  applyOnboarding,
  EXCEPTION_KEY_FILENAME,
  openLocalDatabase,
} from '@akasecurity/persistence';
import type { ActionTaken } from '@akasecurity/schema';
import { PointerToken, VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { dataDir } from '../src/data-dir.ts';
import type { PolicyResolver } from '../src/policy-resolver.ts';
import { createPolicyResolver } from '../src/policy-resolver.ts';
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
    removeTree(base);
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

    // The per-detection custody split. Both spans are enforced; only the one
    // whose detection chose Redact & Vault survives as a pointer. This is ONE
    // rewrite over both, which is the part that has to hold: the tokenizer
    // replaces every span it is handed, so a caller that passed only the
    // reversible subset instead would leave the other value standing in the
    // clear — a leak dressed as a narrower call.
    describe('mixed custody — reversible spans kept, the rest destroyed', () => {
      const mixed = (): { text: string; findings: MatchResult[] } => ({
        text: `key=${SECRET} and other=${OTHER} end`,
        findings: [
          finding({ span: { start: 4, end: 4 + SECRET.length } }),
          finding({
            span: { start: 4 + SECRET.length + 11, end: 4 + SECRET.length + 11 + OTHER.length },
            rawMatch: OTHER,
            ruleId: 'other-rule',
          }),
        ],
      });

      it('vaults only the reversible finding and one-ways the other', async () => {
        const { text, findings } = mixed();
        const keep = findings[0];
        if (keep === undefined) throw new Error('expected a finding');
        const result = await glue.tokenizeText(text, {
          findings,
          reversible: new Set([keep]),
        });
        expect(result.pointers).toHaveLength(1);
        // Both raw values are gone from the output — the one-way span was
        // destroyed, not skipped.
        expect(result.text).not.toContain(SECRET);
        expect(result.text).not.toContain(OTHER);
      });

      it('destroys every span when NOTHING is reversible', async () => {
        const { text, findings } = mixed();
        const result = await glue.tokenizeText(text, { findings, reversible: new Set() });
        expect(result.pointers).toEqual([]);
        expect(result.text).not.toContain(SECRET);
        expect(result.text).not.toContain(OTHER);
      });

      it('keeps every span when the option is ABSENT (the pre-archetype contract)', async () => {
        // Callers written before the per-detection archetype pass no set and
        // mean "all of them"; changing that default would silently stop
        // vaulting for them.
        const { text, findings } = mixed();
        const result = await glue.tokenizeText(text, { findings });
        expect(result.pointers).toHaveLength(2);
      });

      it('does not report a policy-directed destruction as a DEGRADED span', async () => {
        // `degraded` means the vault could not keep something it was asked to.
        // A span the policy said to destroy was never asked for, and counting it
        // would make the surface report a fault on a machine working correctly.
        const { text, findings } = mixed();
        const keep = findings[0];
        if (keep === undefined) throw new Error('expected a finding');
        const result = await glue.tokenizeText(text, {
          findings,
          reversible: new Set([keep]),
        });
        expect(result.degraded).toEqual([]);
      });
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
      expect(result).toEqual({
        text: 'nothing sensitive here',
        pointers: [],
        degraded: [],
        redacted: [],
      });
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

  // The self-scan is the entry with no findings of its own, so without a policy
  // it rewrites — and vaults — every span the rules match, whatever the pack was
  // assigned. That is the leak: a detection asked only to log a value ends up
  // with a recoverable copy of it under ~/.aka.
  describe('tokenizeText — policy-aware self-scan', () => {
    // A resolver that records what it was asked, so the tests can assert the
    // glue resolves each finding by its OWN rule and category rather than
    // deciding once for the text.
    function spyResolver(
      actionFor: (ruleId: string, category: string) => ActionTaken,
      isReversible: (ruleId: string) => boolean = () => false,
    ): PolicyResolver & { asked: { ruleId: string; category: string }[] } {
      const asked: { ruleId: string; category: string }[] = [];
      return {
        asked,
        actionFor: (ruleId, category) => {
          asked.push({ ruleId, category });
          return actionFor(ruleId, category);
        },
        isReversible,
      };
    }

    it('leaves a monitored span alone — no rewrite, no pointer, nothing vaulted', async () => {
      const text = `aws_access_key_id = ${SECRET}`;
      const resolver = spyResolver(() => 'log');
      const result = await glue.tokenizeText(text, { resolver });

      // The text is returned byte-identical: Monitor logs, it does not strip.
      expect(result.text).toBe(text);
      expect(result.pointers).toEqual([]);
      expect(result.degraded).toEqual([]);
      expect(result.redacted).toEqual([]);
      // Positive control on the same bytes: the scan really did find the value,
      // so the untouched text above is a policy decision and not an empty scan.
      expect(resolver.asked.length).toBeGreaterThan(0);
      expect(resolver.asked[0]?.category).toBe('secret');
      const unfiltered = await glue.tokenizeText(text);
      expect(unfiltered.text).not.toContain(SECRET);
      expect(unfiltered.pointers.length).toBeGreaterThan(0);
    });

    it('destroys a redact-action span one-way and reports it as `redacted`, not `degraded`', async () => {
      const text = `aws_access_key_id = ${SECRET}`;
      const result = await glue.tokenizeText(text, {
        resolver: spyResolver(
          () => 'redact',
          () => false,
        ),
      });

      expect(result.text).not.toContain(SECRET);
      // Positive control on the same bytes: the surrounding text survived, so
      // the absence above is this span being destroyed and not a blanket.
      expect(result.text).toContain('aws_access_key_id = ');
      expect(result.pointers).toEqual([]);
      // Nothing was downgraded — the policy said destroy, and it was destroyed.
      expect(result.degraded).toEqual([]);
      expect(result.redacted).toEqual([{ category: 'secret' }]);
    });

    it('vaults a redact-action span only when the resolver also calls it reversible', async () => {
      const text = `aws_access_key_id = ${SECRET}`;
      const result = await glue.tokenizeText(text, {
        resolver: spyResolver(
          () => 'redact',
          () => true,
        ),
      });

      expect(result.text).not.toContain(SECRET);
      expect(result.text).toContain('aws_access_key_id = ');
      expect(result.pointers).toHaveLength(1);
      expect(result.redacted).toEqual([]);
      expect(result.degraded).toEqual([]);
      // Recoverable, which is the whole difference Redact & Vault buys.
      const back = await glue.detokenizeText(result.text, {
        target: 'human',
        reason: 'explicit-reveal',
      });
      expect(back.text).toContain(SECRET);
    });

    it('a block-action span is stripped too — block outranks redact', async () => {
      const text = `aws_access_key_id = ${SECRET}`;
      const result = await glue.tokenizeText(text, { resolver: spyResolver(() => 'block') });
      expect(result.text).not.toContain(SECRET);
      expect(result.text).toContain('aws_access_key_id = ');
      expect(result.redacted).toEqual([{ category: 'secret' }]);
    });

    it('resolves through a real bundle: a category policy governs the self-scan', async () => {
      const text = `aws_access_key_id = ${SECRET}`;
      const monitored = createPolicyResolver({
        version: 'test',
        policies: [
          {
            id: randomUUID(),
            scope: 'global',
            target: { category: 'secret' },
            action: 'log',
            enabled: true,
          },
        ],
        customKeywords: [],
        fetchedAt: new Date().toISOString(),
      });
      expect((await glue.tokenizeText(text, { resolver: monitored })).text).toBe(text);
    });

    it("never widens a caller's own findings — those arrive already resolved", async () => {
      const text = `key=${SECRET} end`;
      const supplied = [finding({ span: { start: 4, end: 4 + SECRET.length } })];
      // The resolver would have filtered this span out had it been a self-scan.
      const result = await glue.tokenizeText(text, {
        findings: supplied,
        resolver: spyResolver(
          () => 'log',
          () => true,
        ),
      });
      // Honoured as given: the span is rewritten, and the resolver supplied the
      // reversibility the caller did not pass.
      expect(result.text).not.toContain(SECRET);
      expect(result.text).toContain('key=');
      expect(result.pointers).toHaveLength(1);
    });

    it('an explicit `reversible` set wins over the resolver for supplied findings', async () => {
      const text = `key=${SECRET} end`;
      const supplied = [finding({ span: { start: 4, end: 4 + SECRET.length } })];
      const result = await glue.tokenizeText(text, {
        findings: supplied,
        reversible: new Set(),
        resolver: spyResolver(
          () => 'redact',
          () => true,
        ),
      });
      expect(result.text).not.toContain(SECRET);
      expect(result.text).toContain('key=');
      expect(result.pointers).toEqual([]);
      expect(result.redacted).toEqual([{ category: 'secret' }]);
    });

    // Same rule where the caller has no findings of its own: the resolver only
    // ever FILLS IN `reversible`, so a set the caller did pass still stands.
    // The self-scan mints its own MatchResult objects, which this set cannot
    // hold — so it reads as "keep nothing", every enforced span is destroyed
    // instead of vaulted, and the caller's statement errs toward not retaining
    // a value rather than being dropped for one derived behind its back.
    it('an explicit `reversible` set wins over the resolver for a self-scan too', async () => {
      const text = `aws_access_key_id = ${SECRET}`;
      const result = await glue.tokenizeText(text, {
        reversible: new Set(),
        resolver: spyResolver(
          () => 'redact',
          () => true,
        ),
      });
      expect(result.text).not.toContain(SECRET);
      // Positive control: the surrounding bytes survived, so the absence above
      // is this span being destroyed and not the blanket a failure emits.
      expect(result.text).toContain('aws_access_key_id = ');
      expect(result.pointers).toEqual([]);
      expect(result.redacted).toEqual([{ category: 'secret' }]);
    });

    it('with no resolver, a self-scan keeps its historical vault-everything behaviour', async () => {
      const text = `aws_access_key_id = ${SECRET}`;
      const result = await glue.tokenizeText(text);
      expect(result.text).not.toContain(SECRET);
      expect(result.text).toContain('aws_access_key_id = ');
      expect(result.pointers.length).toBeGreaterThan(0);
      expect(result.redacted).toEqual([]);
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
        removeTree(bare);
      }
    });
  });

  // The exception fingerprint key is a WRITE dependency: it keys the ledger a
  // vaulted value can later be approved from, and nothing the glue does on the
  // read side consults it. This glue is built once per process and serves both
  // sides, so a session that only renders or reveals must leave the key
  // footprint it found — otherwise a store whose key was deleted (which the
  // CLI's own corrupt-key guidance tells operators to do) silently gets a
  // fresh one back, and the next approve reports a rotation that never
  // happened instead of the missing key.
  describe('fingerprint key footprint', () => {
    const keyFile = (b: string): string => join(dataDir(b), EXCEPTION_KEY_FILENAME);

    it('mints on a write', async () => {
      const fresh = createVaultGlue({ base });
      try {
        const token = await fresh.tokenizeValue(SECRET, {
          ruleId: 'aws-access-key',
          category: 'secret',
          maskedMatch: 'A******E',
        });
        // Positive control: the write really stored something. A degraded
        // tokenize returns the one-way placeholder and would mint nothing.
        expect(PointerToken.safeParse(token).success).toBe(true);
        expect(existsSync(keyFile(base))).toBe(true);
      } finally {
        fresh.close();
      }
    });

    it('mints nothing on the read side', async () => {
      // Seed through the shared glue so there is a real pointer to read back,
      // then take the key away — the reads below must not put one back.
      const token = await glue.tokenizeValue(SECRET, {
        ruleId: 'aws-access-key',
        category: 'secret',
        maskedMatch: 'A******E',
      });
      rmSync(keyFile(base));

      const reader = createVaultGlue({ base });
      try {
        const back = await reader.detokenizeText(`v=${token}`, {
          target: 'human',
          reason: 'explicit-reveal',
        });
        // Positive control: the read side really worked without the key, so
        // the absence below is about minting rather than about a broken glue.
        expect(back.text).toBe(`v=${SECRET}`);
        expect(existsSync(keyFile(base))).toBe(false);
      } finally {
        reader.close();
      }
    });

    // A refused write is not a write. A user who never granted vault consent
    // keeps a zero key footprint, exactly as one who never trips enforcement
    // does.
    it('mints nothing on a write refused for want of consent', async () => {
      const bare = mkdtempSync(join(tmpdir(), 'aka-glue-nokey-'));
      try {
        const ungranted = createVaultGlue({ base: bare });
        try {
          // Positive control: this is the refusal path, not a passthrough.
          await expect(
            ungranted.tokenizeValue(SECRET, {
              ruleId: 'aws-access-key',
              category: 'secret',
              maskedMatch: 'A******E',
            }),
          ).resolves.toBe('[REDACTED:SECRET]');
          expect(existsSync(keyFile(bare))).toBe(false);
        } finally {
          ungranted.close();
        }
      } finally {
        removeTree(bare);
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
          resolvePointerIdentity: () => Promise.resolve(null),
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
      resolvePointerIdentity: () => Promise.reject(new Error('store locked')),
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
      const badBase = mkdtempSync(join(tmpdir(), 'aka-glue-bad-'));
      try {
        const fileAsBase = join(badBase, 'not-a-dir');
        writeFileSync(fileAsBase, 'occupied');
        const degraded = createVaultGlue({ base: fileAsBase });
        await expect(
          degraded.tokenizeValue(SECRET, {
            ruleId: 'r',
            category: 'pii',
            maskedMatch: 'A******E',
          }),
        ).resolves.toBe('[REDACTED:PII]');
        // Opened nothing, so this releases nothing — pinning that close() is
        // safe on a degraded glue, which is the branch a caller cannot detect.
        degraded.close();
      } finally {
        removeTree(badBase);
      }
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

describe('sighting recording', () => {
  let base: string;
  let glue: VaultGlue;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-glue-sight-'));
    applyOnboarding(
      {
        vaultConsent: {
          acknowledgedAt: new Date().toISOString(),
          version: VAULT_CONSENT_VERSION,
        },
      },
      base,
    );
    glue = createVaultGlue({ base });
  });

  afterEach(() => {
    // Before the rm, as every other suite here does: this glue opened a store
    // handle, and Windows refuses to remove a directory one is still held in.
    glue.close();
    removeTree(base);
  });

  it('records where a minted pointer landed, one row per location', async () => {
    const text = `key=${SECRET}`;
    const opts = {
      findings: [finding({ span: { start: 4, end: 4 + SECRET.length } })],
      sighting: { location: '/repo/.env', kind: 'file' as const },
    };
    await glue.tokenizeText(text, opts);
    // Re-sighting the same location bumps timestamps instead of duplicating.
    await glue.tokenizeText(text, opts);
    await glue.tokenizeText(text, {
      ...opts,
      sighting: { location: 'Write input', kind: 'tool-input' as const },
    });

    const db = new DatabaseSync(join(dataDir(base), 'aka.db'));
    const rows = db
      .prepare(`SELECT location, kind FROM secret_vault_sighting ORDER BY location`)
      .all() as { location: string; kind: string }[];
    db.close();
    expect(rows).toEqual([
      { location: '/repo/.env', kind: 'file' },
      { location: 'Write input', kind: 'tool-input' },
    ]);
  });

  it('a clean text records nothing', async () => {
    await glue.tokenizeText('nothing here', {
      findings: [],
      sighting: { location: '/x', kind: 'file' },
    });
    const db = new DatabaseSync(join(dataDir(base), 'aka.db'));
    const count = db.prepare('SELECT count(*) AS n FROM secret_vault_sighting').get() as {
      n: number;
    };
    db.close();
    expect(count.n).toBe(0);
  });
});
