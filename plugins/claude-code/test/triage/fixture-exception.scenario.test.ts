/**
 * The real-store exceptions-write leg: the
 * pre-filled fixture/exception writer (`acceptFixtureExceptionOffer`,
 * src/triage/fixture-exception.ts) bound to a REAL local store's REAL
 * exceptions repository (`db.exceptions`, via `openLocalDatabase`), read back
 * the way `/aka:exceptions` does (`db.exceptions.list()`) — mirroring the
 * leave-remediation integration seam (test/remediation/leave.scenario.test.ts).
 *
 * The unit seam already proves the writer's behaviour against a fake
 * (fixture-exception.test.ts). This file re-proves the legs that actually
 * touch the store over the real repository, where the store read-back — not a
 * fake's recorded calls — is the assertion: identity-keyed accept, the
 * three-scope duration picker (each triple compared exactly against its
 * resolved scope), the masked-token collision, the real repo's
 * `DuplicateActiveExceptionError` driving the writer's skippedDuplicate
 * branch, and the incomplete-identity fail-open. Decline
 * (`declineFixtureExceptionOffer`) takes no writer and is a pure no-op with no
 * real-store behaviour to exercise, so it stays at the fake unit seam
 * (fixture-exception.test.ts); the whole-signal-absent fail-open has no
 * store-touching path and is proven end-to-end at the emission seam
 * (fixture-exception.journey.test.ts).
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { LocalDatabase } from '@akasecurity/persistence';
import { openLocalDatabase } from '@akasecurity/persistence';
import type { FalsePositivePatternGroup, FalsePositivePatternValue } from '@akasecurity/schema';
import { resolveScopeFlags, scopeFromAnswer } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { acceptFixtureExceptionOffer } from '../../src/triage/fixture-exception.ts';

const OPTS = { justification: 'confirmed test fixture', createdBy: 'me' };

// Real wall-clock time, not a fixed instant: db.exceptions.list() filters on
// the REAL active predicate (expires_at > Date.now()) at read time, so a
// once/temporary expiresAt must be computed against the same clock the
// store's read-back uses.
const now = (): number => Date.now();

const valueOf = (over: Partial<FalsePositivePatternValue>): FalsePositivePatternValue => ({
  ruleId: 'secrets/aws-access-key',
  category: 'secret',
  valueFingerprint: 'ab'.repeat(32),
  keyVersion: 1,
  ...over,
});

const groupOf = (
  pattern: string,
  values: FalsePositivePatternValue[],
): FalsePositivePatternGroup => ({ pattern, count: values.length, values });

describe('the mechanical write legs over a REAL local store', () => {
  let base: string;
  let db: LocalDatabase;

  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-fixture-exception-store-'));
    db = openLocalDatabase(join(base, 'data'));
  });

  afterEach(() => {
    db.close();
    rmSync(base, { recursive: true, force: true });
  });

  it("accepting writes an exception keyed on the marked hit's exact value identity, masked on read-back", async () => {
    const value = valueOf({ valueFingerprint: 'ab'.repeat(32) });
    const group = groupOf('test_sk_live_placeholder', [value]);
    const scope = resolveScopeFlags({ permanent: true }, now());
    if (scope === null) throw new Error('expected a resolved scope');

    const result = await acceptFixtureExceptionOffer(group, scope, db.exceptions, OPTS);
    expect(result).toEqual({ written: 1, skippedDuplicate: 0 });

    // Read back the way /aka:exceptions does.
    const stored = await db.exceptions.list();
    expect(stored).toHaveLength(1);
    const [exception] = stored;
    if (exception === undefined) throw new Error('expected a stored exception');

    // Keyed on the marked hit's exact value identity...
    expect(exception.ruleId).toBe(value.ruleId);
    expect(exception.valueFingerprint).toBe(value.valueFingerprint);
    expect(exception.keyVersion).toBe(value.keyVersion);
    // ...masked on read-back...
    expect(exception.maskedValue).toBe(group.pattern);
    // ...never keyed on the shared masked token itself (the collision test
    // below is the definitive proof: two distinct valueFingerprints under one
    // shared token write two distinct rows, not one collapsed on the token).
    expect(exception.valueFingerprint).not.toBe(group.pattern);
  });

  describe('duration picker: each scope selection, in its own run, reads back its resolved triple', () => {
    it('temporary reads back scope "temporary", the resolved expiresAt exactly, and maxUses null', async () => {
      const group = groupOf('test_sk_live_placeholder', [valueOf({})]);
      const scope = scopeFromAnswer('2h', now());

      await acceptFixtureExceptionOffer(group, scope, db.exceptions, OPTS);

      const [exception] = await db.exceptions.list();
      if (exception === undefined) throw new Error('expected a stored exception');
      expect(exception.scope).toBe('temporary');
      // Exact, not merely non-null: the stored expiry is the one the resolver
      // computed, round-tripped through the store unchanged.
      expect(exception.expiresAt).toBe(scope.expiresAt);
      expect(exception.maxUses).toBeNull();
    });

    it('once reads back scope "once", the resolved 30-minute backstop expiresAt exactly, and maxUses 1', async () => {
      const group = groupOf('test_sk_live_placeholder', [valueOf({})]);
      const scope = scopeFromAnswer('once', now());

      await acceptFixtureExceptionOffer(group, scope, db.exceptions, OPTS);

      const [exception] = await db.exceptions.list();
      if (exception === undefined) throw new Error('expected a stored exception');
      expect(exception.scope).toBe('once');
      expect(exception.expiresAt).toBe(scope.expiresAt);
      expect(exception.maxUses).toBe(1);
    });

    it('permanent reads back scope "permanent" with both expiresAt and maxUses null', async () => {
      const group = groupOf('test_sk_live_placeholder', [valueOf({})]);
      const scope = scopeFromAnswer('permanent', now());

      await acceptFixtureExceptionOffer(group, scope, db.exceptions, OPTS);

      const [exception] = await db.exceptions.list();
      if (exception === undefined) throw new Error('expected a stored exception');
      expect(exception.scope).toBe('permanent');
      expect(exception.expiresAt).toBeNull();
      expect(exception.maxUses).toBeNull();
    });
  });

  it('the three duration selections read back as their three distinct resolved triples — the picker is not a no-op', async () => {
    const once = valueOf({ valueFingerprint: 'aa'.repeat(32) });
    const temporary = valueOf({ valueFingerprint: 'bb'.repeat(32) });
    const permanent = valueOf({ valueFingerprint: 'cc'.repeat(32) });
    const onceScope = scopeFromAnswer('once', now());
    const temporaryScope = scopeFromAnswer('2h', now());
    const permanentScope = scopeFromAnswer('permanent', now());

    await acceptFixtureExceptionOffer(
      groupOf('test_sk_live_placeholder', [once]),
      onceScope,
      db.exceptions,
      OPTS,
    );
    await acceptFixtureExceptionOffer(
      groupOf('test_sk_live_placeholder', [temporary]),
      temporaryScope,
      db.exceptions,
      OPTS,
    );
    await acceptFixtureExceptionOffer(
      groupOf('test_sk_live_placeholder', [permanent]),
      permanentScope,
      db.exceptions,
      OPTS,
    );

    const stored = await db.exceptions.list();
    expect(stored).toHaveLength(3);
    const triples = new Map(
      stored.map((e) => [
        e.valueFingerprint,
        { scope: e.scope, expiresAt: e.expiresAt, maxUses: e.maxUses },
      ]),
    );
    const onceTriple = triples.get(once.valueFingerprint);
    const temporaryTriple = triples.get(temporary.valueFingerprint);
    const permanentTriple = triples.get(permanent.valueFingerprint);

    // Each row reads back as EXACTLY its resolved triple...
    expect(onceTriple).toEqual({
      scope: onceScope.scope,
      expiresAt: onceScope.expiresAt,
      maxUses: onceScope.maxUses,
    });
    expect(temporaryTriple).toEqual({
      scope: temporaryScope.scope,
      expiresAt: temporaryScope.expiresAt,
      maxUses: temporaryScope.maxUses,
    });
    expect(permanentTriple).toEqual({
      scope: permanentScope.scope,
      expiresAt: permanentScope.expiresAt,
      maxUses: permanentScope.maxUses,
    });
    // ...and the three are distinct on scope/maxUses (NOT expiresAt nullness,
    // which cannot separate once from temporary — both non-null).
    expect(new Set([onceTriple?.scope, temporaryTriple?.scope, permanentTriple?.scope]).size).toBe(
      3,
    );
  });

  it('a masked-token collision across two distinct valueFingerprints writes one exception per distinct value, never one collapsed grant', async () => {
    const a = valueOf({ valueFingerprint: 'ab'.repeat(32) });
    const b = valueOf({ valueFingerprint: 'cd'.repeat(32) });
    const group = groupOf('AKIA****EXAMPLE', [a, b]);
    const scope = resolveScopeFlags({ permanent: true }, now());
    if (scope === null) throw new Error('expected a resolved scope');

    const result = await acceptFixtureExceptionOffer(group, scope, db.exceptions, OPTS);
    expect(result).toEqual({ written: 2, skippedDuplicate: 0 });

    const stored = await db.exceptions.list();
    expect(stored).toHaveLength(2);
    expect(stored.map((e) => e.valueFingerprint).sort()).toEqual(
      [a.valueFingerprint, b.valueFingerprint].sort(),
    );
    for (const exception of stored) {
      expect(exception.maskedValue).toBe(group.pattern);
    }
  });

  it("re-accepting the SAME identity trips the real repo's DuplicateActiveExceptionError and reads back as skippedDuplicate, one row", async () => {
    // The one assertion a real-store leg adds over the fake seam: the writer's
    // idempotency branch duck-types on `code === 'duplicate-active-exception'`,
    // which only the REAL SqliteExceptionsRepository throws (on its
    // active-unique index). A fake can only simulate that; here the second
    // accept of the same (ruleId, valueFingerprint, keyVersion) drives the
    // real error into the catch.
    const value = valueOf({ valueFingerprint: 'ef'.repeat(32) });
    const group = groupOf('test_sk_live_placeholder', [value]);
    const scope = resolveScopeFlags({ permanent: true }, now());
    if (scope === null) throw new Error('expected a resolved scope');

    const first = await acceptFixtureExceptionOffer(group, scope, db.exceptions, OPTS);
    expect(first).toEqual({ written: 1, skippedDuplicate: 0 });

    const second = await acceptFixtureExceptionOffer(group, scope, db.exceptions, OPTS);
    expect(second).toEqual({ written: 0, skippedDuplicate: 1 });

    // The re-accept is a no-op: still exactly one active grant for the identity.
    const stored = await db.exceptions.list();
    expect(stored).toHaveLength(1);
    const [exception] = stored;
    expect(exception?.valueFingerprint).toBe(value.valueFingerprint);
  });

  it('a marked hit missing its exact value identity is not offered and writes no exception', async () => {
    // Simulates a mark whose identity is unavailable — the incomplete-identity
    // branch, distinct from the whole-signal-absent leg below: the FP mark
    // exists but cannot be keyed to a concrete value.
    const unkeyable = {
      ruleId: 'secrets/aws-access-key',
      category: 'secret',
      valueFingerprint: undefined,
      keyVersion: 1,
    } as unknown as FalsePositivePatternValue;
    const group = groupOf('test_sk_live_placeholder', [unkeyable]);
    const scope = resolveScopeFlags({ permanent: true }, now());
    if (scope === null) throw new Error('expected a resolved scope');

    const result = await acceptFixtureExceptionOffer(group, scope, db.exceptions, OPTS);
    expect(result).toEqual({ written: 0, skippedDuplicate: 0 });

    const stored = await db.exceptions.list();
    expect(stored).toHaveLength(0);
  });
});
