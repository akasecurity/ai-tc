import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { ExceptionPolicyProvider } from '@akasecurity/persistence';
import { applyOnboarding, openLocalDatabase } from '@akasecurity/persistence';
import { VAULT_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { dataDir } from '../src/data-dir.ts';
import type { VaultGlue } from '../src/tokenize.ts';
import { createVaultGlue } from '../src/tokenize.ts';
import { removeTree } from './helpers/remove-tree.ts';

const SECRET = 'AKIAIOSFODNN7EXAMPLE';

// The reveal decision sits behind one injectable seam: swapping WHO decides
// (the user's grant, or any other policy) must flip a crossing's outcome with
// zero change at the crossing site. These tests are that contract.
describe('reveal decision seam', () => {
  let base: string;
  let token: string;

  // Every glue opens a store handle. Tracking them here means no test has to
  // remember to release one — and on Windows an unreleased handle blocks the
  // afterEach removal of the temp base, failing the run far from the cause.
  const opened: VaultGlue[] = [];
  const openGlue = (options: Parameters<typeof createVaultGlue>[0]): VaultGlue => {
    const glue = createVaultGlue(options);
    opened.push(glue);
    return glue;
  };

  beforeEach(async () => {
    base = mkdtempSync(join(tmpdir(), 'aka-seam-'));
    applyOnboarding(
      {
        vaultConsent: {
          acknowledgedAt: new Date().toISOString(),
          version: VAULT_CONSENT_VERSION,
        },
      },
      base,
    );
    const seeded = await openGlue({ base }).tokenizeText(SECRET, {
      findings: [
        {
          ruleId: 'secrets/aws-access-key',
          category: 'secret',
          severity: 'critical',
          span: { start: 0, end: SECRET.length },
          rawMatch: SECRET,
          confidence: 0.9,
        },
      ],
    });
    const first = seeded.pointers[0];
    if (first === undefined) throw new Error('expected a pointer');
    token = first;
  });

  afterEach(() => {
    for (const glue of opened.splice(0)) glue.close();
    removeTree(base);
  });

  it('the default (user-grant) provider denies with no grant on file', async () => {
    const glue = openGlue({ base });
    const result = await glue.substituteModelPointers(`k=${token}`, {
      resolveGrant: glue.revealGrantResolver,
    });
    expect(result.revealed).toEqual([]);
    expect(result.unresolved).toEqual([token]);
    expect(result.text).toBe(`k=${token}`);
  });

  it('the default provider reveals once the user grants', async () => {
    const db = openLocalDatabase(dataDir(base));
    const glue = openGlue({ base });
    // Mint the grant against the exact identity the provider matches on.
    const row = db.secretVault.listAll()[0];
    if (row === undefined) throw new Error('expected the vault row');
    await db.exceptions.create({
      ruleId: row.ruleId,
      category: 'secret',
      valueFingerprint: row.valueFingerprint,
      keyVersion: row.fingerprintKeyVersion,
      maskedValue: 'A******E',
      capability: 'reveal_to_model',
      scope: 'permanent',
      expiresAt: null,
      maxUses: null,
      justification: 'seam test',
      conditions: null,
      createdBy: 'tester',
      createdVia: 'cli-approve',
    });
    db.close();

    const result = await glue.substituteModelPointers(`k=${token}`, {
      resolveGrant: glue.revealGrantResolver,
    });
    expect(result.revealed).toEqual([token]);
    expect(result.text).toBe(`k=${SECRET}`);
  });

  it('an injected provider flips the decision with no call-site change', async () => {
    const allowAll: ExceptionPolicyProvider = {
      decideReveal: () => Promise.resolve({ allow: true, grantId: 'policy-grant' }),
    };
    const glue = openGlue({ base, policyProvider: allowAll });
    const result = await glue.substituteModelPointers(`k=${token}`, {
      resolveGrant: glue.revealGrantResolver,
    });
    expect(result.revealed).toEqual([token]);
    expect(result.text).toBe(`k=${SECRET}`);
  });

  it('a throwing provider denies, never throws', async () => {
    const broken: ExceptionPolicyProvider = {
      decideReveal: () => Promise.reject(new Error('policy service down')),
    };
    const glue = openGlue({ base, policyProvider: broken });
    const result = await glue.substituteModelPointers(`k=${token}`, {
      resolveGrant: glue.revealGrantResolver,
    });
    expect(result.revealed).toEqual([]);
    expect(result.text).toBe(`k=${token}`);
  });

  // The vault re-takes the decision from the row's own identity at the moment
  // raw would leave the store, so a resolver handing over a grant id is not the
  // last word: a decider that says no still refuses the crossing.
  it('refuses when the decider says no, whatever the resolver handed over', async () => {
    const noGrants: ExceptionPolicyProvider = {
      decideReveal: () => Promise.resolve({ allow: false }),
    };
    const glue = createVaultGlue({ base, policyProvider: noGrants });
    const result = await glue.substituteModelPointers(`k=${token}`, {
      resolveGrant: () => Promise.resolve('fabricated-grant'),
    });
    expect(result.revealed).toEqual([]);
    expect(result.text).toBe(`k=${token}`);
  });

  // The seam promises no id stability across calls, so a build whose decider
  // mints a fresh id per call must still be able to reveal. Pinning this stops
  // an id comparison from being reintroduced at the crossing, where it would
  // refuse every such build while reading like a security check.
  it('reveals for a decider that issues a different id each call', async () => {
    let issued = 0;
    const freshIdEachCall: ExceptionPolicyProvider = {
      decideReveal: () => {
        issued += 1;
        return Promise.resolve({ allow: true, grantId: `policy-grant-${String(issued)}` });
      },
    };
    const glue = createVaultGlue({ base, policyProvider: freshIdEachCall });
    const result = await glue.substituteModelPointers(`k=${token}`, {
      resolveGrant: glue.revealGrantResolver,
    });
    expect(issued).toBeGreaterThan(1);
    expect(result.revealed).toEqual([token]);
    expect(result.text).toBe(`k=${SECRET}`);
  });

  // Resolution and the crossing are two separate moments. Re-deciding at the
  // second one is what makes a revocation that lands in between bind.
  it('does not cross on a grant revoked between resolution and de-reference', async () => {
    let decisions = 0;
    const revokedAfterResolve: ExceptionPolicyProvider = {
      decideReveal: () => {
        decisions += 1;
        return Promise.resolve(
          decisions === 1 ? { allow: true, grantId: 'g-live' } : { allow: false },
        );
      },
    };
    const glue = createVaultGlue({ base, policyProvider: revokedAfterResolve });
    const result = await glue.substituteModelPointers(`k=${token}`, {
      resolveGrant: glue.revealGrantResolver,
    });
    expect(decisions).toBeGreaterThan(1);
    expect(result.revealed).toEqual([]);
    expect(result.text).toBe(`k=${token}`);
  });
});
