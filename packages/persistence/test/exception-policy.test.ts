import type { PointerIdentity } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import type { LocalDatabase } from '../src/database.ts';
import { UserGrantPolicyProvider } from '../src/exception-policy.ts';
import type { CreateExceptionInput } from '../src/repositories/exceptions.ts';
import { useTempStore } from './helpers/temp-store.ts';

const FP = 'a'.repeat(64);
const OTHER_FP = 'b'.repeat(64);

function grantInput(overrides: Partial<CreateExceptionInput> = {}): CreateExceptionInput {
  return {
    ruleId: 'secrets/aws-access-key',
    category: 'secret',
    valueFingerprint: FP,
    keyVersion: 1,
    maskedValue: 'A******E',
    capability: 'reveal_to_model',
    scope: 'permanent',
    expiresAt: null,
    maxUses: null,
    justification: 'test grant',
    conditions: null,
    createdBy: 'tester',
    createdVia: 'cli-approve',
    ...overrides,
  };
}

function identity(overrides: Partial<PointerIdentity> = {}): PointerIdentity {
  return {
    ruleId: 'secrets/aws-access-key',
    valueFingerprint: FP,
    fingerprintKeyVersion: 1,
    ...overrides,
  };
}

describe('UserGrantPolicyProvider', () => {
  // The shared harness owns the temp store and closes its handles at teardown,
  // so no test here can leave the tree undeletable on Windows.
  const store = useTempStore('aka-policy-');
  let db: LocalDatabase;
  let provider: UserGrantPolicyProvider;

  beforeEach(() => {
    db = store.open();
    provider = new UserGrantPolicyProvider(db.exceptions);
  });

  it('allows with the grant id when an active reveal grant covers the identity', async () => {
    const grant = await db.exceptions.create(grantInput());
    await expect(provider.decideReveal(identity())).resolves.toEqual({
      allow: true,
      grantId: grant.id,
    });
  });

  // The two capabilities are distinct: today's grants must not silently widen.
  it('denies when the only grant is a suppression grant', async () => {
    await db.exceptions.create(grantInput({ capability: 'suppress' }));
    await expect(provider.decideReveal(identity())).resolves.toEqual({ allow: false });
  });

  it('denies with no grant at all', async () => {
    await expect(provider.decideReveal(identity())).resolves.toEqual({ allow: false });
  });

  // A grant authorizes exactly the value it was created for.
  it('denies a different value under the same rule', async () => {
    await db.exceptions.create(grantInput());
    await expect(provider.decideReveal(identity({ valueFingerprint: OTHER_FP }))).resolves.toEqual({
      allow: false,
    });
  });

  it('denies after revocation, on the very next decision', async () => {
    const grant = await db.exceptions.create(grantInput());
    await expect(provider.decideReveal(identity())).resolves.toMatchObject({ allow: true });
    await db.exceptions.revoke(grant.id, 'tester');
    await expect(provider.decideReveal(identity())).resolves.toEqual({ allow: false });
  });

  it('denies an expired grant at decision time', async () => {
    await db.exceptions.create(
      grantInput({ scope: 'temporary', expiresAt: new Date(Date.now() - 1000).toISOString() }),
    );
    await expect(provider.decideReveal(identity())).resolves.toEqual({ allow: false });
  });

  it('denies a use-exhausted grant', async () => {
    const grant = await db.exceptions.create(grantInput({ scope: 'once', maxUses: 1 }));
    await expect(db.exceptions.consume(grant.id)).resolves.toBe(true);
    await expect(provider.decideReveal(identity())).resolves.toEqual({ allow: false });
  });

  // Rotation is invalidation for grants: a grant written under an old
  // fingerprint-key epoch no longer matches the value's refreshed identity.
  it('denies a grant written under a rotated-away key version', async () => {
    await db.exceptions.create(grantInput({ keyVersion: 1 }));
    await expect(provider.decideReveal(identity({ fingerprintKeyVersion: 2 }))).resolves.toEqual({
      allow: false,
    });
  });

  it('a repository fault denies rather than throwing', async () => {
    // Closing under the provider is the fault: the next query hits a dead
    // handle. The harness tracks whether each handle it handed out is still
    // open, so it skips this one at teardown rather than double-closing.
    db.close();
    await expect(provider.decideReveal(identity())).resolves.toEqual({ allow: false });
  });
});
