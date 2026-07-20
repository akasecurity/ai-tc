import type { FalsePositivePatternGroup, FalsePositivePatternValue } from '@akasecurity/schema';
import { resolveScopeFlags, scopeFromAnswer } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import {
  acceptFixtureExceptionOffer,
  declineFixtureExceptionOffer,
  type FixtureExceptionWriter,
} from '../../src/triage/fixture-exception.ts';

const NOW = Date.parse('2026-07-19T12:00:00.000Z');

class FakeExceptionWriter implements FixtureExceptionWriter {
  readonly calls: Parameters<FixtureExceptionWriter['create']>[0][] = [];

  create(input: Parameters<FixtureExceptionWriter['create']>[0]): Promise<unknown> {
    this.calls.push(input);
    return Promise.resolve({ id: `created-${String(this.calls.length)}` });
  }
}

const valueOf = (over: Partial<FalsePositivePatternValue>): FalsePositivePatternValue => ({
  ruleId: 'secrets/aws-access-key',
  category: 'secret',
  valueFingerprint: 'ab'.repeat(32),
  keyVersion: 1,
  ...over,
});

const groupOf = (values: FalsePositivePatternValue[]): FalsePositivePatternGroup => ({
  pattern: 'AKIA****EXAMPLE',
  count: values.length,
  values,
});

describe('acceptFixtureExceptionOffer', () => {
  let writer: FakeExceptionWriter;

  beforeEach(() => {
    writer = new FakeExceptionWriter();
  });

  it('writes one exception per distinct valueFingerprint under a shared masked token', async () => {
    const a = valueOf({ valueFingerprint: 'ab'.repeat(32) });
    const b = valueOf({ valueFingerprint: 'cd'.repeat(32) });
    const group = groupOf([a, b]);
    const scope = resolveScopeFlags({ permanent: true }, NOW);
    if (scope === null) throw new Error('expected a resolved scope');

    const result = await acceptFixtureExceptionOffer(group, scope, writer, {
      justification: 'confirmed test fixture',
      createdBy: 'me',
    });

    expect(result).toEqual({ written: 2, skippedDuplicate: 0 });
    expect(writer.calls).toHaveLength(2);
    expect(writer.calls.map((c) => c.valueFingerprint).sort()).toEqual(
      ['ab'.repeat(32), 'cd'.repeat(32)].sort(),
    );
    // Keyed on the value identity, never the shared token.
    for (const call of writer.calls) {
      expect(call.ruleId).toBe('secrets/aws-access-key');
      expect(call.keyVersion).toBe(1);
    }
  });

  it('dedupes a repeated identical identity triple to a single write', async () => {
    const a = valueOf({ valueFingerprint: 'ab'.repeat(32) });
    const duplicate = valueOf({ valueFingerprint: 'ab'.repeat(32) });
    const group = groupOf([a, duplicate]);
    const scope = resolveScopeFlags({ permanent: true }, NOW);
    if (scope === null) throw new Error('expected a resolved scope');

    const result = await acceptFixtureExceptionOffer(group, scope, writer, {
      justification: 'confirmed test fixture',
      createdBy: 'me',
    });

    expect(result).toEqual({ written: 1, skippedDuplicate: 0 });
    expect(writer.calls).toHaveLength(1);
  });

  it.each([
    ['once', resolveScopeFlags({ once: true }, NOW)],
    ['temporary', resolveScopeFlags({ for: '2h' }, NOW)],
    ['permanent', resolveScopeFlags({ permanent: true }, NOW)],
  ] as const)(
    'produces the resolved %s {scope, expiresAt, maxUses} triple',
    async (_label, scope) => {
      if (scope === null) throw new Error('expected a resolved scope');
      const group = groupOf([valueOf({})]);

      await acceptFixtureExceptionOffer(group, scope, writer, {
        justification: 'justified',
        createdBy: 'me',
      });

      expect(writer.calls).toHaveLength(1);
      const call = writer.calls[0];
      if (call === undefined) throw new Error('expected a write');
      expect({ scope: call.scope, expiresAt: call.expiresAt, maxUses: call.maxUses }).toEqual(
        scope,
      );
    },
  );

  it('carries the user-selected duration, not a fixed default, through the shared resolver', async () => {
    const group = groupOf([valueOf({})]);
    const onceScope = scopeFromAnswer('once', NOW);
    const permanentScope = scopeFromAnswer('permanent', NOW);

    await acceptFixtureExceptionOffer(group, onceScope, writer, {
      justification: 'j',
      createdBy: 'me',
    });
    await acceptFixtureExceptionOffer(group, permanentScope, writer, {
      justification: 'j',
      createdBy: 'me',
    });

    expect(writer.calls).toHaveLength(2);
    expect(writer.calls[0]?.scope).toBe('once');
    expect(writer.calls[0]?.maxUses).toBe(1);
    expect(writer.calls[1]?.scope).toBe('permanent');
    expect(writer.calls[1]?.maxUses).toBeNull();
    // The two selections are genuinely distinct triples — the picker is not a no-op.
    expect(writer.calls[0]).not.toEqual(writer.calls[1]);
  });

  it('skips a value lacking its exact identity triple and writes nothing for it', async () => {
    // Simulates a malformed/hand-assembled group bypassing FalsePositivePatternGroup's
    // schema guarantee (values.min(1), required identity fields) — the writer must
    // defend against an unkeyable mark on its own, not solely trust the producer.
    const unkeyable = {
      ruleId: 'secrets/aws-access-key',
      valueFingerprint: undefined,
      keyVersion: 1,
    } as unknown as FalsePositivePatternValue;
    const group = groupOf([unkeyable]);
    const scope = resolveScopeFlags({ permanent: true }, NOW);
    if (scope === null) throw new Error('expected a resolved scope');

    const result = await acceptFixtureExceptionOffer(group, scope, writer, {
      justification: 'justified',
      createdBy: 'me',
    });

    expect(result).toEqual({ written: 0, skippedDuplicate: 0 });
    expect(writer.calls).toHaveLength(0);
  });

  it('writes only the keyable values in a mixed keyable/unkeyable group', async () => {
    const keyed = valueOf({ valueFingerprint: 'ab'.repeat(32) });
    const unkeyable = {
      ruleId: 'secrets/aws-access-key',
      valueFingerprint: 'cd'.repeat(32),
      keyVersion: undefined,
    } as unknown as FalsePositivePatternValue;
    const group = groupOf([keyed, unkeyable]);
    const scope = resolveScopeFlags({ permanent: true }, NOW);
    if (scope === null) throw new Error('expected a resolved scope');

    const result = await acceptFixtureExceptionOffer(group, scope, writer, {
      justification: 'justified',
      createdBy: 'me',
    });

    expect(result).toEqual({ written: 1, skippedDuplicate: 0 });
    expect(writer.calls[0]?.valueFingerprint).toBe('ab'.repeat(32));
  });

  it('writes the masked pattern token, never a raw value, as maskedValue', async () => {
    const group = groupOf([valueOf({})]);
    const scope = resolveScopeFlags({ permanent: true }, NOW);
    if (scope === null) throw new Error('expected a resolved scope');

    await acceptFixtureExceptionOffer(group, scope, writer, {
      justification: 'justified',
      createdBy: 'me',
    });

    expect(writer.calls[0]?.maskedValue).toBe('AKIA****EXAMPLE');
  });

  it('stamps the shared justification, createdBy, and createdVia on every write', async () => {
    const group = groupOf([
      valueOf({ valueFingerprint: 'ab'.repeat(32) }),
      valueOf({ valueFingerprint: 'cd'.repeat(32) }),
    ]);
    const scope = resolveScopeFlags({ permanent: true }, NOW);
    if (scope === null) throw new Error('expected a resolved scope');

    await acceptFixtureExceptionOffer(group, scope, writer, {
      justification: 'confirmed test fixture',
      createdBy: 'me',
    });

    for (const call of writer.calls) {
      expect(call.justification).toBe('confirmed test fixture');
      expect(call.createdBy).toBe('me');
      expect(call.createdVia).toBe('setup-triage');
      expect(call.conditions).toBeNull();
    }
  });

  it('stamps each value its OWN category when a masked token collides across categories', async () => {
    // A masked token can collide across DetectionCategories, so a single group
    // can carry values from different ones; each written grant must carry its
    // own value's category, never a single group-level one.
    const group = groupOf([
      valueOf({ category: 'secret', valueFingerprint: 'ab'.repeat(32) }),
      valueOf({ category: 'pii', valueFingerprint: 'cd'.repeat(32) }),
    ]);
    const scope = resolveScopeFlags({ permanent: true }, NOW);
    if (scope === null) throw new Error('expected a resolved scope');

    await acceptFixtureExceptionOffer(group, scope, writer, {
      justification: 'confirmed test fixture',
      createdBy: 'me',
    });

    const byFingerprint = new Map(writer.calls.map((c) => [c.valueFingerprint, c.category]));
    expect(byFingerprint.get('ab'.repeat(32))).toBe('secret');
    expect(byFingerprint.get('cd'.repeat(32))).toBe('pii');
  });

  it('is idempotent: a value already granted collides and is skipped, never aborting the batch', async () => {
    // The real SqliteExceptionsRepository.create throws a
    // duplicate-active-exception (code-tagged) when an active grant already
    // exists for the identity triple — the same triple setup-triage's own
    // 30-day grants target, so an FP offer on an already-granted value must
    // not abort mid-loop with a partial write.
    class AlreadyGrantedWriter implements FixtureExceptionWriter {
      readonly calls: Parameters<FixtureExceptionWriter['create']>[0][] = [];
      constructor(private readonly dupeFingerprint: string) {}
      create(input: Parameters<FixtureExceptionWriter['create']>[0]): Promise<unknown> {
        this.calls.push(input);
        if (input.valueFingerprint === this.dupeFingerprint) {
          return Promise.reject(
            Object.assign(new Error('duplicate-active-exception'), {
              code: 'duplicate-active-exception',
            }),
          );
        }
        return Promise.resolve({ id: 'ok' });
      }
    }
    const already = new AlreadyGrantedWriter('ab'.repeat(32));
    const group = groupOf([
      valueOf({ valueFingerprint: 'ab'.repeat(32) }), // already granted
      valueOf({ valueFingerprint: 'cd'.repeat(32) }), // fresh
    ]);
    const scope = resolveScopeFlags({ permanent: true }, NOW);
    if (scope === null) throw new Error('expected a resolved scope');

    const result = await acceptFixtureExceptionOffer(group, scope, already, {
      justification: 'j',
      createdBy: 'me',
    });

    // Both were attempted; the duplicate is skipped, the fresh one written —
    // no partial-write abort.
    expect(already.calls).toHaveLength(2);
    expect(result).toEqual({ written: 1, skippedDuplicate: 1 });
  });

  it('rethrows a non-duplicate create() error loudly', async () => {
    class FaultyWriter implements FixtureExceptionWriter {
      create(): Promise<unknown> {
        return Promise.reject(new Error('disk is on fire'));
      }
    }
    const group = groupOf([valueOf({})]);
    const scope = resolveScopeFlags({ permanent: true }, NOW);
    if (scope === null) throw new Error('expected a resolved scope');

    await expect(
      acceptFixtureExceptionOffer(group, scope, new FaultyWriter(), {
        justification: 'j',
        createdBy: 'me',
      }),
    ).rejects.toThrow('disk is on fire');
  });
});

describe('declineFixtureExceptionOffer', () => {
  it('writes nothing — no writer is even reachable from the decline entry point', () => {
    // The decline path takes no writer at all: it is structurally incapable of
    // creating an exception, so the no-write guarantee holds by construction
    // rather than by a captured-calls assertion.
    expect(declineFixtureExceptionOffer).toHaveLength(0);
    expect(declineFixtureExceptionOffer()).toEqual({ written: 0 });
  });
});
