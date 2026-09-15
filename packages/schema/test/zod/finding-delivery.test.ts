import { describe, expect, it } from 'vitest';

import {
  deriveFindingDelivery,
  FindingDelivery,
  type FindingDeliveryInputs,
  SyncFailureReason,
} from '../../src/zod/index.ts';

const AT = Date.parse('2026-09-14T10:00:00.000Z');
const AT_ISO = '2026-09-14T10:00:00.000Z';

function inputs(over: Partial<FindingDeliveryInputs> = {}): FindingDeliveryInputs {
  return {
    kind: 'prompt',
    syncedAt: null,
    syncClaimedAt: null,
    syncFailedAt: null,
    syncFailure: null,
    outboxOwed: null,
    ...over,
  };
}

describe('deriveFindingDelivery', () => {
  it('reads a scanned file as a local scan, whatever its sync columns say', () => {
    expect(deriveFindingDelivery(inputs({ kind: 'code_change' }))).toEqual({ state: 'local_scan' });
    expect(
      deriveFindingDelivery(inputs({ kind: 'code_change', syncedAt: AT, outboxOwed: 1 })),
    ).toEqual({ state: 'local_scan' });
  });

  it('reads a delivery time as sent, ahead of a reason, an owed marker and a claim', () => {
    expect(
      deriveFindingDelivery(
        inputs({
          syncedAt: AT,
          syncFailure: 'deployment_refused',
          syncFailedAt: AT,
          outboxOwed: 1,
          syncClaimedAt: AT,
        }),
      ),
    ).toEqual({ state: 'sent', at: AT_ISO });
  });

  it('reads every other stamp as not sent, including zero', () => {
    expect(deriveFindingDelivery(inputs({ syncedAt: -1 }))).toEqual({ state: 'not_sent' });
    expect(deriveFindingDelivery(inputs({ syncedAt: 0 }))).toEqual({ state: 'not_sent' });
  });

  it('keeps the failure time and a known reason on a row not sent', () => {
    expect(
      deriveFindingDelivery(
        inputs({ syncedAt: -1, syncFailedAt: AT, syncFailure: 'deployment_refused' }),
      ),
    ).toEqual({ state: 'not_sent', at: AT_ISO, reason: 'deployment_refused' });
  });

  it.each(SyncFailureReason.options)('carries the %s reason through', (reason) => {
    expect(deriveFindingDelivery(inputs({ syncedAt: -1, syncFailure: reason })).reason).toBe(
      reason,
    );
  });

  it.each(['constructor', '__proto__', 'bogus'])('drops the off-enum reason %j', (reason) => {
    expect(deriveFindingDelivery(inputs({ syncedAt: -1, syncFailure: reason }))).toEqual({
      state: 'not_sent',
    });
  });

  it('reads a stamp as not sent even when the row is also marked owed', () => {
    expect(deriveFindingDelivery(inputs({ syncedAt: -1, outboxOwed: 1 })).state).toBe('not_sent');
  });

  it('reads an owed row, or one claimed by a pass sending it now, as queued', () => {
    expect(deriveFindingDelivery(inputs({ kind: 'tool_use', outboxOwed: 1 }))).toEqual({
      state: 'queued',
    });
    expect(deriveFindingDelivery(inputs({ kind: 'response', syncClaimedAt: AT }))).toEqual({
      state: 'queued',
    });
  });

  it('reads a row nothing queued as never offered', () => {
    expect(deriveFindingDelivery(inputs())).toEqual({ state: 'never_offered' });
    expect(deriveFindingDelivery(inputs({ outboxOwed: 0 }))).toEqual({ state: 'never_offered' });
  });

  it('produces a valid FindingDelivery for every combination, with `at` and `reason` only where they belong', () => {
    const kinds = ['prompt', 'response', 'tool_use', 'code_change'];
    const syncedAts = [null, AT, 0, -1];
    const claims = [null, AT];
    const failures = [null, ...SyncFailureReason.options, 'bogus'];
    const owed = [null, 0, 1];
    let checked = 0;
    for (const kind of kinds)
      for (const syncedAt of syncedAts)
        for (const syncClaimedAt of claims)
          for (const syncFailure of failures)
            for (const outboxOwed of owed) {
              const out = deriveFindingDelivery(
                inputs({
                  kind,
                  syncedAt,
                  syncClaimedAt,
                  syncFailedAt: AT,
                  syncFailure,
                  outboxOwed,
                }),
              );
              expect(FindingDelivery.safeParse(out).success).toBe(true);
              if (out.state !== 'not_sent') expect(out.reason).toBeUndefined();
              if (out.state !== 'sent' && out.state !== 'not_sent') expect(out.at).toBeUndefined();
              checked += 1;
            }
    expect(checked).toBe(4 * 4 * 2 * 5 * 3);
  });
});
