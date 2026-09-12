import { describe, expectTypeOf, it } from 'vitest';

import type {
  BaseAuditEventRow,
  BaseEventRow,
  BaseInstalledPackRow,
  BaseInventoryRow,
  BasePolicyRow,
  BaseSourceProjectRow,
} from '../../src/drizzle/base-rows.ts';

// Every time column in a base row must be spelled `TTime`, never `number`.
//
// The base interfaces are generic so each dialect can carry its own
// representation of an instant: SQLite stores epoch-millis and instantiates
// `TTime = number`, while the Postgres mirror stores `timestamptz` and
// instantiates `TTime = Date`. A time column pinned to `number` is unmirrorable
// — the mirror must either store an instant as a bare integer, alone among its
// time columns, or fail to adhere.
//
// WHY THIS IS A SEPARATE FILE FROM adherence.test.ts, AND NOT REDUNDANT WITH IT.
// That suite compares the SQLite tables against these interfaces at the DEFAULT
// instantiation, where `TTime` IS `number` — so `contentExpiredAt: number | null`
// and `contentExpiredAt: TTime | null` are the SAME TYPE to it and it passes
// either way. It is structurally incapable of seeing this class of mistake, and
// it did not: `contentExpiredAt` shipped pinned to `number`, with every OSS gate
// green, and surfaced only when a downstream consumer instantiated `TTime = Date`
// and found one column that would not move with it.
//
// So this file instantiates the OTHER dialect. Asserting `Date` where the
// default would give `number` is what makes a pinned column fail here: a
// `number`-pinned field stays `number` under `<Date>` and the assertion reds.
describe('base row time columns follow their dialect', () => {
  it('audit events: every instant moves with TTime', () => {
    expectTypeOf<BaseAuditEventRow<Date>['startedAt']>().toEqualTypeOf<Date>();
    expectTypeOf<BaseAuditEventRow<Date>['endedAt']>().toEqualTypeOf<Date | null>();
    // The one this file was written for.
    expectTypeOf<BaseAuditEventRow<Date>['contentExpiredAt']>().toEqualTypeOf<Date | null>();
  });

  it('events: every instant moves with TTime', () => {
    expectTypeOf<BaseEventRow<Date>['occurredAt']>().toEqualTypeOf<Date>();
  });

  it('policies, packs, inventory and projects: every instant moves with TTime', () => {
    expectTypeOf<BasePolicyRow<Date>['createdAt']>().toEqualTypeOf<Date>();
    expectTypeOf<BasePolicyRow<Date>['updatedAt']>().toEqualTypeOf<Date>();
    expectTypeOf<BaseInstalledPackRow<Date>['createdAt']>().toEqualTypeOf<Date>();
    expectTypeOf<BaseInstalledPackRow<Date>['updatedAt']>().toEqualTypeOf<Date>();
    expectTypeOf<BaseInventoryRow<Date>['firstSeen']>().toEqualTypeOf<Date>();
    expectTypeOf<BaseInventoryRow<Date>['lastSeen']>().toEqualTypeOf<Date>();
    expectTypeOf<BaseSourceProjectRow<Date>['firstSeen']>().toEqualTypeOf<Date>();
    expectTypeOf<BaseSourceProjectRow<Date>['lastSeen']>().toEqualTypeOf<Date>();
  });

  // The control. If `TTime` stopped being threaded at all — the interfaces made
  // non-generic, say — every assertion above would still need to fail for the
  // right reason rather than because the type argument was ignored. A field that
  // is genuinely NOT a time column must stay put under `<Date>`.
  it('a non-time column does not move with TTime', () => {
    expectTypeOf<BaseAuditEventRow<Date>['content']>().toEqualTypeOf<string | null>();
    expectTypeOf<BaseAuditEventRow<Date>['inputTokens']>().toEqualTypeOf<number | null>();
  });
});
