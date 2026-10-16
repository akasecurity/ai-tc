import { randomBytes, randomUUID } from 'node:crypto';

import type { SessionAccountObservation } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { AttributionInput, TranscriptMark } from '../../src/account/attribution.ts';
import {
  attributeRecords,
  ATTRIBUTION_HOLD_MAX_AGE_MS,
  holdDecision,
  NO_ATTRIBUTION_CARRY,
} from '../../src/account/attribution.ts';
import type { LoggedObservation } from '../../src/account/observation-log.ts';
import { sessionAccountHash } from '../../src/account/observation-log.ts';
import { MINUTE, SECOND, T0 } from '../helpers/transcript-builder.ts';

const BD = randomBytes(8).toString('hex');
let end = 0;

function logged(observation: SessionAccountObservation): LoggedObservation {
  end += 100;
  return { observation, end };
}

const at = (n: number): number => T0 + n * SECOND;
const startup = (n: number): LoggedObservation => logged({ t: at(n), b: 'startup' });
const clear = (n: number): LoggedObservation => logged({ t: at(n), b: 'clear' });
const resume = (n: number): LoggedObservation => logged({ t: at(n), b: 'resume' });
const inherit = (n: number, bd = BD): LoggedObservation => logged({ t: at(n), bd, inh: true });
const work = (org: string, n: number, bd = BD): LoggedObservation =>
  logged({ t: at(n), bd, k: 'w', h: sessionAccountHash(`claude:${org}`) });
const personal = (n: number): LoggedObservation => logged({ t: at(n), bd: BD, k: 'n' });
const unreadable = (n: number): LoggedObservation => logged({ t: at(n), k: 'u' });
const orgMark = (org: string, n: number): TranscriptMark => ({
  kind: 'org',
  org,
  t: at(n),
  pos: n * 1000,
});
const record = (id: string, n: number): TranscriptMark => ({ kind: 'record', id, t: at(n) });

function run(input: Partial<AttributionInput> & Pick<AttributionInput, 'marks' | 'observations'>) {
  return attributeRecords({
    logOffset: 0,
    carry: NO_ATTRIBUTION_CARRY,
    anchorOrg: undefined,
    lastOrg: undefined,
    bindingHash: BD,
    inScope: () => true,
    ...input,
  });
}

describe('attributeRecords', () => {
  it("attributes a reply bracketed by two work views of its anchor's key", () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), work(org, 1), work(org, 3)],
    });
    expect(result.records.get('a')).toEqual({ status: 'account', key: `claude:${org}` });
  });

  it('an external switch is excluded by the two-sided check', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), work(org, 1), personal(3)],
    });
    expect(result.records.get('a')).toEqual({ status: 'none' });
  });

  it('skips an unreadable view and brackets with the nearest readable ones', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 3)],
      observations: [startup(0), work(org, 1), unreadable(2), unreadable(4), work(org, 5)],
    });
    expect(result.records.get('a')).toEqual({ status: 'account', key: `claude:${org}` });
  });

  it('takes a view at the record time as its after-view, and only a strictly earlier one as its before-view', () => {
    const org = randomUUID();
    const marks = [orgMark(org, 1), record('a', 2)];
    const tiedOnly = run({ marks, observations: [startup(0), work(org, 2), work(org, 3)] });
    expect(tiedOnly.records.get('a')).toEqual({ status: 'none' });
    const tiedAfter = run({ marks, observations: [startup(0), work(org, 1), work(org, 2)] });
    expect(tiedAfter.records.get('a')).toEqual({ status: 'account', key: `claude:${org}` });
    const personalBefore = run({
      marks,
      observations: [startup(0), personal(1), work(org, 2), work(org, 3)],
    });
    expect(personalBefore.records.get('a')).toEqual({ status: 'none' });
  });

  it('ignores a view written under another binding', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), work(org, 1), work(org, 3, randomBytes(8).toString('hex'))],
    });
    expect(result.records.get('a')).toEqual({ status: 'pending' });
  });

  it('holds a record with no view after it as pending, and a later boundary makes it none', () => {
    const org = randomUUID();
    const marks = [orgMark(org, 1), record('a', 2)];
    expect(run({ marks, observations: [startup(0), work(org, 1)] }).records.get('a')).toEqual({
      status: 'pending',
    });
    expect(
      run({ marks, observations: [startup(0), work(org, 1), clear(4), work(org, 5)] }).records.get(
        'a',
      ),
    ).toEqual({
      status: 'none',
    });
  });

  it('attributes none from an org change on, until the next boundary anchors again', () => {
    const [org, other] = [randomUUID(), randomUUID()];
    const result = run({
      marks: [
        orgMark(org, 1),
        record('a', 2),
        orgMark(other, 3),
        record('b', 4),
        orgMark(org, 6),
        record('c', 7),
      ],
      observations: [
        startup(0),
        work(org, 1),
        work(org, 2.5),
        work(org, 4.5),
        clear(5),
        work(org, 6),
        work(org, 8),
      ],
    });
    expect(result.records.get('a')).toEqual({ status: 'account', key: `claude:${org}` });
    expect(result.records.get('b')).toEqual({ status: 'none' });
    expect(result.records.get('c')).toEqual({ status: 'account', key: `claude:${org}` });
  });

  it('anchors an inherited resume on the last org before it, and an uninherited one on none', () => {
    const org = randomUUID();
    const marks = [orgMark(org, 1), record('a', 2), record('b', 6)];
    const inherited = run({
      marks,
      observations: [
        startup(0),
        work(org, 1),
        work(org, 3),
        resume(5),
        inherit(5),
        work(org, 5),
        work(org, 7),
      ],
    });
    expect(inherited.records.get('b')).toEqual({ status: 'account', key: `claude:${org}` });
    const fresh = run({
      marks,
      observations: [startup(0), work(org, 1), work(org, 3), resume(5), work(org, 5), work(org, 7)],
    });
    expect(fresh.records.get('b')).toEqual({ status: 'none' });
  });

  it('attributes a running session from the first work view after its account came into scope, and nothing recorded before', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('before', 2), record('between', 4), record('after', 6)],
      observations: [startup(0), personal(1.5), personal(3), work(org, 5), work(org, 7)],
    });
    expect(result.records.get('before')).toEqual({ status: 'none' });
    expect(result.records.get('between')).toEqual({ status: 'none' });
    expect(result.records.get('after')).toEqual({ status: 'account', key: `claude:${org}` });
  });

  it('needs the account agent key in scope now', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), work(org, 1), work(org, 3)],
      inScope: () => false,
    });
    expect(result.records.get('a')).toEqual({ status: 'none' });
  });

  it('carries the anchor across passes, re-reading only its org, and keeps no org in the carry', () => {
    const org = randomUUID();
    const first = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), work(org, 1), work(org, 3)],
    });
    expect(first.carry.anchorAt).toBe(1000);
    expect(JSON.stringify(first.carry)).not.toContain(org);
    const later = {
      marks: [record('b', 4)],
      observations: [work(org, 5)],
      carry: first.carry,
      logOffset: first.logOffset,
    };
    expect(run({ ...later, anchorOrg: org }).records.get('b')).toEqual({
      status: 'account',
      key: `claude:${org}`,
    });
    expect(run({ ...later, anchorOrg: undefined }).records.get('b')).toEqual({ status: 'none' });
  });

  it("consumes the log only up to the chunk's last record", () => {
    const org = randomUUID();
    const observations = [startup(0), work(org, 1), work(org, 2), work(org, 5)];
    const result = run({ marks: [orgMark(org, 1), record('a', 3)], observations });
    expect(result.logOffset).toBe(observations[2]?.end);
    expect(result.carry.lastObs).toEqual({
      t: at(2),
      k: 'w',
      h: sessionAccountHash(`claude:${org}`),
    });
  });

  it('changes nothing for an empty chunk', () => {
    const result = run({ marks: [], observations: [startup(0)], logOffset: 7 });
    expect(result).toEqual({ records: new Map(), carry: NO_ATTRIBUTION_CARRY, logOffset: 7 });
  });
});

describe('attributeRecords: the closing account', () => {
  const key = (org: string): string => `claude:${org}`;

  it('names the account of a work view after the last record, although the view before the record is not a work view', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 2), record('a', 3)],
      observations: [startup(0), personal(1), work(org, 4)],
    });
    expect(result.records.get('a')).toEqual({ status: 'none' });
    expect(result.closingAccount).toBe(key(org));
  });

  it('takes a view at the last record time, and none before it', () => {
    const org = randomUUID();
    const marks = [orgMark(org, 1), record('a', 2)];
    expect(run({ marks, observations: [startup(0), work(org, 2)] }).closingAccount).toBe(key(org));
    expect(run({ marks, observations: [startup(0), work(org, 1)] }).closingAccount).toBeUndefined();
  });

  it('names no account when the latest view at or after the last record is not a work view', () => {
    const org = randomUUID();
    const marks = [orgMark(org, 1), record('a', 2)];
    for (const latest of [personal(5), logged({ t: at(5), bd: BD, k: 'v' })]) {
      const result = run({ marks, observations: [startup(0), work(org, 3), latest] });
      expect(result.closingAccount).toBeUndefined();
    }
    const result = run({ marks, observations: [startup(0), personal(3), work(org, 5)] });
    expect(result.closingAccount).toBe(key(org));
  });

  it('skips an unreadable view and a view of another binding', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [
        startup(0),
        work(org, 3),
        unreadable(4),
        logged({ t: at(5), bd: randomBytes(8).toString('hex'), k: 'n' }),
      ],
    });
    expect(result.closingAccount).toBe(key(org));
  });

  it('names no account when the latest work view is for another key than the records org', () => {
    const [org, other] = [randomUUID(), randomUUID()];
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), personal(1), work(other, 3)],
    });
    expect(result.closingAccount).toBeUndefined();
  });

  it('names no account when the key is not in scope', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), personal(1), work(org, 3)],
      inScope: () => false,
    });
    expect(result.closingAccount).toBeUndefined();
  });

  it('names no account once a different org is seen after the anchor', () => {
    const [org, other] = [randomUUID(), randomUUID()];
    const result = run({
      marks: [orgMark(org, 1), record('a', 2), orgMark(other, 3), record('b', 4)],
      observations: [startup(0), personal(1), work(org, 5)],
    });
    expect(result.closingAccount).toBeUndefined();
  });

  it('names no account for a session with no recorded boundary', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [personal(1), work(org, 3)],
    });
    expect(result.closingAccount).toBeUndefined();
  });

  it('names no account for a chunk with no record', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1)],
      observations: [startup(0), work(org, 3)],
    });
    expect(result.closingAccount).toBeUndefined();
  });

  it('names no account when a boundary falls between the first and the last record', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2), orgMark(org, 4), record('b', 5)],
      observations: [startup(0), personal(1), clear(3), personal(4), work(org, 6)],
    });
    expect(result.closingAccount).toBeUndefined();
  });

  it('does not take a view past a boundary that follows the last record', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), personal(1), clear(3), work(org, 4)],
    });
    expect(result.closingAccount).toBeUndefined();
  });
});

describe('attributeRecords: the unscoped account', () => {
  const key = (org: string): string => `claude:${org}`;
  const unscoped = { inScope: () => false };

  it('names the account of a work view after the last record when its key is not in scope, with the record unattributed', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), personal(1), work(org, 3)],
      ...unscoped,
    });
    expect(result.records.get('a')).toEqual({ status: 'none' });
    expect(result.closingAccount).toBeUndefined();
    expect(result.unscopedAccount).toBe(key(org));
  });

  it('names no account once the key is in scope, where the closing account is named instead', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), personal(1), work(org, 3)],
    });
    expect(result.closingAccount).toBe(key(org));
    expect(result.unscopedAccount).toBeUndefined();
  });

  it('names no account when the latest view at or after the last record is not a work view', () => {
    const org = randomUUID();
    const marks = [orgMark(org, 1), record('a', 2)];
    for (const latest of [personal(5), logged({ t: at(5), bd: BD, k: 'v' })]) {
      const result = run({ marks, observations: [startup(0), work(org, 3), latest], ...unscoped });
      expect(result.unscopedAccount).toBeUndefined();
    }
  });

  it('names no account when no view follows the last record', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), work(org, 1)],
      ...unscoped,
    });
    expect(result.unscopedAccount).toBeUndefined();
  });

  it('names no account when the latest work view is for another key than the records org', () => {
    const [org, other] = [randomUUID(), randomUUID()];
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [startup(0), personal(1), work(other, 3)],
      ...unscoped,
    });
    expect(result.unscopedAccount).toBeUndefined();
  });

  it('names no account once a different org is seen after the anchor', () => {
    const [org, other] = [randomUUID(), randomUUID()];
    const result = run({
      marks: [orgMark(org, 1), record('a', 2), orgMark(other, 3), record('b', 4)],
      observations: [startup(0), personal(1), work(org, 5)],
      ...unscoped,
    });
    expect(result.unscopedAccount).toBeUndefined();
  });

  it('names no account for a session with no recorded boundary', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2)],
      observations: [personal(1), work(org, 3)],
      ...unscoped,
    });
    expect(result.unscopedAccount).toBeUndefined();
  });

  it('names no account for a chunk with no record', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1)],
      observations: [startup(0), work(org, 3)],
      ...unscoped,
    });
    expect(result.unscopedAccount).toBeUndefined();
  });

  it('names no account when a boundary falls between the first and the last record', () => {
    const org = randomUUID();
    const result = run({
      marks: [orgMark(org, 1), record('a', 2), orgMark(org, 4), record('b', 5)],
      observations: [startup(0), personal(1), clear(3), personal(4), work(org, 6)],
      ...unscoped,
    });
    expect(result.unscopedAccount).toBeUndefined();
  });

  it('names no account for an empty chunk', () => {
    const result = run({ marks: [], observations: [startup(0)], ...unscoped });
    expect(result.unscopedAccount).toBeUndefined();
  });
});

describe('holdDecision', () => {
  it('holds while a pending record is under fifteen minutes old, for at most three passes', () => {
    const now = T0 + MINUTE;
    expect(holdDecision({ pendingTimes: [], pending: undefined, now })).toEqual({ hold: false });
    expect(holdDecision({ pendingTimes: [T0], pending: undefined, now })).toEqual({
      hold: true,
      pending: { passes: 1, since: now },
    });
    expect(holdDecision({ pendingTimes: [T0], pending: { passes: 2, since: T0 }, now })).toEqual({
      hold: true,
      pending: { passes: 3, since: T0 },
    });
    expect(holdDecision({ pendingTimes: [T0], pending: { passes: 3, since: T0 }, now })).toEqual({
      hold: false,
    });
    const late = T0 + ATTRIBUTION_HOLD_MAX_AGE_MS;
    expect(holdDecision({ pendingTimes: [T0], pending: undefined, now: late })).toEqual({
      hold: false,
    });
  });
});
