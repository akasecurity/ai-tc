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
