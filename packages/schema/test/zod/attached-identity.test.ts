import { describe, expect, it } from 'vitest';

import type { AttachedIdentity } from '../../src/zod/local.ts';
import {
  ATTACHED_IDENTITY_SPEC_VERSION,
  ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX,
  attachedIdentityHolds,
  parseAttachedIdentity,
} from '../../src/zod/local.ts';

// Who attached this machine, as digests, and when that record counts: beside
// the credential it was written for, for the endpoint it names, on a scoped
// attachment, and in no other case.
const ENDPOINT = 'https://plane.example.org';
const DIGEST = 'ab'.repeat(32);
const USER = 'cd'.repeat(32);
const TAG = '0123456789abcdef';
const ISO = '2026-10-14T09:00:00.000Z';
const ORG = '2ef4cd3c-c23c-473a-96be-1275cfc79103';

const learned = (org: string) => ({
  kind: 'account' as const,
  identity: `claude:${org}`,
  label: 'Claude work account',
  enrolledAt: ISO,
});
const orgN = (n: number): string => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000000`;

const RECORD: AttachedIdentity = {
  specVersion: 1,
  endpoint: ENDPOINT,
  credentialDigest: DIGEST,
  attachedUserDigest: USER,
  scopeTag: TAG,
  source: 'attach',
  checkedAt: ISO,
  workAccounts: [learned(ORG)],
};
const BINDING = { endpoint: ENDPOINT, credentialDigest: DIGEST, mode: 'scoped' } as const;

describe('attachedIdentityHolds', () => {
  it('holds for the endpoint, credential and scoped mode it was written for', () => {
    expect(ATTACHED_IDENTITY_SPEC_VERSION).toBe(1);
    expect(attachedIdentityHolds(RECORD, BINDING)).toBe(true);
  });

  it.each<[string, Parameters<typeof attachedIdentityHolds>[1]]>([
    ['another endpoint', { ...BINDING, endpoint: 'https://other.example.org' }],
    ['the endpoint spelled with a trailing slash', { ...BINDING, endpoint: `${ENDPOINT}/` }],
    ['another credential', { ...BINDING, credentialDigest: 'ef'.repeat(32) }],
    ['a machine-wide attachment', { ...BINDING, mode: 'machine' }],
    ['no endpoint', { ...BINDING, endpoint: undefined }],
    ['no credential', { ...BINDING, credentialDigest: undefined }],
    ['no mode', { ...BINDING, mode: undefined }],
  ])('does not hold for %s', (_label, binding) => {
    expect(attachedIdentityHolds(RECORD, binding)).toBe(false);
  });

  it.each<[string, unknown]>([
    ['nothing', undefined],
    ['a value that is not a record', 'attached'],
    ['another spec version', { ...RECORD, specVersion: 2 }],
    ['a digest that is not 64 hex digits', { ...RECORD, credentialDigest: 'ab' }],
    ['an upper-case digest', { ...RECORD, attachedUserDigest: USER.toUpperCase() }],
    ['a tag that is not 16 hex digits', { ...RECORD, scopeTag: 'xyz' }],
    ['an unknown source', { ...RECORD, source: 'guess' }],
    ['a time that is not one', { ...RECORD, checkedAt: 'yesterday' }],
    ['learned accounts that are not a list', { ...RECORD, workAccounts: 'x' }],
  ])('does not hold for a malformed record: %s', (_label, raw) => {
    expect(attachedIdentityHolds(raw, BINDING)).toBe(false);
  });

  it('never throws, even on a record whose fields throw when read', () => {
    const hostile = {
      get endpoint(): string {
        throw new Error('unreadable');
      },
    };
    expect(attachedIdentityHolds(hostile, BINDING)).toBe(false);
  });
});

describe('parseAttachedIdentity', () => {
  it('reads a record as written', () => {
    expect(parseAttachedIdentity(RECORD)).toStrictEqual(RECORD);
  });

  it('drops a learned entry this build cannot read, and keeps the rest in order', () => {
    const raw = {
      ...RECORD,
      workAccounts: [
        { kind: 'org', identity: 'acme', enrolledAt: ISO },
        learned(ORG),
        { kind: 'account', identity: 'github.com/acme/payments-api', enrolledAt: ISO },
        { kind: 'repo', identity: `claude:${orgN(1)}`, enrolledAt: ISO },
        { kind: 'account', identity: `example:${orgN(2)}`, enrolledAt: ISO },
        learned(orgN(3)),
      ],
    };
    expect(parseAttachedIdentity(raw)?.workAccounts).toEqual([learned(ORG), learned(orgN(3))]);
  });

  it(`reads at most ${String(ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX)} learned accounts`, () => {
    const many = Array.from({ length: ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX + 1 }, (_, i) =>
      learned(orgN(i + 1)),
    );
    expect(ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX).toBe(8);
    expect(parseAttachedIdentity({ ...RECORD, workAccounts: many })?.workAccounts).toEqual(
      many.slice(0, 8),
    );
  });

  it('strips an unknown key, so a field a newer build adds does not fail the record', () => {
    expect(parseAttachedIdentity({ ...RECORD, refreshedBy: 'a newer build' })).toStrictEqual(
      RECORD,
    );
  });

  it('has no field that could hold an email, an organization name or a key', () => {
    expect(Object.keys(parseAttachedIdentity(RECORD) ?? {}).sort()).toEqual([
      'attachedUserDigest',
      'checkedAt',
      'credentialDigest',
      'endpoint',
      'scopeTag',
      'source',
      'specVersion',
      'workAccounts',
    ]);
  });
});
