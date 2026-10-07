import { describe, expect, it } from 'vitest';

import type { PluginWhoami } from '../../src/zod/control-plane.ts';
import {
  AttachmentScope,
  isAttachmentScopeBoundTo,
  isAttachmentScopeValid,
  parseAttachmentScope,
  resolveScope,
  scopeVerdict,
  WorkspaceSettings,
} from '../../src/zod/local.ts';

// A scope record names the deployment it was enrolled for, and can also name WHO
// it was built for: the organization and account a whoami answer names. Every
// organization on a shared deployment has the same endpoint, so the endpoint
// alone cannot tell one tenant's record from another's. isAttachmentScopeBoundTo
// compares the binding with an organization and account; the binding is never
// part of the forwarding verdict.

const ENDPOINT = 'https://plane.example.test';
const ISO = '2026-10-07T09:00:00.000Z';
const TENANT = 'Acme Payments';
// whoami's `userEmail`. Nothing here reads it as an address; the binding
// compares it byte for byte, so any printable string stands in for one.
const USER = 'member-17';
const WHO: Pick<PluginWhoami, 'tenantName' | 'userEmail'> = {
  tenantName: TENANT,
  userEmail: USER,
};
const REPO = 'github.com/acme/payments-api';
const ESC = String.fromCharCode(27);

const entry = (identity: string) => ({ kind: 'repo', identity, enrolledAt: ISO });

const bound = (over: Record<string, unknown> = {}) => ({
  endpoint: ENDPOINT,
  tenantName: TENANT,
  userEmail: USER,
  entries: [entry(REPO)],
  ...over,
});

const unbound = () => ({ endpoint: ENDPOINT, entries: [entry(REPO)] });

describe('AttachmentScope — the binding', () => {
  it('keeps the organization and account a scoped attach recorded', () => {
    expect(parseAttachmentScope(bound())).toEqual(bound());
  });

  it('reads a record with no binding exactly as before, adding no binding key', () => {
    // toStrictEqual, not toEqual: a parse that spelled `tenantName: undefined`
    // would pass toEqual and still hand every reader a key the file never had.
    expect(parseAttachmentScope(unbound())).toStrictEqual(unbound());
  });

  it('holds the binding to the bounds whoami answers with', () => {
    const ok = (over: Record<string, unknown>) => AttachmentScope.safeParse(bound(over)).success;
    expect(ok({ tenantName: 'x'.repeat(200) })).toBe(true);
    expect(ok({ tenantName: 'x'.repeat(201) })).toBe(false);
    expect(ok({ userEmail: 'x'.repeat(320) })).toBe(true);
    expect(ok({ userEmail: 'x'.repeat(321) })).toBe(false);
  });

  it.each([
    ['a control character in the organization', { tenantName: `Acme${ESC}[2J` }],
    ['a control character in the account', { userEmail: `member${ESC}[2J` }],
    ['an organization that is not a string', { tenantName: 7 }],
    ['an account that is not a string', { userEmail: ['member-17'] }],
  ])('reads a record with %s as no scope at all', (_label, over) => {
    // The binding fields are held to the rule the whoami fields are (printable
    // text, bounded), so the shape refuses a control character or a value that is
    // not a string. A record that breaks it is damaged, and a damaged record
    // forwards nothing: the same answer a bad endpoint gets.
    const raw = bound(over);
    expect(parseAttachmentScope(raw)).toBeUndefined();
    expect(isAttachmentScopeValid(raw, ENDPOINT)).toBe(false);
    expect(
      scopeVerdict(resolveScope({ mode: 'scoped', scope: raw, endpoint: ENDPOINT }), REPO),
    ).toBe('local');
  });

  it('still strips an unknown envelope key, and keeps the binding beside it', () => {
    const parsed = parseAttachmentScope(bound({ builtBy: 'a newer build' }));
    expect(parsed).toEqual(bound());
    expect(parsed).not.toHaveProperty('builtBy');
  });

  it('passes through the settings schema exactly as stored', () => {
    expect(WorkspaceSettings.parse({ attachmentScope: bound() }).attachmentScope).toEqual(bound());
  });

  it('takes no part in the forwarding verdict: an unbound record forwards its entries', () => {
    // A record with no binding still counts for its endpoint, so its entries
    // forward; the binding is only what isAttachmentScopeBoundTo compares.
    const resolved = resolveScope({ mode: 'scoped', scope: unbound(), endpoint: ENDPOINT });
    expect(scopeVerdict(resolved, REPO)).toBe('forward');
    expect(isAttachmentScopeValid(unbound(), ENDPOINT)).toBe(true);
  });
});

describe('isAttachmentScopeBoundTo', () => {
  it('is true for a record built for this deployment, organization and account', () => {
    expect(isAttachmentScopeBoundTo(bound(), ENDPOINT, WHO)).toBe(true);
  });

  it('is true for a bound record with nothing enrolled yet', () => {
    // An empty entries list does not unbind a record: the binding is what is
    // compared, not the entries.
    expect(isAttachmentScopeBoundTo(bound({ entries: [] }), ENDPOINT, WHO)).toBe(true);
  });

  it('is true for a full whoami answer, reading only the two binding fields', () => {
    const whoami: PluginWhoami = {
      ...WHO,
      role: 'member',
      keyKind: 'machine',
      serverTime: ISO,
    };
    expect(isAttachmentScopeBoundTo(bound(), ENDPOINT, whoami)).toBe(true);
  });

  it('is false for a record built for another deployment', () => {
    expect(isAttachmentScopeBoundTo(bound(), 'https://other.example.test', WHO)).toBe(false);
  });

  it('compares the endpoint exactly, as the record and the credential do', () => {
    expect(isAttachmentScopeBoundTo(bound(), `${ENDPOINT}/`, WHO)).toBe(false);
  });

  it.each([
    ['another organization', { ...WHO, tenantName: 'Globex' }],
    ['another account', { ...WHO, userEmail: 'member-18' }],
    ['the organization in another case', { ...WHO, tenantName: 'acme payments' }],
    ['the account with a trailing space', { ...WHO, userEmail: `${USER} ` }],
  ])('is false when the deployment verifies %s', (_label, who) => {
    // Byte for byte: a renamed organization reads as someone else, and the
    // answer is false. That keeps less, never more.
    expect(isAttachmentScopeBoundTo(bound(), ENDPOINT, who)).toBe(false);
  });

  it.each([
    ['no binding at all', unbound()],
    ['an organization and no account', { ...unbound(), tenantName: TENANT }],
    ['an account and no organization', { ...unbound(), userEmail: USER }],
  ])('is false for a record with %s, which cannot be checked', (_label, raw) => {
    expect(isAttachmentScopeBoundTo(raw, ENDPOINT, WHO)).toBe(false);
  });

  it('is false when either field is empty, on the record or in the answer', () => {
    // An empty field binds nothing: two accounts a deployment named '' alike
    // would otherwise share one record.
    const emptyAccount = { ...WHO, userEmail: '' };
    const emptyOrg = { ...WHO, tenantName: '' };
    expect(isAttachmentScopeBoundTo(bound({ userEmail: '' }), ENDPOINT, emptyAccount)).toBe(false);
    expect(isAttachmentScopeBoundTo(bound({ tenantName: '' }), ENDPOINT, emptyOrg)).toBe(false);
  });

  it.each([
    ['no record', undefined],
    ['a string', 'not-a-scope'],
    ['an envelope whose entries is not a list', bound({ entries: 'x' })],
  ])('is false for %s', (_label, raw) => {
    expect(isAttachmentScopeBoundTo(raw, ENDPOINT, WHO)).toBe(false);
  });

  it('never throws, even on an answer whose fields throw when read', () => {
    const hostile = {
      get tenantName(): string {
        throw new Error('boom');
      },
      userEmail: USER,
    };
    expect(isAttachmentScopeBoundTo(bound(), ENDPOINT, hostile)).toBe(false);
  });
});
