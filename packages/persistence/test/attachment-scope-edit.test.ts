import type { AttachmentScopeEntry, PluginWhoami } from '@akasecurity/schema';
import {
  isAttachmentScopeBoundTo,
  isAttachmentScopeValid,
  parseAttachmentScope,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  addAttachmentScopeEntries,
  freshAttachmentScope,
  markCodingAgentEntries,
  removeAttachmentScopeEntries,
  turnWorkSubscriptionsOff,
  turnWorkSubscriptionsOn,
  UnreadableAttachmentScopeError,
} from '../src/attachment-scope-edit.ts';

// The enrolled scope is edited RAW. A record on disk may carry what this build
// cannot read — an entry a newer build wrote, a key a newer build put on the
// envelope — and an edit that went through the parser would delete it for
// good. Every case here checks the whole record that comes back.

const ENDPOINT = 'https://plane.example.test';
const OTHER_ENDPOINT = 'https://other.example.test';
const ISO = '2026-10-07T09:00:00.000Z';
// whoami's `userEmail`; compared byte for byte, never read as an address.
const WHO: Pick<PluginWhoami, 'tenantName' | 'userEmail'> = {
  tenantName: 'Acme Payments',
  userEmail: 'member-17',
};
const PAYMENTS = 'github.com/acme/payments-api';
const LEDGER = 'github.com/acme/ledger';
const ESC = String.fromCharCode(27);

const repo = (
  identity: string,
  over: Partial<AttachmentScopeEntry> = {},
): AttachmentScopeEntry => ({
  kind: 'repo',
  identity,
  enrolledAt: ISO,
  ...over,
});

/** An entry a newer build wrote, with a kind this build does not know. */
const NEWER = { kind: 'org', identity: 'acme', enrolledAt: ISO };

/** A bound record, since touched by a newer build. */
const stored = () => ({
  endpoint: ENDPOINT,
  tenantName: WHO.tenantName,
  userEmail: WHO.userEmail,
  builtBy: 'a newer build',
  entries: [repo(PAYMENTS), NEWER] as unknown[],
});

/**
 * What makes a record for ENDPOINT one this build cannot read, through its
 * binding alone: each is laid over stored(), so the entries stay readable.
 */
const UNREADABLE_BINDING: [string, Record<string, unknown>][] = [
  ['a tenant name longer than this build reads', { tenantName: 't'.repeat(201) }],
  ['a control character in the account', { userEmail: `member-17${ESC}` }],
  ['a binding field that is not a string', { tenantName: null }],
];

/** The stored entries list of a record an edit returned. */
function entriesOf(raw: unknown): readonly unknown[] {
  if (typeof raw !== 'object' || raw === null || !('entries' in raw)) return [];
  const entries: unknown = raw.entries;
  return Array.isArray(entries) ? (entries as readonly unknown[]) : [];
}

describe('freshAttachmentScope', () => {
  it('is an empty record for the endpoint, bound to the organization and account given', () => {
    expect(freshAttachmentScope(ENDPOINT, WHO)).toStrictEqual({
      endpoint: ENDPOINT,
      tenantName: 'Acme Payments',
      userEmail: 'member-17',
      entries: [],
    });
  });

  it('copies only the two binding fields of a full whoami answer', () => {
    const whoami: PluginWhoami = { ...WHO, role: 'member', keyKind: 'machine', serverTime: ISO };
    expect(freshAttachmentScope(ENDPOINT, whoami)).toStrictEqual(
      freshAttachmentScope(ENDPOINT, WHO),
    );
  });

  it('is bound to the organization and account it was built for, and to no other account', () => {
    const fresh = freshAttachmentScope(ENDPOINT, WHO);
    expect(isAttachmentScopeBoundTo(fresh, ENDPOINT, WHO)).toBe(true);
    expect(isAttachmentScopeBoundTo(fresh, ENDPOINT, { ...WHO, userEmail: 'member-18' })).toBe(
      false,
    );
  });
});

describe('addAttachmentScopeEntries', () => {
  it('appends a new identity, keeping the binding, the envelope and every stored entry', () => {
    const { next, added } = addAttachmentScopeEntries(stored(), ENDPOINT, [repo(LEDGER)]);

    expect(added).toEqual([LEDGER]);
    expect(next).toStrictEqual({ ...stored(), entries: [repo(PAYMENTS), NEWER, repo(LEDGER)] });
  });

  it('leaves the record it was handed untouched', () => {
    const raw = stored();
    addAttachmentScopeEntries(raw, ENDPOINT, [repo(LEDGER)]);
    expect(raw).toStrictEqual(stored());
  });

  it('adds nothing for an identity already enrolled, and hands back the same record', () => {
    const raw = stored();
    const result = addAttachmentScopeEntries(raw, ENDPOINT, [repo(PAYMENTS, { label: 'again' })]);

    expect(result.added).toEqual([]);
    expect(result.next).toBe(raw);
  });

  it('compares identities byte for byte: a path in another case is another repository', () => {
    const other = 'github.com/Acme/payments-api';
    const { next, added } = addAttachmentScopeEntries(stored(), ENDPOINT, [repo(other)]);

    expect(added).toEqual([other]);
    expect(parseAttachmentScope(next)?.entries.map((entry) => entry.identity)).toEqual([
      PAYMENTS,
      other,
    ]);
  });

  it('appends an identity repeated within one call once, the first time it appears', () => {
    const { next, added } = addAttachmentScopeEntries(stored(), ENDPOINT, [
      repo(LEDGER),
      repo(LEDGER, { label: 'Ledger' }),
    ]);

    expect(added).toEqual([LEDGER]);
    expect(next).toStrictEqual({ ...stored(), entries: [repo(PAYMENTS), NEWER, repo(LEDGER)] });
  });

  it('does not count a stored entry it cannot read as enrolled', () => {
    // That entry enrolls nothing on this build, so the identity must still be
    // appended. Both are kept: a newer build may read the first.
    const unreadable = { kind: 'org', identity: LEDGER, enrolledAt: ISO };
    const raw = { ...stored(), entries: [unreadable] };
    const { next, added } = addAttachmentScopeEntries(raw, ENDPOINT, [repo(LEDGER)]);

    expect(added).toEqual([LEDGER]);
    expect(next).toStrictEqual({ ...stored(), entries: [unreadable, repo(LEDGER)] });
  });

  it.each<[string, unknown]>([
    ['no record at all, as an older settings writer leaves it', undefined],
    ['a record with no endpoint', { entries: [repo(PAYMENTS)] }],
    ['a value that is not a record', 'not-a-scope'],
    ['a record for another deployment', { ...stored(), endpoint: OTHER_ENDPOINT }],
    [
      'an unreadable record for another deployment',
      { ...stored(), endpoint: OTHER_ENDPOINT, tenantName: 't'.repeat(201) },
    ],
  ])('starts a new, UNBOUND record from %s', (_label, raw) => {
    const { next, added } = addAttachmentScopeEntries(raw, ENDPOINT, [repo(LEDGER)]);

    expect(added).toEqual([LEDGER]);
    expect(next).toStrictEqual({ endpoint: ENDPOINT, entries: [repo(LEDGER)] });
    // Unbound: it names no organization or account, so it is bound to none.
    expect(isAttachmentScopeBoundTo(next, ENDPOINT, WHO)).toBe(false);
  });

  it.each<[string, Record<string, unknown>]>([
    ...UNREADABLE_BINDING,
    ['entries that are not a list', { entries: 'x' }],
  ])(
    'refuses to enroll into a record for this deployment with %s, and leaves it as found',
    (_label, over) => {
      // Its entries may be another build's, read and forwarded there: a new record
      // in its place would delete them, and dropping the binding would make this
      // build forward every one of them.
      const raw = { ...stored(), ...over };
      const before = structuredClone(raw);
      expect(isAttachmentScopeValid(raw, ENDPOINT)).toBe(false);
      expect(() => addAttachmentScopeEntries(raw, ENDPOINT, [repo(LEDGER)])).toThrow(
        UnreadableAttachmentScopeError,
      );
      expect(() => addAttachmentScopeEntries(raw, ENDPOINT, [repo(LEDGER)])).toThrow(
        /^refusing to enroll into a scope record this build cannot read$/,
      );
      expect(raw).toStrictEqual(before);
    },
  );

  it('refuses with an error named UnreadableAttachmentScopeError, a plain Error to a caller', () => {
    // The name is part of what a caller can match on, as well as the class.
    const raw = { ...stored(), tenantName: 't'.repeat(201) };
    const refusal = (): unknown => {
      try {
        addAttachmentScopeEntries(raw, ENDPOINT, [repo(LEDGER)]);
      } catch (error) {
        return error;
      }
      return undefined;
    };
    const error = refusal();

    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(UnreadableAttachmentScopeError);
    expect(error).toHaveProperty('name', 'UnreadableAttachmentScopeError');
  });

  it('changes nothing when handed nothing to add', () => {
    const raw = stored();
    expect(addAttachmentScopeEntries(raw, ENDPOINT, []).next).toBe(raw);
    // Nothing to add judges no record, so an unreadable one is not refused.
    const unreadable = { ...stored(), tenantName: 't'.repeat(201) };
    expect(addAttachmentScopeEntries(unreadable, ENDPOINT, []).next).toBe(unreadable);
    expect(addAttachmentScopeEntries(undefined, ENDPOINT, [])).toEqual({
      next: undefined,
      added: [],
    });
  });

  it.each<[string, AttachmentScopeEntry]>([
    ['an empty identity', repo('')],
    ['a control character in the identity', repo(`${PAYMENTS}${ESC}[2J`)],
    ['a label longer than 80 characters', repo(LEDGER, { label: 'l'.repeat(81) })],
    ['a timestamp that is not one', repo(LEDGER, { enrolledAt: 'last tuesday' })],
  ])('refuses %s, in a sentence that repeats nothing', (_label, entry) => {
    // Stored, it would be dropped on every read: an enrollment that could never
    // take effect, reported as one. The message is fixed text, so a hostile
    // identity is never echoed by it.
    expect(() => {
      addAttachmentScopeEntries(stored(), ENDPOINT, [entry]);
    }).toThrow(/^refusing to enroll an entry this build would not read back$/);
  });

  it('raises the entry error, not the refusal, for an invalid entry over an unreadable record', () => {
    // The entry is judged first: whichever way the call fails, nothing is written,
    // but a caller learns the entry was at fault, not the record.
    const raw = { ...stored(), tenantName: 't'.repeat(201) };
    const before = structuredClone(raw);
    const offer = () => addAttachmentScopeEntries(raw, ENDPOINT, [repo('')]);

    expect(offer).toThrow(/^refusing to enroll an entry this build would not read back$/);
    expect(offer).not.toThrow(UnreadableAttachmentScopeError);
    expect(raw).toStrictEqual(before);
  });

  it('stores the parse of each entry, so a stray key on one is not written', () => {
    const stray = { ...repo(LEDGER), source: 'org' } as AttachmentScopeEntry;
    const { next } = addAttachmentScopeEntries(stored(), ENDPOINT, [stray]);

    expect(entriesOf(next).at(-1)).toStrictEqual(repo(LEDGER));
  });
});

describe('removeAttachmentScopeEntries', () => {
  it('removes the identity, keeping the binding, the envelope and every other stored entry', () => {
    const raw = { ...stored(), entries: [repo(PAYMENTS), NEWER, repo(LEDGER)] };
    const { next, removed } = removeAttachmentScopeEntries(raw, ENDPOINT, [PAYMENTS]);

    expect(removed).toEqual([PAYMENTS]);
    expect(next).toStrictEqual({ ...stored(), entries: [NEWER, repo(LEDGER)] });
  });

  it('removes every stored entry with the identity, one it cannot read included', () => {
    // Removing an entry means "stop forwarding this". An entry a newer build
    // would read must not be left behind to keep forwarding it there.
    const unreadable = { kind: 'org', identity: PAYMENTS, enrolledAt: ISO };
    const raw = { ...stored(), entries: [repo(PAYMENTS), unreadable, repo(LEDGER)] };
    const { next, removed } = removeAttachmentScopeEntries(raw, ENDPOINT, [PAYMENTS]);

    expect(removed).toEqual([PAYMENTS]);
    expect(next).toStrictEqual({ ...stored(), entries: [repo(LEDGER)] });
  });

  it('compares identities byte for byte, and hands back the same record when nothing matched', () => {
    const raw = stored();
    const result = removeAttachmentScopeEntries(raw, ENDPOINT, ['github.com/Acme/payments-api']);

    expect(result.removed).toEqual([]);
    expect(result.next).toBe(raw);
  });

  it('lists each identity once, in the order asked, and only those that matched', () => {
    const raw = { ...stored(), entries: [repo(PAYMENTS), repo(LEDGER)] };
    const { removed } = removeAttachmentScopeEntries(raw, ENDPOINT, [
      LEDGER,
      'github.com/acme/web',
      PAYMENTS,
      LEDGER,
    ]);

    expect(removed).toEqual([LEDGER, PAYMENTS]);
  });

  it.each(UNREADABLE_BINDING)(
    'removes the identity from a record for this deployment with %s, keeping the rest as found',
    (_label, over) => {
      // A build that reads this record would go on forwarding the identity.
      const raw = { ...stored(), ...over, entries: [repo(PAYMENTS), NEWER, repo(LEDGER)] };
      expect(isAttachmentScopeValid(raw, ENDPOINT)).toBe(false);
      const { next, removed } = removeAttachmentScopeEntries(raw, ENDPOINT, [PAYMENTS]);

      expect(removed).toEqual([PAYMENTS]);
      expect(next).toStrictEqual({ ...stored(), ...over, entries: [NEWER, repo(LEDGER)] });
    },
  );

  it.each<[string, unknown]>([
    ['no record at all', undefined],
    [
      'a record for this deployment whose entries are not a list',
      { endpoint: ENDPOINT, entries: 'x' },
    ],
    ['a record for another deployment', { ...stored(), endpoint: OTHER_ENDPOINT }],
    [
      'an unreadable record for another deployment',
      { ...stored(), endpoint: OTHER_ENDPOINT, tenantName: 't'.repeat(201) },
    ],
  ])('edits nothing for %s', (_label, raw) => {
    // Another deployment's record is not this function's to edit.
    const result = removeAttachmentScopeEntries(raw, ENDPOINT, [PAYMENTS]);

    expect(result.removed).toEqual([]);
    expect(result.next).toBe(raw);
  });

  it('leaves the record it was handed untouched', () => {
    const raw = stored();
    removeAttachmentScopeEntries(raw, ENDPOINT, [PAYMENTS]);
    expect(raw).toStrictEqual(stored());
  });
});

const ACCOUNT = 'claude:2ef4cd3c-c23c-473a-96be-1275cfc79103';
const OTHER_ACCOUNT = 'claude:f6793695-e29b-47e4-9473-c77e9ba752e9';
const account = (identity: string, over: Record<string, unknown> = {}) => ({
  kind: 'account',
  identity,
  enrolledAt: ISO,
  ...over,
});

describe('turnWorkSubscriptionsOff', () => {
  it('an unknown envelope key survives the opt-out', () => {
    const { next, changed } = turnWorkSubscriptionsOff(stored(), ENDPOINT);

    expect(changed).toBe(true);
    expect(next).toStrictEqual({ ...stored(), workSubscriptions: 'off' });
  });

  it('leaves the record it was handed untouched', () => {
    const raw = stored();
    turnWorkSubscriptionsOff(raw, ENDPOINT);
    expect(raw).toStrictEqual(stored());
  });

  it('changes nothing on a record already off, and hands back the same record', () => {
    const raw = { ...stored(), workSubscriptions: 'off' };
    expect(turnWorkSubscriptionsOff(raw, ENDPOINT)).toEqual({ next: raw, changed: false });
    expect(turnWorkSubscriptionsOff(raw, ENDPOINT).next).toBe(raw);
  });

  it('writes off over a value this build does not know', () => {
    const raw = { ...stored(), workSubscriptions: 'paused' };
    expect(turnWorkSubscriptionsOff(raw, ENDPOINT)).toEqual({
      next: { ...stored(), workSubscriptions: 'off' },
      changed: true,
    });
  });

  it.each(UNREADABLE_BINDING)(
    'turns off a record for this deployment with %s, keeping the rest as found',
    (_label, over) => {
      const raw = { ...stored(), ...over };
      expect(turnWorkSubscriptionsOff(raw, ENDPOINT).next).toStrictEqual({
        ...raw,
        workSubscriptions: 'off',
      });
    },
  );

  it.each<[string, unknown]>([
    ['no record at all', undefined],
    ['a record for another deployment', { ...stored(), endpoint: OTHER_ENDPOINT }],
    ['a value that is not a record', 'not-a-scope'],
  ])('starts a new, unbound record from %s', (_label, raw) => {
    expect(turnWorkSubscriptionsOff(raw, ENDPOINT)).toStrictEqual({
      next: { endpoint: ENDPOINT, entries: [], workSubscriptions: 'off' },
      changed: true,
    });
  });
});

describe('turnWorkSubscriptionsOn', () => {
  it('removes the opt-out, keeping every other key and entry as found', () => {
    const { next, changed } = turnWorkSubscriptionsOn(
      { ...stored(), workSubscriptions: 'off' },
      ENDPOINT,
    );

    expect(changed).toBe(true);
    expect(next).toStrictEqual(stored());
  });

  it('removes a value this build does not know as well', () => {
    expect(
      turnWorkSubscriptionsOn({ ...stored(), workSubscriptions: 'paused' }, ENDPOINT).next,
    ).toStrictEqual(stored());
  });

  it("removes it from another deployment's record, which reads as off too", () => {
    const raw = { ...stored(), endpoint: OTHER_ENDPOINT, workSubscriptions: 'off' };
    expect(turnWorkSubscriptionsOn(raw, ENDPOINT).next).toStrictEqual({
      ...stored(),
      endpoint: OTHER_ENDPOINT,
    });
  });

  it('changes nothing on a record with no opt-out, and hands back the same record', () => {
    const raw = stored();
    expect(turnWorkSubscriptionsOn(raw, ENDPOINT)).toEqual({ next: raw, changed: false });
    expect(turnWorkSubscriptionsOn(raw, ENDPOINT).next).toBe(raw);
    expect(turnWorkSubscriptionsOn(undefined, ENDPOINT)).toEqual({
      next: undefined,
      changed: false,
    });
  });

  it('replaces a stored value that is not a record with an empty one for this deployment', () => {
    expect(turnWorkSubscriptionsOn('not-a-scope', ENDPOINT)).toStrictEqual({
      next: { endpoint: ENDPOINT, entries: [] },
      changed: true,
    });
  });

  it('leaves the record it was handed untouched', () => {
    const raw = { ...stored(), workSubscriptions: 'off' };
    turnWorkSubscriptionsOn(raw, ENDPOINT);
    expect(raw).toStrictEqual({ ...stored(), workSubscriptions: 'off' });
  });
});

describe('markCodingAgentEntries', () => {
  it('marks a stored account entry in place, keeping its label, its time and every other key', () => {
    const raw = {
      ...stored(),
      entries: [repo(PAYMENTS), account(ACCOUNT, { label: 'Work', note: 'a newer build' }), NEWER],
    };
    const { next, marked } = markCodingAgentEntries(raw, ENDPOINT, [ACCOUNT]);

    expect(marked).toEqual([ACCOUNT]);
    expect(next).toStrictEqual({
      ...raw,
      entries: [
        repo(PAYMENTS),
        account(ACCOUNT, { label: 'Work', note: 'a newer build', codingAgents: true }),
        NEWER,
      ],
    });
  });

  it('leaves an entry already marked, a repository entry and another identity as they are', () => {
    const raw = {
      ...stored(),
      entries: [repo(PAYMENTS), account(ACCOUNT, { codingAgents: true }), account(OTHER_ACCOUNT)],
    };
    const result = markCodingAgentEntries(raw, ENDPOINT, [ACCOUNT, PAYMENTS]);

    expect(result.marked).toEqual([]);
    expect(result.next).toBe(raw);
  });

  it("marks nothing in another deployment's record", () => {
    const raw = { ...stored(), endpoint: OTHER_ENDPOINT, entries: [account(ACCOUNT)] };
    expect(markCodingAgentEntries(raw, ENDPOINT, [ACCOUNT])).toEqual({ next: raw, marked: [] });
  });

  it('leaves the record it was handed untouched', () => {
    const raw = { ...stored(), entries: [account(ACCOUNT)] };
    markCodingAgentEntries(raw, ENDPOINT, [ACCOUNT]);
    expect(raw).toStrictEqual({ ...stored(), entries: [account(ACCOUNT)] });
  });
});

describe('the opt-out and the coding-agents marker through every edit', () => {
  const MARKED = account(ACCOUNT, { codingAgents: true });
  const optedOut = () => ({
    ...stored(),
    workSubscriptions: 'off',
    entries: [repo(PAYMENTS), MARKED, NEWER] as unknown[],
  });

  it('enroll, unenroll and rotation edits keep workSubscriptions and codingAgents', () => {
    const enrolled = addAttachmentScopeEntries(optedOut(), ENDPOINT, [repo(LEDGER)]).next;
    expect(enrolled).toStrictEqual({
      ...optedOut(),
      entries: [repo(PAYMENTS), MARKED, NEWER, repo(LEDGER)],
    });

    const unenrolled = removeAttachmentScopeEntries(enrolled, ENDPOINT, [PAYMENTS]).next;
    expect(unenrolled).toStrictEqual({ ...optedOut(), entries: [MARKED, NEWER, repo(LEDGER)] });

    // A key rotation keeps the stored record whole exactly when it is bound to
    // the organization and account the key verified as, so the opt-out and the
    // marker ride along only while such a record still reads as bound.
    expect(isAttachmentScopeBoundTo(optedOut(), ENDPOINT, WHO)).toBe(true);
    expect(
      isAttachmentScopeBoundTo({ ...optedOut(), workSubscriptions: 'paused' }, ENDPOINT, WHO),
    ).toBe(true);

    // turnWorkSubscriptionsOff and markCodingAgentEntries keep what each other wrote.
    const unmarked = { ...stored(), entries: [account(ACCOUNT)] };
    const marked = markCodingAgentEntries(unmarked, ENDPOINT, [ACCOUNT]).next;
    expect(turnWorkSubscriptionsOff(marked, ENDPOINT).next).toStrictEqual({
      ...stored(),
      workSubscriptions: 'off',
      entries: [MARKED],
    });
    expect(
      markCodingAgentEntries({ ...unmarked, workSubscriptions: 'off' }, ENDPOINT, [ACCOUNT]).next,
    ).toStrictEqual({ ...stored(), workSubscriptions: 'off', entries: [MARKED] });
  });
});
