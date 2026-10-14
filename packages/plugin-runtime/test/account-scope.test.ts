import { randomUUID } from 'node:crypto';

import { agentKey } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { AccountScope } from '../src/account-scope.ts';
import {
  accountScopeOf,
  createAccountScope,
  repoStamp,
  stampScopeKey,
} from '../src/account-scope.ts';

// The capability a producer stamps a row's key through. A row in a repository
// in scope keeps the repository key; a row anywhere else takes the agent key of
// an account in scope; everything else keeps the repository key. `admit` lets a
// hook that has just validated an account forward its own rows, under the
// binding it validated against and never while work subscriptions are off.

const TAG = '0123456789abcdef';
const BINDING = 'fedcba9876543210';
const WORK_REPO = 'github.com/acme/payments-api';
const PERSONAL_REPO = 'github.com/someone/side-project';
const LEARNED = `claude:${randomUUID()}`;
const MANUAL = `claude:${randomUUID()}`;
const UNSEEN = `claude:${randomUUID()}`;
function agent(account: string): string {
  const key = agentKey(TAG, account);
  if (key === undefined) throw new Error(`no agent key for ${account}`);
  return key;
}

const CONTEXT = {
  attachedUserDigest: 'd'.repeat(64),
  workSubscriptionsOn: true,
  learned: [],
  manual: [],
} as const;

function scopeOver(
  keys: readonly string[] = [WORK_REPO, agent(LEARNED)],
  workSubscriptionsOn = true,
): { scope: AccountScope; keys: Set<string>; learnt: string[] } {
  const set = new Set(keys);
  const learnt: string[] = [];
  return {
    keys: set,
    learnt,
    scope: createAccountScope({
      keys: set,
      scopeTag: TAG,
      bindingHash: BINDING,
      context: { ...CONTEXT, workSubscriptionsOn },
      learn: (accountKey) => {
        learnt.push(accountKey);
        return 'written';
      },
    }),
  };
}

describe('AccountScope.stamp', () => {
  it('an enrolled repository keeps its key whatever the account', () => {
    const { scope } = scopeOver();
    expect(scope.stamp(WORK_REPO, LEARNED)).toBe(WORK_REPO);
    expect(scope.stamp(WORK_REPO, UNSEEN)).toBe(WORK_REPO);
  });

  it('stamps the agent key of an account in scope outside any repository in scope', () => {
    const { scope } = scopeOver();
    expect(scope.stamp(PERSONAL_REPO, LEARNED)).toBe(agent(LEARNED));
    expect(scope.stamp(undefined, LEARNED)).toBe(agent(LEARNED));
  });

  it('keeps the repository key for an account out of scope, or for none', () => {
    const { scope } = scopeOver();
    expect(scope.stamp(PERSONAL_REPO, UNSEEN)).toBe(PERSONAL_REPO);
    expect(scope.stamp(PERSONAL_REPO)).toBe(PERSONAL_REPO);
    expect(scope.stamp(undefined, UNSEEN)).toBeUndefined();
    expect(scope.stamp(undefined)).toBeUndefined();
  });

  it.each([
    ['a repository key', WORK_REPO],
    ['an agent key', agent(LEARNED)],
    ['an unknown provider', 'example-chat:acme'],
    ['an empty string', ''],
  ])('never stamps an agent key from %s passed as the account', (_name, account) => {
    // The key a stamp that skipped the account check would build, spelled by the
    // grammar directly so the row does not depend on how agentKey treats it.
    const { scope } = scopeOver([agent(LEARNED), `agent:${TAG}:${account}`]);
    expect(scope.stamp(PERSONAL_REPO, account)).toBe(PERSONAL_REPO);
  });
});

describe('AccountScope.admit', () => {
  it('admits a validated account for this process, so the next stamp carries it', () => {
    const { scope, keys } = scopeOver();
    expect(scope.admit(UNSEEN, BINDING)).toBe(true);
    expect(keys.has(agent(UNSEEN))).toBe(true);
    expect(scope.stamp(PERSONAL_REPO, UNSEEN)).toBe(agent(UNSEEN));
  });

  it('refuses an account offered under another binding', () => {
    const { scope, keys } = scopeOver();
    expect(scope.admit(UNSEEN, 'another-binding-hash')).toBe(false);
    expect(keys.has(agent(UNSEEN))).toBe(false);
    expect(scope.stamp(PERSONAL_REPO, UNSEEN)).toBe(PERSONAL_REPO);
  });

  it('an opted-out gateway never admits a learned key', () => {
    const { scope, keys } = scopeOver([WORK_REPO], false);
    expect(scope.admit(UNSEEN, BINDING)).toBe(false);
    expect(scope.admit(LEARNED, BINDING)).toBe(false);
    expect([...keys]).toEqual([WORK_REPO]);
    expect(scope.stamp(PERSONAL_REPO, LEARNED)).toBe(PERSONAL_REPO);
  });

  // An account enrolled by hand for coding sessions is in scope whatever the
  // opt-out says, so admitting it again changes nothing.
  it('answers yes, adding nothing, for an account already in scope while opted out', () => {
    const { scope, keys } = scopeOver([WORK_REPO, agent(MANUAL)], false);
    expect(scope.admit(MANUAL, BINDING)).toBe(true);
    expect(keys.size).toBe(2);
  });

  it.each([
    ['a repository key', WORK_REPO],
    ['an agent key', agent(UNSEEN)],
    ['an unknown provider', 'example-chat:acme'],
  ])('refuses %s offered as the account', (_name, account) => {
    const { scope, keys } = scopeOver();
    expect(scope.admit(account, BINDING)).toBe(false);
    expect(keys.size).toBe(2);
  });
});

describe('AccountScope.learn and context', () => {
  it('learns through the function it was built with, and admits nothing by itself', () => {
    const { scope, keys, learnt } = scopeOver();
    expect(scope.learn(UNSEEN)).toBe('written');
    expect(learnt).toEqual([UNSEEN]);
    expect(keys.has(agent(UNSEEN))).toBe(false);
  });

  it('answers timeout, never a throw, when the learning function throws', () => {
    const set = new Set<string>();
    const scope = createAccountScope({
      keys: set,
      scopeTag: TAG,
      bindingHash: BINDING,
      context: CONTEXT,
      learn: () => {
        throw new Error('lock timed out');
      },
    });
    expect(scope.learn(UNSEEN)).toBe('timeout');
  });

  it('hands a hook the context it was built with', () => {
    expect(scopeOver([], false).scope.context).toEqual({ ...CONTEXT, workSubscriptionsOn: false });
  });
});

describe('AccountScope.inScope and bindingHash', () => {
  it('answers from the key set alone', () => {
    const { scope } = scopeOver();
    expect(scope.inScope(WORK_REPO)).toBe(true);
    expect(scope.inScope(agent(LEARNED))).toBe(true);
    expect(scope.inScope(LEARNED)).toBe(false);
    expect(scope.inScope(PERSONAL_REPO)).toBe(false);
    expect(scope.inScope('')).toBe(false);
  });

  it('names the binding it was built from', () => {
    expect(scopeOver().scope.bindingHash).toBe(BINDING);
  });
});

describe('accountScopeOf and stampScopeKey', () => {
  it('reads the scope a gateway offers, and stamps through it', () => {
    const { scope } = scopeOver();
    const gateway = { accountScope: () => scope };
    expect(accountScopeOf(gateway)).toBe(scope);
    expect(stampScopeKey(gateway, PERSONAL_REPO, LEARNED)).toBe(agent(LEARNED));
  });

  // What every producer calls: a stand-in that offers those members is a scope.
  it('reads a scope that offers only stamp, admit and its binding hash', () => {
    const stub = { bindingHash: BINDING, stamp: () => undefined, admit: () => false };
    expect(accountScopeOf({ accountScope: () => stub })).toBe(stub);
  });

  it('a gateway without the capability stamps the repository key', () => {
    expect(accountScopeOf({})).toBeUndefined();
    expect(stampScopeKey({}, PERSONAL_REPO, LEARNED)).toBe(PERSONAL_REPO);
    expect(stampScopeKey({}, undefined, LEARNED)).toBeUndefined();
    expect(stampScopeKey({ accountScope: () => undefined }, PERSONAL_REPO, LEARNED)).toBe(
      PERSONAL_REPO,
    );
  });

  it.each<[string, object]>([
    [
      'a member that throws',
      {
        accountScope: () => {
          throw new Error('unreadable');
        },
      },
    ],
    [
      'a getter that throws',
      Object.defineProperty({}, 'accountScope', {
        get: () => {
          throw new Error('unreadable');
        },
      }),
    ],
    ['a member that is not a method', { accountScope: { stamp: () => undefined } }],
    ['a member that answers something else', { accountScope: () => ({ stamp: 42 }) }],
  ])('reads no scope, and stamps the repository key, from %s', (_name, gateway) => {
    expect(accountScopeOf(gateway)).toBeUndefined();
    expect(stampScopeKey(gateway, PERSONAL_REPO, LEARNED)).toBe(PERSONAL_REPO);
  });

  it('repoStamp is the repository key itself', () => {
    expect(repoStamp(WORK_REPO)).toBe(WORK_REPO);
    expect(repoStamp(undefined)).toBeUndefined();
  });
});
