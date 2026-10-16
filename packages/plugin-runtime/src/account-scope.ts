import type { WorkAccountWrite } from '@akasecurity/persistence';
import type { AttachmentScopeEntry, ResolvedAttachmentScope } from '@akasecurity/schema';
import { agentKey, effectiveScopeKey, isWebAccountKey } from '@akasecurity/schema';

// The key a producer stamps a row with, and the capability it stamps through.
//
// A row stamped for a recognised work account is forwarded from any folder
// under that account's agent key (`agent:<scopeTag>:<account key>`), unless the
// row's own repository is in scope, which keeps the repository key. The attached
// gateway of a scoped attachment whose identity record holds offers the
// capability that makes the choice; every other gateway offers none, and a
// producer then stamps the repository key.

/**
 * A row's scope key as a producer stamped it: through an account scope, or as
 * the repository key when the gateway offers none. A brand, so a parameter can
 * require a key that came through one of the two.
 */
export type StampedScopeKey = string & { readonly __brand: 'StampedScopeKey' };

/**
 * What the gateway exposes of its identity record without the credential: the
 * bound record's attached-user digest and learned accounts, whether work
 * subscriptions are on, and the account keys enrolled by hand for coding
 * sessions on this deployment.
 */
export interface AccountScopeContext {
  readonly attachedUserDigest: string;
  readonly workSubscriptionsOn: boolean;
  readonly learned: readonly AttachmentScopeEntry[];
  readonly manual: readonly string[];
}

/** What a scoped attached gateway offers producers while its identity record holds. */
export interface AccountScope {
  /**
   * The key a row is stamped with: `repoKey` when it is in scope (repository
   * first), else the agent key of `accountKey` when that is in scope, else
   * `repoKey`. A value that is not an account key never makes an agent key.
   * Total, O(1), no I/O.
   */
  stamp(repoKey: string | undefined, accountKey?: string): StampedScopeKey | undefined;
  /**
   * Add the agent key of `accountKey` to this gateway's scope, for this process
   * only, so rows stamped afterwards through this gateway carry that key and are
   * forwarded. False, adding nothing, when `bindingHash` is not this scope's,
   * when the key is not an account key, and, for a key not already in scope,
   * while work subscriptions are off. True when the key is in scope afterwards.
   * Total.
   */
  admit(accountKey: string, bindingHash: string): boolean;
  /** Whether a row stamped `key` is in this gateway's scope. Total, O(1), no I/O. */
  inScope(key: string): boolean;
  /**
   * Write `accountKey` to the identity record as a learned work account, with
   * the gateway's own credential: 'present' when the record already holds it,
   * 'refused' while work subscriptions are off, for a value that is not an
   * account key, at the cap, when the record does not hold for the credential,
   * or when the record's lock cannot be taken for a reason waiting does not cure
   * (a missing or unwritable data directory), 'written' when it added the key,
   * and 'timeout' only when the record's lock timed out (a later call can
   * retry). It admits nothing. Total.
   */
  learn(accountKey: string): WorkAccountWrite;
  /** The binding hash of the identity record this scope was built from. */
  readonly bindingHash: string;
  /** The identity record's facts the gateway exposes (see AccountScopeContext). */
  readonly context: AccountScopeContext;
}

/** A gateway that may offer an account scope. */
export interface AccountScopeReader {
  accountScope(): AccountScope | undefined;
}

/**
 * The account scope over `keys`: the gateway's own key set, shared and not
 * copied, so a key `admit` adds is in every verdict that gateway makes.
 */
export function createAccountScope(init: {
  readonly keys: Set<string>;
  readonly scopeTag: string;
  readonly bindingHash: string;
  readonly context: AccountScopeContext;
  readonly learn: (accountKey: string) => WorkAccountWrite;
}): AccountScope {
  const { keys, scopeTag, bindingHash, context } = init;
  const scope: ResolvedAttachmentScope = { mode: 'scoped', keys };
  return {
    bindingHash,
    context,
    stamp(repoKey, accountKey) {
      try {
        const agent =
          accountKey !== undefined && isWebAccountKey(accountKey)
            ? agentKey(scopeTag, accountKey)
            : undefined;
        return repoStamp(effectiveScopeKey(scope, repoKey, agent));
      } catch {
        return repoStamp(repoKey);
      }
    },
    admit(accountKey, offered) {
      try {
        if (offered !== bindingHash || !isWebAccountKey(accountKey)) return false;
        const agent = agentKey(scopeTag, accountKey);
        if (agent === undefined) return false;
        if (keys.has(agent)) return true;
        if (!context.workSubscriptionsOn) return false;
        keys.add(agent);
        return true;
      } catch {
        return false;
      }
    },
    learn(accountKey) {
      try {
        return init.learn(accountKey);
      } catch {
        return 'timeout';
      }
    },
    inScope(key) {
      try {
        return key !== '' && keys.has(key);
      } catch {
        return false;
      }
    },
  };
}

/** A key as a stamp: the repository key a producer stamps when the gateway offers no account scope. */
export function repoStamp(repoKey: string | undefined): StampedScopeKey | undefined {
  return repoKey as StampedScopeKey | undefined;
}

/**
 * The account scope `gateway` offers through its `accountScope()` method, or
 * undefined. Total: a method that is missing or throws, or an answer without
 * `stamp`, `admit` and a binding hash, offers none.
 */
export function accountScopeOf(gateway: object): AccountScope | undefined {
  try {
    if (typeof (gateway as Partial<AccountScopeReader>).accountScope !== 'function') {
      return undefined;
    }
    const scope: unknown = (gateway as AccountScopeReader).accountScope();
    return isAccountScope(scope) ? scope : undefined;
  } catch {
    return undefined;
  }
}

/**
 * The key a producer stamps a row with: through `gateway`'s account scope when
 * it offers one, and the repository key otherwise. Total.
 */
export function stampScopeKey(
  gateway: object,
  repoKey: string | undefined,
  accountKey?: string,
): StampedScopeKey | undefined {
  try {
    const scope = accountScopeOf(gateway);
    return scope === undefined ? repoStamp(repoKey) : scope.stamp(repoKey, accountKey);
  } catch {
    return repoStamp(repoKey);
  }
}

// The members every producer calls. `context`, `learn` and `inScope` are not
// required, so a stand-in without them is still read.
function isAccountScope(value: unknown): value is AccountScope {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Partial<AccountScope>;
  return (
    typeof candidate.stamp === 'function' &&
    typeof candidate.admit === 'function' &&
    typeof candidate.bindingHash === 'string'
  );
}
