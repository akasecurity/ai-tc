import { z } from 'zod';

import type { ResolvedAttachmentScope } from './local.ts';
import { scopeVerdict } from './local.ts';
import { isWebAccountKey } from './web-account.ts';

// The scope key a coding agent's row carries when the row is attributed to the
// work account its session runs under: `agent:<scope tag>:<account key>`.
//
// The tag is sixteen lower-case hex digits naming the deployment, the
// organization and the attached user the key was made for; the account key is a
// web account key (`claude:<uuid>`). An agent key never names a repository, is
// never written to settings.json and is never sent: it lives in the local
// `scope_key` column and in the resolved scope a forward path checks rows
// against.
//
// Pure, with no I/O. The functions here never throw.

/** The first segment of every agent key. */
export const AGENT_KEY_PREFIX = 'agent';

// The first 64 bits of a sha256 digest, as lower-case hex.
const SCOPE_TAG = /^[0-9a-f]{16}$/;

/**
 * The agent key for `accountKey` under `scopeTag`, or `undefined` when the tag
 * is not sixteen lower-case hex digits or the account key is not exactly a web
 * account key (isWebAccountKey).
 */
export function agentKey(scopeTag: string, accountKey: string): string | undefined {
  try {
    if (!SCOPE_TAG.test(scopeTag) || !isWebAccountKey(accountKey)) return undefined;
    return `${AGENT_KEY_PREFIX}:${scopeTag}:${accountKey}`;
  } catch {
    return undefined;
  }
}

/**
 * An agent key split into its tag and account key, or `undefined` when `key` is
 * not exactly an agent key: the prefix, a colon, a tag, a colon, and a web
 * account key.
 */
export function parseAgentKey(key: unknown): { scopeTag: string; accountKey: string } | undefined {
  try {
    if (typeof key !== 'string') return undefined;
    const prefix = `${AGENT_KEY_PREFIX}:`;
    if (!key.startsWith(prefix)) return undefined;
    const rest = key.slice(prefix.length);
    const colon = rest.indexOf(':');
    if (colon === -1) return undefined;
    const scopeTag = rest.slice(0, colon);
    const accountKey = rest.slice(colon + 1);
    return SCOPE_TAG.test(scopeTag) && isWebAccountKey(accountKey)
      ? { scopeTag, accountKey }
      : undefined;
  } catch {
    return undefined;
  }
}

/** Whether `key` is exactly an agent key (see parseAgentKey). */
export function isAgentScopeKey(key: unknown): boolean {
  return parseAgentKey(key) !== undefined;
}

/**
 * Whether a scope key names a repository: it holds a `/`, and no `:` comes
 * before its first `/`. A repository key is `host/owner/repo`; an account key and
 * an agent key start with a provider or a prefix and a colon, so neither is one,
 * and neither is ever sent as a repository's name.
 */
export function isRepoShapedScopeKey(key: unknown): boolean {
  if (typeof key !== 'string') return false;
  const slash = key.indexOf('/');
  if (slash === -1) return false;
  const colon = key.indexOf(':');
  return colon === -1 || colon > slash;
}

/**
 * The scope key a row is stamped with, repository first.
 *
 *   - Not exactly a scoped attachment (machine-wide, or a mode this build does
 *     not know): `repoKey`.
 *   - `repoKey` in scope (scopeVerdict): `repoKey`, whatever the account.
 *   - `agentScopeKey` exactly an agent key, and in scope: `agentScopeKey`.
 *   - Anything else, a throw included: `repoKey`.
 *
 * A web account key or a repository key passed as `agentScopeKey` is never
 * stamped: only an agent key is. O(1), with no I/O.
 */
export function effectiveScopeKey(
  resolved: ResolvedAttachmentScope,
  repoKey: string | undefined,
  agentScopeKey: string | undefined,
): string | undefined {
  try {
    if (resolved.mode !== 'scoped') return repoKey;
    const agent =
      agentScopeKey !== undefined && isAgentScopeKey(agentScopeKey) ? agentScopeKey : undefined;
    if (scopeVerdict(resolved, repoKey) === 'forward') return repoKey;
    if (agent !== undefined && resolved.keys.has(agent)) return agent;
    return repoKey;
  } catch {
    return repoKey;
  }
}

/**
 * Whether work-subscription recognition is on, given the stored scope record:
 * `settings.attachmentScope` as found, never its parse, so an opt-out on a record
 * this build cannot otherwise read still counts.
 *
 * On when there is no record at all, or the record carries no
 * `workSubscriptions`, which is how every record written before the field reads.
 * Off for any value present, `'off'` or another, for a stored value that is not
 * a record, and for a throw.
 */
export function workSubscriptionsOn(scope: unknown): boolean {
  try {
    if (scope === undefined) return true;
    if (typeof scope !== 'object' || scope === null || Array.isArray(scope)) return false;
    return !('workSubscriptions' in scope) || scope.workSubscriptions === undefined;
  } catch {
    return false;
  }
}

/**
 * An account email in the one form two of them are compared in, or `undefined`
 * when it is not one: trimmed, then refused when empty, when it holds any
 * character outside ASCII, or unless it has exactly one `@` with text on both
 * sides; otherwise lower-cased. Nothing else is folded: a `+` tag and the dots
 * stay as they are.
 */
export function normalizeAccountEmail(input: unknown): string | undefined {
  try {
    if (typeof input !== 'string') return undefined;
    const value = input.trim();
    if (value === '') return undefined;
    for (let i = 0; i < value.length; i += 1) {
      if (value.charCodeAt(i) > 0x7f) return undefined;
    }
    const at = value.indexOf('@');
    if (at <= 0 || at === value.length - 1 || value.includes('@', at + 1)) return undefined;
    return value.toLowerCase();
  } catch {
    return undefined;
  }
}

/**
 * Why a coding agent's login was not taken as a work subscription. Local only:
 * shown on the user's own terminal, never stamped on a row, a session root or a
 * request. No `.meta({ id })`: it registers nothing.
 */
export const AccountCheckReason = z.enum([
  'no-session-account',
  'veto',
  'unreadable',
  'env-mismatch',
  'login-changed',
  'org-changed',
  'email',
  'plan',
  'plan-unconfirmed',
  'plan-stale',
  'attached-user-unknown',
  'opted-out',
  'resumed',
  'provider',
  'absent',
  'mode',
  'malformed',
  'account-mismatch',
  'auth-changed',
  'cap-reached',
]);
export type AccountCheckReason = z.infer<typeof AccountCheckReason>;

/**
 * What a work account was taken on: validated in this session against the
 * attached user, remembered from an earlier validation on this machine, or
 * enrolled by hand. Local only, like AccountCheckReason, and registers nothing.
 */
export const AccountBasis = z.enum(['validated', 'remembered', 'manual']);
export type AccountBasis = z.infer<typeof AccountBasis>;
