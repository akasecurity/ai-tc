import { attachedUserDigestOf } from '@akasecurity/persistence';
import type {
  AccountBasis,
  AccountCheckReason,
  AttachedIdentity,
  AttachmentScopeEntry,
} from '@akasecurity/schema';
import {
  ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX,
  normalizeAccountEmail,
  parseAttachmentScope,
  workSubscriptionsOn,
} from '@akasecurity/schema';

/** Whether a login's plan is a company plan, is not shown, or is anything else. */
export type AccountPlanState = 'company' | 'absent' | 'other';

/** A session's account key and its basis, or the local reason it does not count. */
export type AccountCheck =
  { readonly key: string; readonly basis: AccountBasis } | { readonly none: AccountCheckReason };

/** What every account check knows about this attachment. */
export interface AccountContext {
  readonly bindingHash: string;
  readonly attachedUserDigest: string;
  readonly workSubscriptionsOn: boolean;
  /** The work accounts learned on this device for this attached user. */
  readonly learned: readonly AttachmentScopeEntry[];
  /** The account keys enrolled by hand for coding sessions. */
  readonly manual: readonly string[];
  /** Whether this account's agent key is already in the resolved scope. */
  readonly inScope: (accountKey: string) => boolean;
}

export interface AccountContextInput {
  /** The identity record, only when it holds for this endpoint, credential and mode. */
  readonly identity: AttachedIdentity | undefined;
  /** The stored `attachmentScope`, raw. */
  readonly scope: unknown;
  readonly bindingHash: string;
  readonly inScope: (accountKey: string) => boolean;
}

/** The parts of the gateway's account capability a check reads, taken structurally. */
export interface AccountScopeView {
  readonly bindingHash: string;
  readonly context: {
    readonly attachedUserDigest: string;
    readonly workSubscriptionsOn: boolean;
    readonly learned: readonly AttachmentScopeEntry[];
    readonly manual: readonly string[];
  };
  stamp(repoKey: undefined, accountKey: string): string | undefined;
}

export const CLAUDE_ACCOUNT_PREFIX = 'claude:';
export const CHATGPT_ACCOUNT_PREFIX = 'chatgpt:';

/** The account key of a Claude organization id. */
export function claudeKey(org: string): string {
  return `${CLAUDE_ACCOUNT_PREFIX}${org}`;
}

/** The account key of a ChatGPT workspace id. */
export function chatgptKey(accountId: string): string {
  return `${CHATGPT_ACCOUNT_PREFIX}${accountId}`;
}

/** The context the checks read, or undefined when no identity record holds. */
export function accountContextFor(input: AccountContextInput): AccountContext | undefined {
  if (input.identity === undefined) return undefined;
  const manual = (parseAttachmentScope(input.scope)?.entries ?? [])
    .filter((entry) => entry.kind === 'account' && entry.codingAgents === true)
    .map((entry) => entry.identity);
  return {
    bindingHash: input.bindingHash,
    attachedUserDigest: input.identity.attachedUserDigest,
    workSubscriptionsOn: workSubscriptionsOn(input.scope),
    learned: input.identity.workAccounts,
    manual,
    inScope: input.inScope,
  };
}

/** The context from the gateway's account capability; an account is in scope when it stamps. */
export function accountContextOf(scope: AccountScopeView): AccountContext {
  return {
    bindingHash: scope.bindingHash,
    ...scope.context,
    inScope: (accountKey) => scope.stamp(undefined, accountKey) !== undefined,
  };
}

export function isAccountMatch(
  check: AccountCheck,
): check is { readonly key: string; readonly basis: AccountBasis } {
  return 'key' in check;
}

export function isManual(ctx: AccountContext, accountKey: string): boolean {
  return ctx.manual.includes(accountKey);
}

export function isLearned(ctx: AccountContext, accountKey: string): boolean {
  return ctx.learned.some((entry) => entry.identity === accountKey);
}

export function hasManualKey(ctx: AccountContext, prefix: string): boolean {
  return ctx.manual.some((accountKey) => accountKey.startsWith(prefix));
}

/** Whether a reader runs at all: work subscriptions on, or a manual entry for this provider. */
export function accountGateOpen(ctx: AccountContext, prefix: string): boolean {
  return ctx.workSubscriptionsOn || hasManualKey(ctx, prefix);
}

/** Whether a login email is the attached user's, compared by digest. */
export function emailMatchesAttached(
  email: string | undefined,
  attachedUserDigest: string,
): boolean {
  if (email === undefined) return false;
  const normalized = normalizeAccountEmail(email);
  return normalized !== undefined && attachedUserDigestOf(normalized) === attachedUserDigest;
}

export interface BasisInput {
  readonly key: string;
  readonly ctx: AccountContext;
  readonly emailMatches: boolean;
  readonly plan: AccountPlanState;
  /** The reason an absent plan gives on the automatic path. */
  readonly absentPlan: 'plan-unconfirmed' | 'plan';
  /** False when the login's plan may belong to another org. */
  readonly fresh: boolean;
}

/**
 * The basis step both validators share: a manual entry first; then, unless the
 * user opted out, a learned key (email again, any plan shown must be a company
 * plan); then the automatic path (email, company plan, freshness, the cap).
 */
export function decideBasis(input: BasisInput): AccountCheck {
  const { key, ctx } = input;
  if (isManual(ctx, key)) return { key, basis: 'manual' };
  if (!ctx.workSubscriptionsOn) return { none: 'opted-out' };
  if (isLearned(ctx, key)) {
    if (!input.emailMatches) return { none: 'email' };
    if (input.plan === 'other') return { none: 'plan' };
    return { key, basis: 'remembered' };
  }
  if (!input.emailMatches) return { none: 'email' };
  if (input.plan === 'absent') return { none: input.absentPlan };
  if (input.plan === 'other') return { none: 'plan' };
  if (!input.fresh) return { none: 'plan-stale' };
  if (ctx.learned.length >= ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX) return { none: 'cap-reached' };
  return { key, basis: 'validated' };
}
