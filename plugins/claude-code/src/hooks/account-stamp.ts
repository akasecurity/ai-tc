// Which account a Claude Code session's events are stamped for. A hook asks the
// account readers (`checkClaudeHook`) about the session's login and, for a work
// login, the session's own organization in its transcript; the gateway's account
// scope then stamps a repository key as the session's agent key wherever that
// key is in scope. Every function here is total: a fault answers "no account",
// counts one fail-open, and the event keeps its repository key.
import { pruneSessionAccountState, sessionAccountsDir } from '@akasecurity/persistence';
import type { StampedScopeKey } from '@akasecurity/plugin-runtime';
import { accountScopeOf, readAccountScope, repoStamp } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import type { AccountCheck, AccountContext } from '@akasecurity/plugin-sdk/account';
import {
  accountContextOf,
  accountGateOpen,
  appendObservation,
  checkClaudeHook,
  CLAUDE_ACCOUNT_PREFIX,
  claudeLoginCheck,
  isAccountMatch,
  loginViewObservation,
  startClaudeSession,
} from '@akasecurity/plugin-sdk/account';
import type { AccountBasis } from '@akasecurity/schema';

import { findSessionTranscript } from './session-transcript.ts';
import { countFailOpen } from './shared.ts';

/** The account one hook's events are stamped for. */
export interface HookAccount {
  /** `claude:<uuid>` when the session check named one; undefined: the repository key applies. */
  readonly accountKey: string | undefined;
  readonly basis: AccountBasis | undefined;
  /**
   * What this hook's check answered, when one ran. A matched key the identity record refuses
   * to learn gives no account and is answered `cap-reached`, whatever the cause: for example the
   * learned account cap, a record that does not hold for the gateway's credential, or a record
   * lock that cannot be taken for a reason other than a timeout.
   */
  readonly view: AccountCheck | undefined;
  /** The binding hash, set when this invocation's own full check validated the key. */
  readonly admitWith: string | undefined;
}

export const NO_ACCOUNT: HookAccount = {
  accountKey: undefined,
  basis: undefined,
  view: undefined,
  admitWith: undefined,
};

export interface HookAccountInput {
  readonly dataDir: string;
  readonly sessionId: string | undefined;
  readonly transcriptPath: string | undefined;
  /** The session's directory, whose project and local settings the vetoes read. */
  readonly cwd: string | undefined;
  /** The clock the observation lines are stamped with; hooks pass none. */
  readonly now?: (() => number) | undefined;
}

/**
 * The context the readers check a session against, from what `readAccountScope`
 * reads without a gateway. Nothing is in scope there, so no memo stands in for a
 * full check.
 */
function storeFreeContext(config: PluginConfig): AccountContext | undefined {
  const read = readAccountScope(config);
  return read === undefined ? undefined : accountContextOf({ ...read, stamp: () => undefined });
}

/**
 * The transcript of `sessionId`, for a mod helper, which the mod hands a session
 * id and a directory and no transcript path. Looks only where the account check
 * could read it: a scoped attachment whose Claude gate is open, so any other
 * attachment reads no directory. Never throws.
 */
export function locateSessionTranscript(
  config: PluginConfig,
  sessionId: string | undefined,
): string | undefined {
  try {
    const ctx = storeFreeContext(config);
    if (ctx === undefined || !accountGateOpen(ctx, CLAUDE_ACCOUNT_PREFIX)) return undefined;
    return findSessionTranscript(sessionId);
  } catch {
    countFailOpen();
    return undefined;
  }
}

// One check per gateway and session: a hook that asks twice (a turn's refusal,
// then its capture) records one login view.
const checked = new WeakMap<object, Map<string, HookAccount>>();

/**
 * The account the events of this hook are stamped for, on `gateway`.
 *
 * Records the login view, and for a work login checks the session: its org from
 * its transcript, the login and the vetoes. A key this invocation's own full
 * check validated is written to the identity record once; a key that write
 * refuses gives no account. No account scope on the gateway (standalone,
 * machine-wide, no identity record), work subscriptions off with nothing
 * enrolled by hand, or no session id: no account, and nothing is read. Never
 * throws.
 */
export function resolveHookAccount(gateway: object, input: HookAccountInput): HookAccount {
  try {
    if (input.sessionId === undefined) return NO_ACCOUNT;
    const bySession = checked.get(gateway) ?? new Map<string, HookAccount>();
    checked.set(gateway, bySession);
    const known = bySession.get(input.sessionId);
    if (known !== undefined) return known;
    const account = checkSession(gateway, input.sessionId, input);
    bySession.set(input.sessionId, account);
    return account;
  } catch {
    countFailOpen();
    return NO_ACCOUNT;
  }
}

function checkSession(gateway: object, sessionId: string, input: HookAccountInput): HookAccount {
  try {
    const scope = accountScopeOf(gateway);
    if (scope === undefined) return NO_ACCOUNT;
    const ctx = accountContextOf(scope);
    if (!accountGateOpen(ctx, CLAUDE_ACCOUNT_PREFIX)) return NO_ACCOUNT;
    const result = checkClaudeHook({
      dataDir: input.dataDir,
      sessionId,
      transcriptPath: input.transcriptPath,
      cwd: input.cwd ?? process.cwd(),
      ctx,
      now: input.now,
    });
    if (result.threw) countFailOpen();
    const { check } = result;
    if (!isAccountMatch(check)) return { ...NO_ACCOUNT, view: check };
    // The write re-checks the record inside its lock, so it can refuse a key the
    // check passed. A refused write, whatever the cause (see `HookAccount.view`),
    // is reported as the cap and the key is not stamped, so it is not admitted
    // either. A write that times out leaves the key unwritten; the admit below
    // still forwards this invocation, and the next full check writes it.
    if (result.mayAdmit && scope.learn(check.key) === 'refused') {
      return { ...NO_ACCOUNT, view: { none: 'cap-reached' } };
    }
    return {
      accountKey: check.key,
      basis: check.basis,
      view: check,
      admitWith: result.mayAdmit ? scope.bindingHash : undefined,
    };
  } catch {
    countFailOpen();
    return NO_ACCOUNT;
  }
}

/**
 * `repoKey` stamped for `account` on `gateway`: the session's agent key where
 * that key is in scope and the repository is not, else the repository key.
 * Admits a key this invocation validated before stamping, on this gateway. A
 * gateway with no account scope gets the repository key. Never throws.
 */
export function stampFor(
  gateway: object,
  account: HookAccount,
  repoKey: string | undefined,
): StampedScopeKey | undefined {
  try {
    const scope = accountScopeOf(gateway);
    if (scope === undefined) return repoStamp(repoKey);
    if (account.accountKey === undefined) return scope.stamp(repoKey);
    if (account.admitWith !== undefined) scope.admit(account.accountKey, account.admitWith);
    return scope.stamp(repoKey, account.accountKey);
  } catch {
    countFailOpen();
    return repoStamp(repoKey);
  }
}

/** What SessionStart recorded about the session's account. */
export interface SessionStartAccount {
  /** The login view recorded at session start, when a check ran. */
  readonly view: AccountCheck | undefined;
  /** The basis that view reached for the login's own key, when it is a work login. */
  readonly basis: AccountBasis | undefined;
  /** The login cannot be told yet: the config is unreadable, or shows no plan. */
  readonly undetermined: boolean;
}

export interface SessionStartAccountInput {
  readonly config: PluginConfig;
  readonly sessionId: string | undefined;
  readonly transcriptPath: string | undefined;
  /** The session's directory, whose project and local settings the vetoes read. */
  readonly cwd: string | undefined;
  /** The payload's `source`: startup, resume, clear or compact. */
  readonly source: string | undefined;
  readonly now?: (() => number) | undefined;
}

const SESSION_START_NONE: SessionStartAccount = {
  view: undefined,
  basis: undefined,
  undetermined: false,
};

function sessionSourceOf(
  source: string | undefined,
): 'startup' | 'clear' | 'resume' | 'compact' | undefined {
  switch (source) {
    case 'startup':
    case 'clear':
    case 'resume':
    case 'compact':
      return source;
    default:
      return undefined;
  }
}

/**
 * What SessionStart records before the session start runs, on a scoped
 * attachment whose identity record holds: the boundary (none for a compaction)
 * and, on a resume, whether the session inherits the org it ran under; then,
 * unless the check is gated off, the login view. On any attachment, scoped or
 * not, prunes the session state files last written more than thirty days ago.
 * Opens no store. Never throws.
 */
export function recordSessionStartAccount(input: SessionStartAccountInput): SessionStartAccount {
  const nowMs = (input.now ?? Date.now)();
  const account = sessionStartAccount(input, nowMs);
  try {
    pruneSessionAccountState(input.config.dataDir, nowMs);
  } catch {
    countFailOpen();
  }
  return account;
}

function sessionStartAccount(input: SessionStartAccountInput, nowMs: number): SessionStartAccount {
  try {
    const { sessionId } = input;
    if (sessionId === undefined) return SESSION_START_NONE;
    const ctx = storeFreeContext(input.config);
    if (ctx === undefined) return SESSION_START_NONE;
    const { dataDir } = input.config;
    const cwd = input.cwd ?? process.cwd();
    const source = sessionSourceOf(input.source);
    if (source !== undefined) {
      const started = startClaudeSession({
        dataDir,
        sessionId,
        transcriptPath: input.transcriptPath,
        cwd,
        ctx,
        now: () => nowMs,
        source,
      });
      if (started.threw) countFailOpen();
    }
    if (!accountGateOpen(ctx, CLAUDE_ACCOUNT_PREFIX)) return SESSION_START_NONE;
    const view = claudeLoginCheck({ ctx, cwd }).check;
    appendObservation(
      sessionAccountsDir(dataDir),
      sessionId,
      loginViewObservation(view, ctx.bindingHash, nowMs),
    );
    if (isAccountMatch(view)) return { view, basis: view.basis, undetermined: false };
    return {
      view,
      basis: undefined,
      undetermined: view.none === 'unreadable' || view.none === 'plan-unconfirmed',
    };
  } catch {
    countFailOpen();
    return SESSION_START_NONE;
  }
}

/**
 * Stop's login view, appended to the session's account log before the reconcile
 * is triggered. Reads no transcript. Never throws.
 */
export function recordStopObservation(
  config: PluginConfig,
  sessionId: string,
  cwd: string | undefined,
  now?: () => number,
): void {
  try {
    const result = checkClaudeHook({
      dataDir: config.dataDir,
      sessionId,
      transcriptPath: undefined,
      cwd: cwd ?? process.cwd(),
      ctx: storeFreeContext(config),
      now,
    });
    if (result.threw) countFailOpen();
  } catch {
    countFailOpen();
  }
}
