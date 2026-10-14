import { sessionAccountsDir } from '@akasecurity/persistence';
import type {
  AccountBasis,
  AccountCheckReason,
  SessionAccountObservation,
} from '@akasecurity/schema';
import { ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX } from '@akasecurity/schema';

import type { AccountContext } from './account-check.ts';
import {
  accountGateOpen,
  CHATGPT_ACCOUNT_PREFIX,
  chatgptKey,
  decideBasis,
  isLearned,
  isManual,
} from './account-check.ts';
import type { CodexAccountEnv } from './account-env.ts';
import { codexEnvVetoed, readCodexAccountEnv, resolveCodexHome } from './account-env.ts';
import type { CodexHead } from './codex-head.ts';
import { readCodexHead } from './codex-head.ts';
import type { CodexLoginRead } from './codex-login.ts';
import { codexAuthFingerprint, inspectCodexLogin } from './codex-login.ts';
import {
  appendObservation,
  classifyObservation,
  readObservations,
  sessionAccountHash,
} from './observation-log.ts';

// Which ChatGPT account a Codex thread runs under: the creating account its
// rollout head names, checked against the login file at SessionStart and again
// once for each change a later hook sees in that file.

export type CodexSessionSource = 'startup' | 'clear' | 'fork' | 'resume' | 'compact';

export type CodexAccountCheck =
  | { readonly key: string; readonly basis: AccountBasis; readonly authFingerprint: string }
  | { readonly none: AccountCheckReason };

export function isCodexAccountMatch(check: CodexAccountCheck): check is {
  readonly key: string;
  readonly basis: AccountBasis;
  readonly authFingerprint: string;
} {
  return 'key' in check;
}

export interface CodexSessionInput {
  readonly source: Exclude<CodexSessionSource, 'compact'>;
  readonly sessionId: string;
  readonly env: CodexAccountEnv;
  readonly head: CodexHead | 'pending' | undefined;
  readonly login: CodexLoginRead;
  readonly ctx: AccountContext;
}

/** Whether a fresh thread's account is a work subscription of the attached user. Pure. */
export function codexSessionAccount(input: CodexSessionInput): CodexAccountCheck {
  if (input.source === 'resume') return { none: 'resumed' };
  if (codexEnvVetoed(input.env)) return { none: 'veto' };
  const { head } = input;
  if (typeof head !== 'object' || head.sessionId !== input.sessionId)
    return { none: 'no-session-account' };
  if (head.modelProvider !== 'openai') return { none: 'provider' };
  if (head.creatorAccountId === undefined) return { none: 'no-session-account' };
  if (input.login.status !== 'ok') return { none: input.login.status };
  const { login } = input.login;
  if (login.accountId !== head.creatorAccountId) return { none: 'account-mismatch' };
  const basis = decideBasis({
    key: chatgptKey(login.accountId),
    ctx: input.ctx,
    emailMatches: login.emailMatchesAttached,
    plan: login.planState,
    absentPlan: 'plan',
    fresh: true,
  });
  return 'key' in basis ? { ...basis, authFingerprint: login.fingerprint } : basis;
}

export interface CodexHeld {
  readonly key: string;
  readonly basis: AccountBasis;
  readonly fingerprint: string;
}

/**
 * Whether a re-read login still carries the thread: a ChatGPT login whose
 * account hashes to the start line's, and whose basis still holds (a manual
 * key for its mode and account only).
 */
export function codexLoginStillHolds(input: {
  readonly login: CodexLoginRead;
  readonly startHash: string;
  readonly ctx: AccountContext;
}): CodexHeld | undefined {
  if (input.login.status !== 'ok') return undefined;
  const { login } = input.login;
  const accountKey = chatgptKey(login.accountId);
  if (sessionAccountHash(accountKey) !== input.startHash) return undefined;
  const held = (basis: AccountBasis): CodexHeld => ({
    key: accountKey,
    basis,
    fingerprint: login.fingerprint,
  });
  if (isManual(input.ctx, accountKey)) return held('manual');
  if (!login.emailMatchesAttached) return undefined;
  if (isLearned(input.ctx, accountKey))
    return login.planState === 'other' ? undefined : held('remembered');
  return login.planState === 'company' ? held('validated') : undefined;
}

export type CodexThreadState =
  | { readonly kind: 'unstarted' | 'resumed' | 'pending' | 'none' | 'sticky' }
  | { readonly kind: 'started'; readonly startHash: string; readonly baselineFp: string };

/**
 * The thread's state from its log lines of this binding: the last start line,
 * then its baselines and sticky lines. A start line marked pending, written
 * while the rollout head was not on disk yet, stays pending until a later
 * start line replaces it.
 */
export function codexThreadState(
  entries: readonly SessionAccountObservation[],
  bindingHash: string,
): CodexThreadState {
  let state: CodexThreadState = { kind: 'unstarted' };
  for (const entry of entries) {
    const line = classifyObservation(entry);
    if (line.kind === 'start' && line.bd === bindingHash) {
      if (line.start === 'resume') state = { kind: 'resumed' };
      else if (line.s === 'pending') state = { kind: 'pending' };
      else if (line.s === 'none' || line.fp === undefined) state = { kind: 'none' };
      else state = { kind: 'started', startHash: line.s, baselineFp: line.fp };
    } else if (
      line.kind === 'baseline' &&
      line.bd === bindingHash &&
      state.kind === 'started' &&
      line.s === state.startHash
    ) {
      state = { kind: 'started', startHash: line.s, baselineFp: line.fp };
    } else if (line.kind === 'sticky' && line.bd === bindingHash && state.kind === 'started') {
      state = { kind: 'sticky' };
    }
  }
  return state;
}

export interface CodexHookInput {
  readonly dataDir: string;
  readonly sessionId: string;
  /** Undefined when no identity record is bound to this credential. */
  readonly ctx: AccountContext | undefined;
  readonly transcriptPath?: string | undefined;
  /** The OS home the default Codex home sits under; tests only. */
  readonly home?: string | undefined;
  readonly now?: (() => number) | undefined;
}

export interface CodexHookResult {
  readonly check: CodexAccountCheck;
  /** True only when this call validated a key the caller may learn and admit. */
  readonly mayAdmit: boolean;
  readonly threw: boolean;
}

export interface CodexStartResult extends CodexHookResult {
  /** The rollout head was not on disk yet, and nothing was written. */
  readonly pending: boolean;
}

const NO_LOGIN: CodexLoginRead = { status: 'absent' };
const answer = (check: CodexAccountCheck, mayAdmit = false): CodexHookResult => ({
  check,
  mayAdmit,
  threw: false,
});
const started = (result: CodexHookResult, pending = false): CodexStartResult => ({
  ...result,
  pending,
});

function headNamesThread(head: CodexHead | 'pending' | undefined, sessionId: string): boolean {
  return (
    typeof head === 'object' &&
    head.sessionId === sessionId &&
    head.modelProvider === 'openai' &&
    head.creatorAccountId !== undefined
  );
}

/**
 * SessionStart's part, before the session is claimed. Startup, clear and fork
 * write the thread's start line: the key's hash and the login file's
 * fingerprint when it validated, `none` otherwise. Resume writes the sticky
 * resume line whether or not the user is opted out; compact keeps the earlier
 * decision. A head not on disk yet is pending and writes nothing, unless this
 * is the final attempt.
 */
export function startCodexSession(
  input: CodexHookInput & {
    readonly source: CodexSessionSource;
    readonly final?: boolean | undefined;
  },
): CodexStartResult {
  try {
    const { ctx } = input;
    if (ctx === undefined) return started(answer({ none: 'attached-user-unknown' }));
    const now = (input.now ?? Date.now)();
    const stateDir = sessionAccountsDir(input.dataDir);
    const bd = ctx.bindingHash;
    // The resume line goes in ahead of the opt-out gate: opting back in mid-thread
    // must not let a resumed thread validate again from its earlier start line.
    if (input.source === 'resume') {
      appendObservation(stateDir, input.sessionId, { t: now, bd, start: 'resume', s: 'none' });
      return started(answer({ none: 'resumed' }));
    }
    if (!accountGateOpen(ctx, CHATGPT_ACCOUNT_PREFIX))
      return started(answer({ none: 'opted-out' }));
    if (input.source === 'compact') return started(codexHookAccount(input));
    const env = readCodexAccountEnv();
    const head =
      input.transcriptPath === undefined ? 'pending' : readCodexHead(input.transcriptPath);
    if (head === 'pending' && input.final !== true && !codexEnvVetoed(env)) {
      return started(answer({ none: 'no-session-account' }), true);
    }
    const codexHome =
      !codexEnvVetoed(env) && headNamesThread(head, input.sessionId)
        ? resolveCodexHome(env, input.home)
        : undefined;
    const login =
      codexHome === undefined ? NO_LOGIN : inspectCodexLogin(codexHome, ctx.attachedUserDigest);
    const check = codexSessionAccount({
      source: input.source,
      sessionId: input.sessionId,
      env,
      head,
      login,
      ctx,
    });
    const line: SessionAccountObservation = isCodexAccountMatch(check)
      ? {
          t: now,
          bd,
          start: input.source,
          s: sessionAccountHash(check.key),
          fp: check.authFingerprint,
        }
      : {
          t: now,
          bd,
          start: input.source,
          s: 'none',
          fp: codexHome === undefined ? 'absent' : codexAuthFingerprint(codexHome),
        };
    appendObservation(stateDir, input.sessionId, line);
    return started(answer(check, isCodexAccountMatch(check) && check.basis === 'validated'));
  } catch {
    return { check: { none: 'malformed' }, mayAdmit: false, threw: true, pending: false };
  }
}

function keyForHash(hash: string, ctx: AccountContext): string | undefined {
  const candidates = [...ctx.manual, ...ctx.learned.map((entry) => entry.identity)];
  return candidates.find(
    (accountKey) =>
      accountKey.startsWith(CHATGPT_ACCOUNT_PREFIX) && sessionAccountHash(accountKey) === hash,
  );
}

function retryAfterLockTimeout(
  input: CodexHookInput,
  ctx: AccountContext,
  env: CodexAccountEnv,
  startHash: string,
  earlier: CodexLoginRead | undefined,
  codexHome: string | undefined,
): CodexHookResult {
  if (!ctx.workSubscriptionsOn) return answer({ none: 'opted-out' });
  // The thread's key is not a learned one, so with the cap full the automatic
  // path can only answer none: nothing is read until a learned account is forgotten.
  if (ctx.learned.length >= ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX) {
    return answer({ none: 'cap-reached' });
  }
  const login =
    earlier ??
    (codexHome === undefined ? NO_LOGIN : inspectCodexLogin(codexHome, ctx.attachedUserDigest));
  const head = input.transcriptPath === undefined ? 'pending' : readCodexHead(input.transcriptPath);
  const check = codexSessionAccount({
    source: 'startup',
    sessionId: input.sessionId,
    env,
    head,
    login,
    ctx,
  });
  if (!isCodexAccountMatch(check)) return answer(check);
  if (sessionAccountHash(check.key) !== startHash) return answer({ none: 'account-mismatch' });
  return answer(check, check.basis === 'validated');
}

/**
 * A later hook's check. It only lstat's the login file; a fingerprint other
 * than the thread's latest baseline triggers one re-read, after which the
 * thread either keeps its account (a new baseline line) or ends (a sticky none
 * line). A start hash that names no learned or manual key is validated again,
 * the way the hook that first validated it would have, while the learned-account
 * cap leaves room for it.
 */
export function codexHookAccount(input: CodexHookInput): CodexHookResult {
  try {
    const { ctx } = input;
    if (ctx === undefined) return answer({ none: 'attached-user-unknown' });
    if (!accountGateOpen(ctx, CHATGPT_ACCOUNT_PREFIX)) return answer({ none: 'opted-out' });
    const now = (input.now ?? Date.now)();
    const stateDir = sessionAccountsDir(input.dataDir);
    const entries = readObservations(stateDir, input.sessionId).entries.map(
      (entry) => entry.observation,
    );
    const thread = codexThreadState(entries, ctx.bindingHash);
    if (thread.kind === 'resumed') return answer({ none: 'resumed' });
    if (thread.kind === 'sticky') return answer({ none: 'auth-changed' });
    if (thread.kind !== 'started') return answer({ none: 'no-session-account' });
    const env = readCodexAccountEnv();
    if (codexEnvVetoed(env)) return answer({ none: 'veto' });
    const codexHome = resolveCodexHome(env, input.home);
    let current = codexHome === undefined ? 'absent' : codexAuthFingerprint(codexHome);
    let login: CodexLoginRead | undefined;
    if (current !== thread.baselineFp) {
      login =
        codexHome === undefined ? NO_LOGIN : inspectCodexLogin(codexHome, ctx.attachedUserDigest);
      const held = codexLoginStillHolds({ login, startHash: thread.startHash, ctx });
      if (held === undefined) {
        appendObservation(stateDir, input.sessionId, { t: now, bd: ctx.bindingHash, s: 'none' });
        return answer({ none: 'auth-changed' });
      }
      appendObservation(stateDir, input.sessionId, {
        t: now,
        bd: ctx.bindingHash,
        s: thread.startHash,
        fp: held.fingerprint,
      });
      current = held.fingerprint;
    }
    const known = keyForHash(thread.startHash, ctx);
    if (known === undefined)
      return retryAfterLockTimeout(input, ctx, env, thread.startHash, login, codexHome);
    if (isManual(ctx, known))
      return answer({ key: known, basis: 'manual', authFingerprint: current });
    if (!ctx.workSubscriptionsOn) return answer({ none: 'opted-out' });
    return answer({ key: known, basis: 'remembered', authFingerprint: current });
  } catch {
    return { check: { none: 'malformed' }, mayAdmit: false, threw: true };
  }
}
