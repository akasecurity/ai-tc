import { createHash } from 'node:crypto';

import { sessionAccountsDir } from '@akasecurity/persistence';
import type { SessionAccountObservation } from '@akasecurity/schema';

import type { AccountCheck, AccountContext, AccountPlanState } from './account-check.ts';
import {
  accountGateOpen,
  CLAUDE_ACCOUNT_PREFIX,
  claudeKey,
  decideBasis,
  emailMatchesAttached,
  isAccountMatch,
  isManual,
} from './account-check.ts';
import type { ClaudeAccountEnv } from './account-env.ts';
import { readClaudeAccountEnv } from './account-env.ts';
import type { ClaudeLoginPaths, ClaudeLoginRead } from './claude-login.ts';
import {
  claudeConfigPath,
  claudeSettingsPaths,
  claudeSettingsVeto,
  readClaudeLogin,
} from './claude-login.ts';
import type { ResolvedAnchor, SessionAnchor, TranscriptScanCache } from './claude-session.ts';
import {
  readScanCache,
  resolveSessionAnchor,
  scanCredentialOrgs,
  writeScanCache,
} from './claude-session.ts';
import type { SessionBoundary } from './observation-log.ts';
import {
  appendObservation,
  latestBoundary,
  readObservations,
  readObservationTail,
  sessionAccountHash,
} from './observation-log.ts';

export interface ClaudeSessionInput {
  readonly anchor: SessionAnchor;
  readonly login: ClaudeLoginRead;
  readonly env: ClaudeAccountEnv;
  readonly settingsVeto: boolean;
  readonly ctx: AccountContext;
}

/** Anything that bills the session to a key, a token, a proxy or another provider. */
export function claudeVetoed(
  env: ClaudeAccountEnv,
  login: ClaudeLoginRead,
  settingsVeto: boolean,
): boolean {
  return (
    env.credentialEnv ||
    env.providerFlag ||
    env.baseUrlVeto ||
    settingsVeto ||
    (login.status === 'ok' && login.login.primaryApiKey)
  );
}

/**
 * Whether the session's org is a work subscription of the attached user. Pure.
 * The transcript's anchor is the session's org; the login file and the env can
 * only confirm it or veto it.
 */
export function validateClaudeSession(input: ClaudeSessionInput): AccountCheck {
  const { anchor, login, env, ctx } = input;
  const sessionOrg = anchor.kind === 'anchor' ? anchor.org : undefined;
  if (sessionOrg === undefined) {
    return { none: anchor.kind === 'none' ? anchor.reason : 'no-session-account' };
  }
  if (claudeVetoed(env, login, input.settingsVeto)) return { none: 'veto' };
  if (login.status === 'unreadable') return { none: 'unreadable' };
  const account = login.status === 'ok' && login.login.hasOauthAccount ? login.login : undefined;
  const loginOrg = account === undefined ? env.org : account.org;
  if (account !== undefined && env.orgPresent && env.org !== account.org)
    return { none: 'env-mismatch' };
  if (account?.email !== undefined && env.emailPresent && env.email !== account.email) {
    return { none: 'env-mismatch' };
  }
  if (loginOrg === undefined || sessionOrg !== loginOrg) return { none: 'login-changed' };
  return decideBasis({
    key: claudeKey(sessionOrg),
    ctx,
    emailMatches: emailMatchesAttached(account?.email, ctx.attachedUserDigest),
    plan: account?.planState ?? 'absent',
    absentPlan: 'plan-unconfirmed',
    fresh: account === undefined || !account.hasSlots || account.newestSlotOrg === loginOrg,
  });
}

/** The same check against the login's own org, with no transcript. It never learns. */
export function claudeLoginView(input: Omit<ClaudeSessionInput, 'anchor'>): AccountCheck {
  if (claudeVetoed(input.env, input.login, input.settingsVeto)) return { none: 'veto' };
  if (input.login.status === 'unreadable') return { none: 'unreadable' };
  const account =
    input.login.status === 'ok' && input.login.login.hasOauthAccount
      ? input.login.login
      : undefined;
  const loginOrg = account === undefined ? input.env.org : account.org;
  if (loginOrg === undefined) return { none: 'no-session-account' };
  return validateClaudeSession({ ...input, anchor: { kind: 'anchor', org: loginOrg, at: 0 } });
}

/** The log line a login view leaves: a hash only for a work key, never a reason. */
export function loginViewObservation(
  view: AccountCheck,
  bindingHash: string,
  t: number,
): SessionAccountObservation {
  if (isAccountMatch(view)) return { t, bd: bindingHash, k: 'w', h: sessionAccountHash(view.key) };
  if (view.none === 'veto') return { t, bd: bindingHash, k: 'v' };
  if (view.none === 'unreadable') return { t, k: 'u' };
  return { t, bd: bindingHash, k: 'n' };
}

/** A hash over which vetoes and env variables are set and agree with the file, never over values. */
export function claudeEnvFingerprint(
  env: ClaudeAccountEnv,
  login: ClaudeLoginRead,
  settingsVeto: boolean,
): string {
  const account = login.status === 'ok' ? login.login : undefined;
  const bits = [
    env.credentialEnv,
    env.providerFlag,
    env.baseUrlVeto,
    settingsVeto,
    account?.primaryApiKey === true,
    env.orgPresent,
    env.emailPresent,
    env.org === account?.org,
    env.email === account?.email,
  ];
  return createHash('sha256')
    .update(bits.map((bit) => (bit ? '1' : '0')).join(''))
    .digest('hex')
    .slice(0, 16);
}

export type ClaudeSessionSource = 'startup' | 'clear' | 'resume' | 'compact';

export interface ClaudeHookInput {
  readonly dataDir: string;
  readonly sessionId: string;
  readonly transcriptPath: string | undefined;
  readonly cwd: string;
  /** Undefined when no identity record is bound to this credential. */
  readonly ctx: AccountContext | undefined;
  readonly paths?: ClaudeLoginPaths | undefined;
  readonly now?: (() => number) | undefined;
}

export interface ClaudeHookResult {
  readonly check: AccountCheck;
  /** True only after a full check in this call validated a key the caller may learn and admit. */
  readonly mayAdmit: boolean;
  readonly threw: boolean;
}

const done = (check: AccountCheck): ClaudeHookResult => ({ check, mayAdmit: false, threw: false });

function boundaryFor(
  stateDir: string,
  sessionId: string,
  bindingHash: string,
  cache: TranscriptScanCache | undefined,
): SessionBoundary | undefined {
  const tail = readObservationTail(stateDir, sessionId);
  const fromTail = latestBoundary(tail.entries, bindingHash);
  if (fromTail !== undefined) return fromTail;
  if (cache?.lastBoundaryAt !== undefined && cache.boundaryKind !== undefined) {
    const inherited = cache.inherited === true && cache.boundaryBd === bindingHash;
    return { t: cache.lastBoundaryAt, kind: cache.boundaryKind, inherited };
  }
  if (tail.complete) return undefined;
  const all = readObservations(stateDir, sessionId).entries.map((entry) => entry.observation);
  return latestBoundary(all, bindingHash);
}

function memoHit(
  cache: TranscriptScanCache | undefined,
  resolved: ResolvedAnchor,
  ctx: AccountContext,
  login: ClaudeLoginRead,
  envFp: string,
): string | undefined {
  if (cache?.memo === undefined || resolved.anchor.kind !== 'anchor' || login.status !== 'ok')
    return undefined;
  const { memo } = cache;
  const anchorKey = claudeKey(resolved.anchor.org);
  const same =
    memo.bd === ctx.bindingHash &&
    memo.h === sessionAccountHash(anchorKey) &&
    memo.cfgMtime === login.mtimeMs &&
    memo.cfgSize === login.size &&
    memo.envFp === envFp &&
    cache.anchorAt === resolved.state.anchorAt;
  return same && ctx.inScope(anchorKey) ? anchorKey : undefined;
}

/**
 * One hook's account check: the login view first, recorded in the session log;
 * then, for a work view, the transcript's anchor and the full validation. A
 * memo from an earlier hook stands in for the full run only when nothing it
 * covers has changed and the key is already in scope.
 */
export function checkClaudeHook(input: ClaudeHookInput): ClaudeHookResult {
  try {
    const { ctx } = input;
    if (ctx === undefined) return done({ none: 'attached-user-unknown' });
    if (!accountGateOpen(ctx, CLAUDE_ACCOUNT_PREFIX)) return done({ none: 'opted-out' });
    const now = (input.now ?? Date.now)();
    const stateDir = sessionAccountsDir(input.dataDir);
    const env = readClaudeAccountEnv();
    const login = readClaudeLogin(claudeConfigPath(env, input.paths?.home));
    const settingsVeto = claudeSettingsVeto(claudeSettingsPaths(env, input.cwd, input.paths));
    const view = claudeLoginView({ login, env, settingsVeto, ctx });
    appendObservation(stateDir, input.sessionId, loginViewObservation(view, ctx.bindingHash, now));
    if (!isAccountMatch(view)) return done(view);
    if (input.transcriptPath === undefined) return done({ none: 'no-session-account' });
    const cache = readScanCache(stateDir, input.sessionId);
    const boundary = boundaryFor(stateDir, input.sessionId, ctx.bindingHash, cache);
    const resolved = resolveSessionAnchor(input.transcriptPath, input.sessionId, boundary, cache);
    if (resolved === undefined) return done({ none: 'no-session-account' });
    const envFp = claudeEnvFingerprint(env, login, settingsVeto);
    const hit = memoHit(cache, resolved, ctx, login, envFp);
    const check: AccountCheck =
      hit === undefined
        ? validateClaudeSession({ anchor: resolved.anchor, login, env, settingsVeto, ctx })
        : { key: hit, basis: isManual(ctx, hit) ? 'manual' : 'remembered' };
    const memo =
      isAccountMatch(check) && login.status === 'ok'
        ? {
            bd: ctx.bindingHash,
            h: sessionAccountHash(check.key),
            cfgMtime: login.mtimeMs,
            cfgSize: login.size,
            envFp,
            at: now,
          }
        : undefined;
    writeScanCache(stateDir, input.sessionId, {
      ...resolved.state,
      ...(boundary === undefined
        ? {}
        : {
            lastBoundaryAt: boundary.t,
            boundaryKind: boundary.kind,
            inherited: boundary.inherited,
            boundaryBd: ctx.bindingHash,
          }),
      ...(memo === undefined ? {} : { memo }),
    });
    return {
      check,
      mayAdmit: hit === undefined && isAccountMatch(check) && check.basis === 'validated',
      threw: false,
    };
  } catch {
    return { check: { none: 'unreadable' }, mayAdmit: false, threw: true };
  }
}

function inheritsAcrossResume(input: ClaudeHookInput, ctx: AccountContext, at: number): boolean {
  if (!accountGateOpen(ctx, CLAUDE_ACCOUNT_PREFIX) || input.transcriptPath === undefined)
    return false;
  const env = readClaudeAccountEnv();
  if (env.envScrub) return false;
  const login = readClaudeLogin(claudeConfigPath(env, input.paths?.home));
  if (
    claudeVetoed(env, login, claudeSettingsVeto(claudeSettingsPaths(env, input.cwd, input.paths)))
  )
    return false;
  const configOrg = login.status === 'ok' ? login.login.org : undefined;
  if (configOrg === undefined || (env.orgPresent && env.org !== configOrg)) return false;
  let last: string | undefined;
  for (const sighting of scanCredentialOrgs(input.transcriptPath, input.sessionId, 0)?.sightings ??
    []) {
    if (sighting.t < at) last = sighting.org;
  }
  return last !== undefined && last === configOrg;
}

/**
 * Records the start of a session: the boundary line for startup, clear and resume (none for
 * compact), and on resume the inheritance line when the login still names the org the session
 * last ran under.
 */
export function startClaudeSession(
  input: ClaudeHookInput & { readonly source: ClaudeSessionSource },
): { readonly inherited: boolean; readonly threw: boolean } {
  try {
    if (input.source === 'compact') return { inherited: false, threw: false };
    const now = (input.now ?? Date.now)();
    const stateDir = sessionAccountsDir(input.dataDir);
    appendObservation(stateDir, input.sessionId, { t: now, b: input.source });
    const { ctx } = input;
    if (input.source !== 'resume' || ctx === undefined || !inheritsAcrossResume(input, ctx, now)) {
      return { inherited: false, threw: false };
    }
    appendObservation(stateDir, input.sessionId, { t: now, bd: ctx.bindingHash, inh: true });
    return { inherited: true, threw: false };
  } catch {
    return { inherited: false, threw: true };
  }
}

export interface ClaudeLoginReport {
  /** The login's account key; undefined with no org. */
  readonly key: string | undefined;
  readonly planState: AccountPlanState | undefined;
  readonly found: boolean;
  readonly check: AccountCheck;
}

/**
 * The check of the login file alone, against the env and the settings layers: the login's key and
 * plan state, whether the file exists, and the view of it. Reads no transcript and writes nothing.
 */
export function claudeLoginCheck(input: {
  readonly ctx: AccountContext | undefined;
  readonly cwd: string;
  readonly paths?: ClaudeLoginPaths | undefined;
}): ClaudeLoginReport {
  try {
    const env = readClaudeAccountEnv();
    const login = readClaudeLogin(claudeConfigPath(env, input.paths?.home));
    const account = login.status === 'ok' ? login.login : undefined;
    const org = account?.hasOauthAccount === true ? account.org : env.org;
    const settingsVeto = claudeSettingsVeto(claudeSettingsPaths(env, input.cwd, input.paths));
    const check: AccountCheck =
      input.ctx === undefined
        ? { none: 'attached-user-unknown' }
        : claudeLoginView({ login, env, settingsVeto, ctx: input.ctx });
    return {
      key: org === undefined ? undefined : claudeKey(org),
      planState: account?.planState,
      found: login.status !== 'absent',
      check,
    };
  } catch {
    return { key: undefined, planState: undefined, found: false, check: { none: 'unreadable' } };
  }
}
