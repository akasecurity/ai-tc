// A Codex thread's account, from the readers that write its session log:
// SessionStart decides it before the session is claimed, and every later hook
// checks the login file against the log. An event carries the account's agent
// key only while the log says the thread still runs under it. Every function
// here is total: a fault answers "no account", and the event keeps its
// repository key.
import { pruneSessionAccountState, sessionAccountsDir } from '@akasecurity/persistence';
import type { AccountScope, SessionStartInput, StampedScopeKey } from '@akasecurity/plugin-runtime';
import { accountScopeOf, readAccountScope, resolveDataGateway } from '@akasecurity/plugin-runtime';
import type { DataGateway, PluginConfig } from '@akasecurity/plugin-sdk';
import { sessionRootScopeKey } from '@akasecurity/plugin-sdk';
import type {
  CodexHookInput,
  CodexHookResult,
  CodexSessionSource,
} from '@akasecurity/plugin-sdk/account';
import {
  accountContextOf,
  appendObservation,
  chatgptKey,
  codexAuthFingerprint,
  codexHomeDir,
  codexHookAccount,
  codexThreadState,
  isCodexAccountMatch,
  readCodexHead,
  readObservations,
  sessionAccountHash,
  startCodexSession,
} from '@akasecurity/plugin-sdk/account';
import type { AccountBasis, SessionAccountObservation } from '@akasecurity/schema';

import { captureScopeKey } from './shared.ts';
import { stampFor } from './stamped-capture.ts';

export interface ThreadAccount {
  accountKey: string | undefined;
  basis: AccountBasis | undefined;
  /** The thread's first rollout line was not on disk, so its account waits for its next hook. */
  pending: boolean;
}

export interface StartThreadInput {
  dataDir: string;
  sessionId: string | undefined;
  source: string | undefined;
  transcriptPath: string | undefined;
  nowMs: number;
  /** The directory Codex's default home sits under; tests only. */
  home?: string | undefined;
}

export type ThreadHookInput = Omit<StartThreadInput, 'source'>;

export type LeafStamper = (repoKey: string | undefined, occurredAt: string) => string | undefined;

export type CodexSessionStartFields = Pick<
  SessionStartInput,
  'rootScopeKey' | 'accountBasis' | 'admitAccount' | 'threadAccountPending'
>;

const NO_ACCOUNT: ThreadAccount = { accountKey: undefined, basis: undefined, pending: false };

const SOURCES: ReadonlySet<string> = new Set<CodexSessionSource>([
  'startup',
  'clear',
  'fork',
  'resume',
  'compact',
]);

function isSource(value: string | undefined): value is CodexSessionSource {
  return value !== undefined && SOURCES.has(value);
}

/** The thread's session log, in file order. */
function threadLog(dataDir: string, sessionId: string): SessionAccountObservation[] {
  return readObservations(sessionAccountsDir(dataDir), sessionId).entries.map(
    (entry) => entry.observation,
  );
}

function hookInput(scope: AccountScope, input: ThreadHookInput, sessionId: string): CodexHookInput {
  return {
    dataDir: input.dataDir,
    sessionId,
    ctx: accountContextOf(scope),
    transcriptPath: input.transcriptPath,
    home: input.home,
    now: () => input.nowMs,
  };
}

/**
 * The thread's account from one check. A key this call validated is learned,
 * then admitted unless the write refused it.
 */
function settle(scope: AccountScope, result: CodexHookResult): ThreadAccount {
  const check = result.check;
  if (!isCodexAccountMatch(check)) return NO_ACCOUNT;
  if (result.mayAdmit) {
    // The write re-checks the learned-account cap inside the lock, so it can
    // refuse a key the validator passed: that thread keeps the repository rule.
    // A write that timed out still admits for this invocation; a later hook
    // retries it.
    if (scope.learn(check.key) === 'refused') return NO_ACCOUNT;
    scope.admit(check.key, scope.bindingHash);
  }
  return { accountKey: check.key, basis: check.basis, pending: false };
}

/** Whether the thread's latest start line says its first rollout line was not on disk yet. */
function headPending(dataDir: string, sessionId: string, bindingHash: string): boolean {
  return codexThreadState(threadLog(dataDir, sessionId), bindingHash).kind === 'pending';
}

/** The login file's fingerprint, for a pending start line. */
function fingerprintOf(home: string | undefined): string {
  const codexHome = codexHomeDir(home);
  return codexHome === undefined ? 'absent' : codexAuthFingerprint(codexHome);
}

/**
 * SessionStart: decide the thread's account. Runs before the session is
 * claimed, so a resume's sticky line is on disk whatever the claim does. A first
 * rollout line that is not on disk yet leaves a pending start line, which the
 * next hook resolves once. Until then the thread has no account, so its session
 * root is keyed by its folder, and the root is not re-keyed when the thread is
 * decided: the thread's captures carry its agent key from that hook on, while its
 * token and tool rows follow the root's verdict, sent when the folder is an
 * enrolled repository and kept on the machine when it is not. A payload that
 * names no known source decides nothing, because the thread cannot then be told
 * from a resumed one. Total.
 */
export function startThreadAccount(gateway: object, input: StartThreadInput): ThreadAccount {
  try {
    const scope = accountScopeOf(gateway);
    const sessionId = input.sessionId;
    const source = input.source;
    if (scope === undefined || sessionId === undefined || !isSource(source)) return NO_ACCOUNT;
    const result = startCodexSession({ ...hookInput(scope, input, sessionId), source });
    const pending = result.pending && source !== 'resume' && source !== 'compact';
    if (pending) {
      appendObservation(sessionAccountsDir(input.dataDir), sessionId, {
        t: input.nowMs,
        bd: scope.bindingHash,
        start: source,
        s: 'pending',
        fp: fingerprintOf(input.home),
      });
    }
    return { ...settle(scope, result), pending };
  } catch {
    return NO_ACCOUNT;
  }
}

/**
 * Every later hook: the thread's account key, or undefined for the repository
 * rule. The readers only `lstat` the login file unless it changed since the
 * latest start or baseline line; a pending start line gets its one final
 * attempt here. Total.
 */
export function threadAccountKey(gateway: object, input: ThreadHookInput): string | undefined {
  try {
    const scope = accountScopeOf(gateway);
    const sessionId = input.sessionId;
    if (scope === undefined || sessionId === undefined) return undefined;
    const base = hookInput(scope, input, sessionId);
    const result = headPending(input.dataDir, sessionId, scope.bindingHash)
      ? startCodexSession({ ...base, source: 'startup', final: true })
      : codexHookAccount(base);
    return settle(scope, result).accountKey;
  } catch {
    return undefined;
  }
}

/**
 * The key a tool event is stored under. An apply_patch names its files inside
 * the patch body, which is not parsed here, so it carries no repository key: the
 * thread's agent key in a work thread, no key otherwise.
 */
export function codexToolStamp(
  gateway: object,
  input: Record<string, unknown>,
  toolName: string | undefined,
  accountKey: string | undefined,
  filePath?: string,
): StampedScopeKey | undefined {
  const repoKey = toolName === 'apply_patch' ? undefined : captureScopeKey(input, filePath);
  return stampFor(gateway, repoKey, accountKey);
}

/** Closes `gateway`; a failing close cannot take back what was already written. */
async function closeQuietly(gateway: DataGateway | undefined): Promise<void> {
  try {
    await gateway?.close();
  } catch {
    // Nothing to release.
  }
}

/**
 * What the SessionStart hook hands `handleSessionStart` about the thread's
 * account, after the start line is written: the root's stamped key, the basis the
 * session-start line names, and the admission the session start's own gateway
 * repeats. A thread left pending hands only that fact, for the line to name.
 * Also prunes old session state. Empty on a fault, with no account and not
 * pending, and on a machine that is not on a scoped attachment, where no gateway
 * is opened.
 */
export async function codexSessionStartAccount(
  config: PluginConfig,
  input: Omit<StartThreadInput, 'dataDir'> & { cwd: string },
): Promise<CodexSessionStartFields> {
  let gateway: DataGateway | undefined;
  try {
    if (readAccountScope(config) === undefined) return {};
    gateway = resolveDataGateway(config);
    const scope = accountScopeOf(gateway);
    const account = startThreadAccount(gateway, { ...input, dataDir: config.dataDir });
    if (scope === undefined) return {};
    if (account.accountKey === undefined)
      return account.pending ? { threadAccountPending: true } : {};
    const rootScopeKey = stampFor(gateway, sessionRootScopeKey(input.cwd), account.accountKey);
    return {
      ...(rootScopeKey === undefined ? {} : { rootScopeKey }),
      ...(account.basis === undefined ? {} : { accountBasis: account.basis }),
      admitAccount: { accountKey: account.accountKey, bindingHash: scope.bindingHash },
    };
  } catch {
    return {};
  } finally {
    await closeQuietly(gateway);
    try {
      pruneSessionAccountState(config.dataDir, input.nowMs);
    } catch {
      // Old state stays until the next session start.
    }
  }
}

/**
 * Stop: check the thread's login before the reconcile reads the log, so a login
 * change is on disk first. Opens no gateway on a machine that is not on a scoped
 * attachment. Never throws.
 */
export async function noteThreadAccount(
  config: PluginConfig,
  sessionId: string,
  transcriptPath: string,
  home?: string,
): Promise<void> {
  let gateway: DataGateway | undefined;
  try {
    if (readAccountScope(config) === undefined) return;
    gateway = resolveDataGateway(config);
    threadAccountKey(gateway, {
      dataDir: config.dataDir,
      sessionId,
      transcriptPath,
      nowMs: Date.now(),
      home,
    });
  } catch {
    // The next hook checks again.
  } finally {
    await closeQuietly(gateway);
  }
}

/**
 * The reconciler's stamper for one thread: each row's repository key, or the
 * thread's agent key when the session log, as it stood at the row's time, puts
 * the thread under the account its first rollout line names.
 */
export function codexLeafStamper(
  gateway: object,
  dataDir: string,
  sessionId: string,
  transcriptPath: string,
): LeafStamper {
  const repoOnly: LeafStamper = (repoKey) => repoKey;
  try {
    const scope = accountScopeOf(gateway);
    const head = readCodexHead(transcriptPath);
    const accountId = typeof head === 'object' ? head.creatorAccountId : undefined;
    if (scope === undefined || accountId === undefined) return repoOnly;
    const accountKey = chatgptKey(accountId);
    const hash = sessionAccountHash(accountKey);
    const lines = threadLog(dataDir, sessionId);
    return (repoKey, occurredAt) => {
      try {
        const at = Date.parse(occurredAt);
        if (!Number.isFinite(at)) return repoKey;
        const state = codexThreadState(
          lines.filter((line) => line.t <= at),
          scope.bindingHash,
        );
        return state.kind === 'started' && state.startHash === hash
          ? scope.stamp(repoKey, accountKey)
          : repoKey;
      } catch {
        return repoKey;
      }
    };
  } catch {
    return repoOnly;
  }
}
