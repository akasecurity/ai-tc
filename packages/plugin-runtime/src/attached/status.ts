import {
  bindingHashOf,
  codingScopeExtras,
  credentialDigestOf,
  enrollableRepoKey,
  managedScopedRefusal,
  readAttachedIdentity,
  readBoundAttachedIdentity,
  readControlPlaneCredentialFile,
  readWorkspaceSettings,
} from '@akasecurity/persistence';
import { readHookFailOpens } from '@akasecurity/plugin-sdk';
import type { AccountPlanState, ClaudeLoginPaths } from '@akasecurity/plugin-sdk/account';
import {
  accountContextFor,
  chatgptKey,
  claudeLoginCheck,
  codexEnvVetoed,
  inspectCodexLogin,
  isAccountMatch,
} from '@akasecurity/plugin-sdk/account';
import type {
  AccountBasis,
  AccountCheckReason,
  AttachedIdentity,
  AttachmentMode,
  AttachmentScope,
  AttachmentScopeEntry,
  ControlPlaneConnection,
  ManagedSettings,
  WebAccountProvider,
  WorkspaceSettings,
} from '@akasecurity/schema';
import {
  agentKey,
  ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX,
  attachedIdentityHolds,
  ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH,
  attachmentModeOf,
  controlPlaneName,
  historySyncChangesSince,
  isAttached,
  isAttachmentScopeValid,
  isHistorySyncConsentStale,
  isHistorySyncConsentValid,
  originOnly,
  parseAttachmentScope,
  parseWebAccountKey,
  resolveScope,
  WEB_ACCOUNT_PROVIDER,
  workSubscriptionsOn,
} from '@akasecurity/schema';

import { readForwardDrops } from './forward-drops.ts';
import type { ForwardFailureReason } from './forward-policy.ts';
import { readForwardHealth } from './forward-policy.ts';
import { readHistorySyncState } from './history-state.ts';
import { readUnsendableLabels } from './label-drops.ts';
import { createPolicyStore } from './policy-store.ts';
import type { PolicySyncOutcome } from './policy-sync.ts';
import { readPostureReportState } from './posture-report-state.ts';
import { readSyncState } from './sync-state.ts';

/**
 * What `/aka:status` prints about attached mode.
 *
 * NO NETWORK, EVER. No `pluginWhoami`, no call of any kind — a status renderer
 * that hangs for two seconds or throws when the control plane is down is the worst
 * possible first experience of attached mode, and "is my machine managed?" is
 * exactly the question a user asks WHEN something is wrong. Every field below is
 * read from disk. If identity from the control plane is ever wanted, it belongs behind
 * an explicit flag on `attach`, not here.
 *
 * Offline is the guarantee; PURE is not. `readAttachedConnection` can WRITE:
 * `repairOrRefuseMode` chmods a too-permissive `attached.json` back to 0600 on
 * sight. That is deliberate there — tightening beats stranding a legitimately
 * attached device, and a read is where a 0644 credential actually gets noticed —
 * but it means rendering status has a filesystem side effect, and nothing here
 * should be built on the assumption that it does not.
 *
 * ALLOW-LIST, NOT DENY-LIST. The renderer names the fields it prints, one by
 * one, rather than printing a record minus a redaction list. The connection
 * object holds `apiKey`; a deny-list satisfies today's redaction test and then
 * leaks the first field someone adds afterwards. `keyPrefix` — the non-secret
 * display half — is the only key-derived thing that is ever rendered, and it is
 * rendered because it was stored separately for that purpose.
 */

export interface RenderAttachedStatusDeps {
  /** The ~/.aka root, for reading settings. */
  base: string;
  settingsDir: string;
  dataDir: string;
  now?: () => number;
  /** Whether stdout is a terminal. Off one, the login reasons collapse to one line. */
  isTTY?: boolean | undefined;
  /** The administrator's overlay. `null` means unmanaged; absent reads the system paths. */
  managedSettings?: ManagedSettings | null | undefined;
  /** Where Claude Code keeps its login and settings files. Absent, no Claude Code login is read. */
  claudePaths?: ClaudeLoginPaths | undefined;
  /** The project whose Claude Code settings layers can veto the login. Defaults to the working directory. */
  cwd?: string | undefined;
  /**
   * Codex's home directory, whose login file the Codex line describes. `null`
   * asks for the line when the environment names no usable home: it reads as no
   * login file, or as an API key or another provider in use when a key, a token
   * or a gateway is set. Left out, no Codex login is read and the status has no
   * Codex line.
   */
  codexHome?: string | null | undefined;
}

/**
 * What to DO about a refusal — the two verdicts a human has to act on, and the
 * two whose remediations are NOT interchangeable.
 *
 * Shared by both halves of the block on purpose. Policy sync and event
 * forwarding fail on different routes and are recorded in different files, but
 * a 403 means the same thing on both, and the failure this whole surface exists
 * to prevent is a user being sent somewhere that cannot help.
 *
 * The distinction is the point:
 *
 *   401 — the credential is no longer accepted. `attach` mints a new one, and
 *         that fixes it. This is the wording the sync path has always had.
 *   403 — the credential IS accepted and is not permitted: a role demoted to
 *         read-only, an api-key scoped away from the route, a suspended account
 *         or member. Re-attaching mints a credential refused identically, so
 *         sending the user to `attach` would be a wrong instruction, not merely
 *         a vague one — they would do the work and land back here. Only someone
 *         who administers the organization can lift it, so that is who the line
 *         names.
 */
const REFUSAL_LINES: Record<'unauthorized' | 'forbidden', string> = {
  unauthorized: 'KEY REJECTED — re-attach with a valid plugin key',
  forbidden: 'ACCESS REFUSED — key is valid but not permitted; ask your org admin',
};

/** Human phrasing for each sync outcome. The two refusals are the ones that act. */
const OUTCOME_LINES: Record<PolicySyncOutcome, string> = {
  ok: 'policy synced',
  'not-modified': 'policy up to date',
  unauthorized: REFUSAL_LINES.unauthorized,
  forbidden: REFUSAL_LINES.forbidden,
  unreachable: 'control plane unreachable at last attempt',
  'invalid-bundle': 'control plane sent a policy bundle this build cannot read',
};

/**
 * How each attachment mode reads on the `mode` line: which activity the
 * attachment forwards, not everything the machine sends. The scoped line names
 * no kind of entry, because an entry may name a repository or an account and the
 * block under it lists whichever the record holds. An exhaustive Record, so a
 * mode added later fails typecheck here instead of rendering a line with a hole
 * in it.
 */
const MODE_LINES: Record<AttachmentMode, string> = {
  machine: 'machine (activity from anywhere on this machine)',
  scoped: 'scoped (activity from what is enrolled, and from work-subscription sessions)',
};

/**
 * What to do about a scope that forwards no activity: printed under the "nothing
 * enrolled yet" line (a record with no entries). The lines for a list that is
 * not stored spell out their own advice, and the lines for one this build cannot
 * read carry none.
 */
const ENROLL_HINT =
  '             (run `aka enroll` inside a work repository to add it, or `aka enroll --account <key>` for a work subscription this device does not recognise)';

/**
 * The `user` line when no identity record counts for this credential. What a
 * work subscription is recognised against is then unknown, so none is, and the
 * coding-agent keys derive from that record, so no Claude Code session is sent
 * for an account enrolled by hand either. Never the user's address: the record
 * holds only a digest of it. The plugin's background sync asks the deployment
 * which account the key belongs to, and asks again at later syncs until it has an
 * answer, which is what both lines wait for.
 */
const USER_LINES = {
  unknown:
    '  user       not known until this machine syncs — until then work subscriptions are not recognised and no Claude Code session is sent for an enrolled account',
  untied:
    '  user       not tied to this key — the next sync re-checks it; until then no Claude Code session is sent for a work subscription or an enrolled account',
} as const;

/**
 * What a learned work account forwards, by the provider its key names. An
 * exhaustive Record, so a provider added later fails typecheck here until its
 * coding agent's line is written.
 */
const WORK_ACCOUNT_REACH: Record<WebAccountProvider, string> = {
  [WEB_ACCOUNT_PROVIDER.Claude]: 'Claude Code sessions signed in to it forward from any folder',
  [WEB_ACCOUNT_PROVIDER.ChatGpt]: 'new Codex threads signed in to it forward from any folder',
};

/** The commands that turn work-subscription recognition off and back on, as every surface prints them. */
export const WORK_SUBSCRIPTION_COMMANDS = {
  off: 'aka unenroll --work-subscriptions',
  on: 'aka enroll --work-subscriptions',
} as const;

/**
 * The `work` line, by whether recognition is on, each naming the command that
 * changes it, on a personal device whose connection nobody manages.
 */
const WORK_LINES = {
  on: `  work       subscriptions on — \`${WORK_SUBSCRIPTION_COMMANDS.off}\` turns them off on this device`,
  off: `  work       subscriptions off — you turned them off; \`${WORK_SUBSCRIPTION_COMMANDS.on}\` turns them back on`,
} as const;

/**
 * What follows "on" or "off" on a scoped device whose connection an
 * administrator now manages. Both commands refuse there, so none is named.
 */
const WORK_LINE_FIXED =
  "— fixed while an administrator manages this machine's connection; re-attaching makes it machine-wide";

/** The one line a machine-wide attachment gains when an administrator manages its connection. */
const MANAGED_MACHINE_LINE =
  "  personal device  not available — an administrator manages this machine's connection, so it is attached machine-wide and there is no work-subscription opt-out";

/** The this-login block off a terminal: no reason and no key. */
const THIS_LOGIN_COLLAPSED = '  this login details on an interactive terminal';

/** What the Claude Code login signed in now is, as `aka status` and `aka enroll --list-detected` show it. */
export type ClaudeCodeLoginState =
  | 'manual'
  | 'remembered'
  | 'would-validate'
  | 'off'
  | 'cap-reached'
  | 'email'
  | 'plan'
  | 'plan-unconfirmed'
  | 'plan-stale'
  | 'env-mismatch'
  | 'veto'
  | 'attached-user-unknown'
  | 'signed-out'
  | 'absent'
  | 'unreadable';

export interface ClaudeCodeLoginView {
  /** The login's account key, for the user's own terminal; undefined with no organization. */
  readonly key: string | undefined;
  readonly planState: AccountPlanState | undefined;
  readonly state: ClaudeCodeLoginState;
}

export interface ClaudeCodeLoginViewInput {
  /** The identity record, only when it holds for this endpoint and credential. */
  readonly identity: AttachedIdentity | undefined;
  /** The stored `attachmentScope`, raw. */
  readonly scope: unknown;
  readonly endpoint: string;
  /** The project whose Claude Code settings layers can veto the login. */
  readonly cwd: string;
  readonly paths: ClaudeLoginPaths;
}

const FORWARDS = 'a work subscription for the attached user — its sessions forward from any folder';

/**
 * The this-login reason for each state, given the key as it prints. An
 * exhaustive Record, so a state added later fails typecheck here.
 */
const CLAUDE_CODE_LOGIN_LINES: Record<ClaudeCodeLoginState, (key: string) => string> = {
  manual: () => 'an account you enrolled by hand — its sessions forward from any folder',
  remembered: () => FORWARDS,
  'would-validate': () => FORWARDS,
  off: () =>
    'a work subscription for the attached user — not sent, because work subscriptions are off on this device',
  'cap-reached': () =>
    `a work subscription for the attached user — not sent, because this device already recognises ${String(ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX)} work accounts`,
  email: () => 'signed in with a different email than the AKA user who attached this device',
  plan: () => 'personal plan — sessions follow the repository rule',
  'plan-unconfirmed': (key) =>
    `plan not confirmed by Claude Code — run \`aka enroll --account ${key}\` if this is a work subscription`,
  'plan-stale': (key) =>
    `plan not confirmed for this organization — run \`aka enroll --account ${key}\` if this is a work subscription`,
  'env-mismatch': () =>
    "the desktop app names another login than Claude Code's login file — sessions follow the repository rule",
  veto: () => 'an API key or another provider is in use',
  'attached-user-unknown': () =>
    'not checked — this device does not know yet which AKA user attached it',
  'signed-out': () => 'not signed in to a Claude account',
  absent: () => 'login file not found',
  unreadable: () => 'login file could not be read',
};

/** A login that counts, by the basis it would count on. */
const MATCH_STATE_OF: Record<AccountBasis, ClaudeCodeLoginState> = {
  manual: 'manual',
  remembered: 'remembered',
  validated: 'would-validate',
};

/**
 * Each reason a check can give, as the state shown. The login-level check
 * compares the login with its own organization and reads no Codex file, so a
 * session's reasons and Codex's never reach here; they read as unreadable.
 */
const LOGIN_STATE_OF: Record<AccountCheckReason, ClaudeCodeLoginState> = {
  'no-session-account': 'signed-out',
  veto: 'veto',
  unreadable: 'unreadable',
  'env-mismatch': 'env-mismatch',
  'login-changed': 'unreadable',
  'org-changed': 'unreadable',
  email: 'email',
  plan: 'plan',
  'plan-unconfirmed': 'plan-unconfirmed',
  'plan-stale': 'plan-stale',
  'attached-user-unknown': 'attached-user-unknown',
  'opted-out': 'off',
  resumed: 'unreadable',
  provider: 'veto',
  absent: 'absent',
  mode: 'unreadable',
  malformed: 'unreadable',
  'account-mismatch': 'unreadable',
  'auth-changed': 'unreadable',
  'cap-reached': 'cap-reached',
};

/**
 * The Claude Code login signed in now, checked on demand through the readers
 * the hooks use: the login file, the settings layers and the environment, never
 * a transcript, and no network. Persists nothing. On an opted-out device a login
 * that would count reads as `off`. Without an identity record that holds, the
 * key and the plan state are still given. Never throws.
 */
export function claudeCodeLoginView(input: ClaudeCodeLoginViewInput): ClaudeCodeLoginView {
  try {
    const { identity } = input;
    const ctx = accountContextFor({
      identity,
      scope: input.scope,
      bindingHash:
        identity === undefined
          ? ''
          : bindingHashOf(input.endpoint, identity.credentialDigest, identity.attachedUserDigest),
      inScope: () => false,
    });
    const report = claudeLoginCheck({ ctx, cwd: input.cwd, paths: input.paths });
    const shown = { key: report.key, planState: report.planState };
    if (report.key === undefined && !report.found) return { ...shown, state: 'absent' };
    if (isAccountMatch(report.check)) {
      return { ...shown, state: MATCH_STATE_OF[report.check.basis] };
    }
    if (report.check.none !== 'opted-out' || ctx === undefined) {
      return { ...shown, state: LOGIN_STATE_OF[report.check.none] };
    }
    // Off on this device: say whether the login would count were it on.
    const on = claudeLoginCheck({
      ctx: { ...ctx, workSubscriptionsOn: true },
      cwd: input.cwd,
      paths: input.paths,
    });
    return { ...shown, state: isAccountMatch(on.check) ? 'off' : LOGIN_STATE_OF[on.check.none] };
  } catch {
    return { key: undefined, planState: undefined, state: 'unreadable' };
  }
}

/** The Claude Code this-login line. The key prints on the user's own terminal, as `aka enroll --list` prints it. */
function claudeCodeLoginLine(view: ClaudeCodeLoginView): string {
  const key =
    view.key === undefined
      ? 'claude:<organization-id>'
      : printableForTerminal(view.key, ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH);
  return `Claude Code — ${CLAUDE_CODE_LOGIN_LINES[view.state](key)}`;
}

/** What the Codex login signed in now is, as `aka status` and `aka enroll --list-detected` show it. */
export type CodexLoginState =
  | 'manual'
  | 'remembered'
  | 'would-validate'
  | 'off'
  | 'cap-reached'
  | 'email'
  | 'plan'
  | 'plan-unconfirmed'
  | 'veto'
  | 'attached-user-unknown'
  | 'absent'
  | 'unreadable';

export interface CodexLoginView {
  /** The login's workspace key, for the user's own terminal; undefined when no login is named. */
  readonly key: string | undefined;
  readonly planState: AccountPlanState | undefined;
  readonly state: CodexLoginState;
}

export interface CodexLoginViewInput {
  /** The identity record, only when it holds for this endpoint and credential. */
  readonly identity: AttachedIdentity | undefined;
  /** The stored `attachmentScope`, raw. */
  readonly scope: unknown;
  readonly endpoint: string;
  /** Codex's home directory. Without one no login file is read. */
  readonly codexHome: string | undefined;
}

/**
 * The Codex login signed in now, checked the way a new thread would be, without a
 * thread: the same login reader, the address compared by digest, the plan read as
 * a state.
 *
 * The login file is read before the environment can veto it, so a login that was
 * read is named by its key and plan state under a key, a token or a gateway too,
 * and before the device knows who attached it, so `aka enroll` can ask about a
 * personal plan before the first sync. What each case reads as:
 * - no usable Codex home, or no login file under it, with no key, token or gateway
 *   set: `absent`, naming nothing;
 * - a file that is not a ChatGPT login this device can read, with none set:
 *   `unreadable`, naming nothing;
 * - either of those with a key, a token or a gateway set: `veto`, naming nothing;
 * - a login with a key, a token or a gateway set: `veto`, naming its key and plan
 *   state;
 * - a login with none set: the state the checks described next give, naming its
 *   key and plan state;
 * - a read that throws, whatever is set: `unreadable`, naming nothing.
 *
 * An account enrolled by hand counts before the address and the plan are
 * compared. Those two are compared before the opt-out, so a personal plan reads as
 * one whether or not the user opted out; the opt-out is compared before the cap on
 * recognised accounts, so with recognition off a login that would otherwise be
 * over the cap reads as `off`. Persists nothing. Never throws.
 */
export function codexLoginView(input: CodexLoginViewInput): CodexLoginView {
  const unnamed = (state: CodexLoginState): CodexLoginView => ({
    key: undefined,
    planState: undefined,
    state,
  });
  try {
    const vetoed = codexEnvVetoed();
    const read =
      input.codexHome === undefined
        ? undefined
        : inspectCodexLogin(input.codexHome, input.identity?.attachedUserDigest);
    if (read?.status !== 'ok') {
      if (vetoed) return unnamed('veto');
      return unnamed(read === undefined || read.status === 'absent' ? 'absent' : 'unreadable');
    }
    const { login } = read;
    const key = chatgptKey(login.accountId);
    const named = (state: CodexLoginState): CodexLoginView => ({
      key,
      planState: login.planState,
      state,
    });
    if (vetoed) return named('veto');
    if (input.identity === undefined) return named('attached-user-unknown');
    if (manualCodingKeys(input.scope, input.endpoint).has(key)) return named('manual');
    if (!login.emailMatchesAttached) return named('email');
    if (login.planState === 'other') return named('plan');
    const learned = input.identity.workAccounts.map((entry) => entry.identity);
    const on = workSubscriptionsOn(input.scope);
    if (learned.includes(key)) return named(on ? 'remembered' : 'off');
    if (login.planState === 'absent') return named('plan-unconfirmed');
    if (!on) return named('off');
    if (learned.length >= ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX) return named('cap-reached');
    return named('would-validate');
  } catch {
    return unnamed('unreadable');
  }
}

/** The account keys enrolled by hand for coding-agent sessions on this deployment. */
function manualCodingKeys(scope: unknown, endpoint: string): Set<string> {
  const record = parseAttachmentScope(scope);
  if (record === undefined || !isAttachmentScopeValid(scope, endpoint)) return new Set();
  return new Set(
    record.entries
      .filter((entry) => entry.kind === 'account' && entry.codingAgents === true)
      .map((entry) => entry.identity),
  );
}

const CODEX_FORWARDS =
  'a work subscription for the attached user — its new threads forward from any folder';

/**
 * The this-login reason for each Codex state, given the key as it prints. An
 * exhaustive Record, so a state added later fails typecheck here.
 */
const CODEX_LOGIN_LINES: Record<CodexLoginState, (key: string) => string> = {
  manual: () => 'an account you enrolled by hand — its new threads forward from any folder',
  remembered: () => CODEX_FORWARDS,
  'would-validate': () => CODEX_FORWARDS,
  off: () =>
    'a work subscription for the attached user — not sent, because work subscriptions are off on this device',
  'cap-reached': () =>
    `a work subscription, but this device already recognises ${String(ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX)} — threads follow the repository rule`,
  email: () => 'signed in with a different email than the AKA user who attached this device',
  plan: () => 'not a ChatGPT workspace plan — threads follow the repository rule',
  'plan-unconfirmed': (key) =>
    `plan not shown in Codex's login — run \`aka enroll --account ${key}\` if this is a work subscription`,
  veto: () => 'an API key or another provider is in use',
  'attached-user-unknown': () => 'not checked until this machine syncs',
  absent: () => 'login file not found',
  unreadable: () => 'not a ChatGPT login this device can read',
};

/** The Codex this-login line. The key prints on the user's own terminal, as the Claude Code line prints its key. */
function codexLoginLine(view: CodexLoginView): string {
  const key =
    view.key === undefined
      ? 'chatgpt:<workspace-id>'
      : printableForTerminal(view.key, ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH);
  return `Codex — ${CODEX_LOGIN_LINES[view.state](key)}`;
}

/**
 * The this-login block: one line per coding agent under one label, or the
 * collapsed line off a terminal, and nothing when no login was read.
 */
function thisLoginLines(isTTY: boolean, hostLines: readonly string[]): string[] {
  if (hostLines.length === 0) return [];
  if (!isTTY) return [THIS_LOGIN_COLLAPSED];
  return hostLines.map((line, at) => `${at === 0 ? '  this login ' : '             '}${line}`);
}

/**
 * The last line of every scope block: what the record does not limit. A scoped
 * attachment's record decides which activity is forwarded, not whether the
 * machine pulls its deployment's policy, checks it for device commands or sends
 * it a device report.
 */
const NOT_LIMITED_LINE =
  '             the policy pull, the command check and the device report are not limited to what is enrolled';

/**
 * The note under a SCOPED machine's history numbers when the pass that wrote
 * them counted everything recorded on this machine, keyed on what that pass
 * recorded about its counts: nothing at all (a version of aka from before passes
 * recorded it, whose drain counted the whole machine in either mode), or a
 * machine-wide count (a pass that ran while this machine was attached
 * machine-wide, kept by a re-attach that made it scoped). An exhaustive Record,
 * so a mode added later fails typecheck here instead of printing no note.
 */
const WIDE_COUNTS_NOTES: Record<'unmarked' | Exclude<AttachmentMode, 'scoped'>, string> = {
  unmarked:
    '             (counted by an older version of aka, for everything recorded on this machine)',
  machine:
    '             (counted while attached machine-wide, for everything recorded on this machine)',
};

/**
 * The note under a MACHINE-WIDE attachment's history numbers when a scoped pass
 * wrote them: a re-attach that made the machine machine-wide kept the file (only
 * a detach removes it), so its totals cover only what was enrolled and would
 * read as the whole machine's. It goes once a pass runs and counts everything.
 */
const SCOPED_COUNTS_NOTE: readonly string[] = [
  '             (counted while attached as a personal device, for what was enrolled only;',
  '             the next pass counts everything recorded on this machine)',
];

/**
 * The note, if any, that goes under the history numbers: keyed on the live mode
 * and on what the pass that wrote the file says it counted. A machine-wide
 * attachment prints a note for one marker only, the scoped one; with none, or
 * the machine-wide one, its lines are as they always were.
 */
function countsNote(scoped: boolean, countedAs: AttachmentMode | undefined): readonly string[] {
  if (scoped) return countedAs === 'scoped' ? [] : [WIDE_COUNTS_NOTES[countedAs ?? 'unmarked']];
  return countedAs === 'scoped' ? SCOPED_COUNTS_NOTE : [];
}

function ageLine(fromMs: number, nowMs: number): string {
  const deltaMs = Math.max(0, nowMs - fromMs);
  const minutes = Math.floor(deltaMs / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${String(minutes)}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${String(hours)}h ago`;
  return `${String(Math.floor(hours / 24))}d ago`;
}

/**
 * Render the block, offline. Never throws — the same fail-open contract as the
 * rest of the package, because this runs inside a slash-command entry.
 *
 * The NOT-ATTACHED block covers all three negative cases identically on purpose:
 * file absent, file present but unparseable, and unknown `specVersion` all mean
 * "this device is not managed", and distinguishing them in the output would
 * describe the contents of a file the reader is not otherwise shown.
 */
export function renderAttachedStatus(deps: RenderAttachedStatusDeps): string {
  try {
    const nowMs = (deps.now ?? (() => Date.now()))();
    const settings = readWorkspaceSettings(deps.base);
    if (!isAttached(settings) || settings.controlPlane === undefined) {
      return [
        'AKA: standalone (not attached)',
        '  no control plane configured',
        ...failOpenLines(deps.dataDir, nowMs),
      ].join('\n');
    }
    const connection = settings.controlPlane;
    // The WIDE read: this block prints `keyPrefix`, which the narrow state
    // deliberately does not carry. It is a TERMINAL surface — `aka status` — so
    // nothing here crosses to a browser.
    const state = readControlPlaneCredentialFile(deps.settingsDir, connection);
    // The mode is read off the credential, the half of an attachment no settings
    // writer rewrites, and only off one this machine can use. An unusable
    // credential forwards nothing in either mode, so naming a mode for it would
    // describe forwarding that does not happen.
    const mode: AttachmentMode | undefined = state.usable
      ? attachmentModeOf(state.credential)
      : undefined;
    const plane = deploymentNameForTerminal(connection);
    // Whether an administrator manages this machine's connection. Such a machine
    // attaches machine-wide only, and a scoped device that became managed keeps
    // its stored choice, which neither command may change, until it is re-attached.
    const managed =
      mode !== undefined && managedScopedRefusal(deps.base, deps.managedSettings) !== null;
    // The coding-agent keys a scoped attachment forwards beside its stored
    // entries, from the identity record bound to this credential, and what the
    // block says about them. Read only for a scoped credential: a machine-wide
    // attachment consults no identity record.
    const extras =
      state.usable && mode === 'scoped'
        ? codingScopeExtras(deps.dataDir, settings, state.credential)
        : [];
    const work =
      state.usable && mode === 'scoped'
        ? workSubscriptionLines(
            deps.dataDir,
            settings,
            connection.endpoint,
            credentialDigestOf(state.credential.apiKey),
            extras,
            managed,
          )
        : undefined;
    // Who a login is compared with: the identity record, only when it holds for
    // this credential.
    const heldIdentity =
      state.usable && mode === 'scoped'
        ? readBoundAttachedIdentity(deps.dataDir, connection.endpoint, state.credential)
        : undefined;
    // One line per coding agent whose login the caller asked to have read.
    const loginLines: string[] = [];
    if (work !== undefined && deps.claudePaths !== undefined) {
      loginLines.push(
        claudeCodeLoginLine(
          claudeCodeLoginView({
            identity: heldIdentity,
            scope: settings.attachmentScope,
            endpoint: connection.endpoint,
            cwd: deps.cwd ?? process.cwd(),
            paths: deps.claudePaths,
          }),
        ),
      );
    }
    if (work !== undefined && deps.codexHome !== undefined) {
      loginLines.push(
        codexLoginLine(
          codexLoginView({
            identity: heldIdentity,
            scope: settings.attachmentScope,
            endpoint: connection.endpoint,
            codexHome: deps.codexHome ?? undefined,
          }),
        ),
      );
    }
    const thisLogin = thisLoginLines(deps.isTTY === true, loginLines);

    const lines = [
      // The mismatch case earns its own headline. An administrator can repoint
      // `controlPlane` across a fleet and cannot write the credential file, so
      // this is an ordinary migration rather than a fault — and reporting it as
      // a bare "not attached" would send every affected user looking for a file
      // that is present and intact.
      state.usable
        ? 'AKA: attached'
        : state.reason === 'endpoint-mismatch'
          ? 'AKA: attached — credential is for another deployment, re-attach'
          : 'AKA: attached — no usable credential, re-attach',
      // ALLOW-LISTED, field by field. The credential itself is deliberately
      // absent and must stay that way; `keyPrefix` is the non-secret half.
      //
      // And every one of them goes through `printableForTerminal`, which is
      // about the field's CONTENT rather than which fields appear. The
      // allow-list above decides what is rendered; it says nothing about what
      // those strings hold. None of these is authored by this machine — `label`
      // comes from `aka attach --label` or from a `settings.json` an
      // administrator can pin fleet-wide, and the endpoint and `keyPrefix` come
      // off the credential file — and all of them land in a status block a user
      // reads to decide whether their machine is managed. An ANSI escape in any
      // of them can repaint that block or hide a line.
      `  plane      ${plane}`,
      `  attached   ${printableForTerminal(connection.attachedAt, 40)}`,
    ];
    if (state.usable && state.credential.keyPrefix !== undefined) {
      // `max` matches the schema's own bound, so a conforming prefix is never
      // truncated and a longer one cannot outrun it.
      lines.push(`  key        ${printableForTerminal(state.credential.keyPrefix, 16)}…`);
    }
    if (!state.usable && state.reason === 'endpoint-mismatch') {
      lines.push(`  credential ${printableForTerminal(state.credentialEndpoint, 200)}`);
    }
    if (mode !== undefined) lines.push(`  mode       ${MODE_LINES[mode]}`);
    if (mode === 'machine' && managed) lines.push(MANAGED_MACHINE_LINE);
    // With a label, `plane` names the label. The scope record is bound to the
    // endpoint by exact string, so the endpoint gets its own line and a user can
    // compare it with the one a record names. Without a label, `plane` is it.
    if (mode !== undefined && connection.label !== undefined) {
      lines.push(`  endpoint   ${printableForTerminal(connection.endpoint, 200)}`);
    }

    return [
      ...lines,
      // Only a scoped attachment is filtered by its scope. A machine-wide one
      // never reads the record, so listing it there would describe a filter
      // that is not applied. The work lines come first, so the scope block
      // still ends with what the record does not limit.
      ...(work === undefined
        ? []
        : [
            ...work,
            ...thisLogin,
            ...attachmentScopeLines(settings.attachmentScope, connection.endpoint),
          ]),
      ...policyLines(deps.dataDir, nowMs),
      ...forwardLines(deps.dataDir, nowMs),
      ...postureLines(deps.dataDir, nowMs),
      ...historyLines(
        deps.dataDir,
        settings,
        connection.endpoint,
        nowMs,
        mode === 'scoped',
        extras,
      ),
      ...failOpenLines(deps.dataDir, nowMs),
    ].join('\n');
  } catch {
    // A status renderer that throws is worse than one that says little.
    return 'AKA: status unavailable';
  }
}

/**
 * The enrolled scope of a SCOPED attachment, as `aka status` prints it.
 *
 * Exported so any command that lists the enrolled scope prints these same lines
 * rather than a second rendering of the same states, which could disagree with
 * this one.
 *
 * THE FORWARD VERDICT'S OWN READ. The record is read with parseAttachmentScope
 * and bound with isAttachmentScopeValid, the two halves resolveScope is built
 * from, and an entry is listed only when the key set resolveScope returns holds
 * its identity. So the block lists what a forward path forwards, once per
 * identity however often it is stored.
 *
 * WHAT IT DOES NOT LIST. The block reads the stored record alone. The forward
 * paths also add coding-agent keys to the key set (`codingScopeExtras`), which
 * never live in settings.json: one per work account the device recognised, and
 * one per account enrolled by hand for coding sessions. `aka status` lists the
 * recognised ones above this block. Whether recognition is on (the record's own
 * `workSubscriptions` field, through `workSubscriptionsOn`) is what the
 * headlines read, so while it is on a block that enrolls little or nothing does
 * not call local the sessions a recognised work subscription forwards. An
 * account enrolled by hand is a stored entry, and is listed here like any other.
 *
 * Each state that forwards no activity has its own line, because each has its own
 * cause: no list stored (an older settings writer dropped it, or an attach
 * stopped before writing it), a list this version cannot read (damaged, or
 * written by a newer build), a record for another deployment, or a record with
 * nothing in it yet. The first two are told apart on purpose: the missing list
 * says what to run, and the unreadable one deliberately gives no advice. Entries
 * this version cannot read are counted and never printed: one written by a newer
 * build is not this build's to describe. A record that names no account is said
 * to be one, because the next scoped attach cannot tell whose it is and starts it
 * empty.
 *
 * EVERY BLOCK ENDS WITH WHAT THE RECORD DOES NOT LIMIT. The record decides which
 * activity is forwarded, not whether the machine pulls its deployment's policy,
 * checks it for device commands or sends it a device report. So the last line
 * says so in every state, and a block that says no activity is sent does not read
 * as a machine that sends nothing.
 *
 * Every stored string goes through printableForTerminal. The schema already
 * refuses control characters in an identity or a label; the strip is the layer
 * that holds whatever a settings file actually carries. The record's address
 * goes through endpointForTerminal, which also keeps userinfo, a query or a
 * fragment off the screen.
 *
 * `endpoint` is the deployment the machine is attached to now.
 *
 * PURE: `staleKeyNote` reaches `enrollableRepoKey`, which is string reduction
 * and reads nothing. It must stay that way — the identity reduction is on a
 * path the dashboard's build compiles, and a file read reached from it breaks
 * the Windows binary build (see Architecture principles §8).
 */
export function attachmentScopeLines(raw: unknown, endpoint: string): string[] {
  return [...scopeStateLines(raw, endpoint), NOT_LIMITED_LINE];
}

/** What a scope that enrolls nothing still sends: nothing, or a recognised work subscription's sessions. */
function nothingEnrolledSends(forwardsWork: boolean): string {
  return forwardsWork
    ? 'only sessions signed in to a recognised work subscription are sent'
    : 'no activity is sent';
}

/** The lines for the record's state, before the line every block ends with. */
function scopeStateLines(raw: unknown, endpoint: string): string[] {
  const forwardsWork = workSubscriptionsOn(raw);
  // No list at all and a list this build cannot read are told apart before
  // anything is parsed: parseAttachmentScope answers undefined for both, and
  // what to do about one is not what to do about the other.
  if (raw === undefined || raw === null) {
    return [
      `  scope      no enrolled list is stored — ${nothingEnrolledSends(forwardsWork)}`,
      '             (run `aka enroll` inside a work repository to add it; an aka older than 0.9.16 also',
      '             drops the list when it saves settings)',
    ];
  }
  const record = parseAttachmentScope(raw);
  if (record === undefined) {
    return [
      `  scope      the enrolled list cannot be read by this aka — ${nothingEnrolledSends(forwardsWork)}`,
      '             (it may have been written by a newer aka)',
    ];
  }
  if (!isAttachmentScopeValid(raw, endpoint)) {
    return [
      `  scope      recorded for another deployment (${endpointForTerminal(record.endpoint)})`,
      `             — ${nothingEnrolledSends(forwardsWork)} here (run \`aka enroll\` to enroll for this one)`,
    ];
  }
  const forwarded = resolveScope({ mode: 'scoped', scope: raw, endpoint }).keys;
  const listed = new Set<string>();
  const rows: string[] = [];
  for (const entry of record.entries) {
    // The filter is redundant while resolveScope keeps every parsed entry. It stays
    // as the literal form of "listed only when the verdict's key set holds the
    // identity", so this block stays honest if resolveScope ever filters. It sees
    // the stored record only, not the coding-agent keys (see the note above).
    if (!forwarded.has(entry.identity) || listed.has(entry.identity)) continue;
    listed.add(entry.identity);
    rows.push(`             ${entryLine(entry)}${staleKeyNote(entry)}`);
  }
  const lines =
    rows.length === 0
      ? [`  scope      nothing enrolled yet — ${nothingEnrolledSends(forwardsWork)}`, ENROLL_HINT]
      : [
          forwardsWork
            ? `  scope      ${count(rows.length)} enrolled — anything else stays on this machine, except sessions signed in to a recognised work subscription`
            : `  scope      ${count(rows.length)} enrolled — activity anywhere else stays on this machine`,
          ...rows,
        ];
  const unread = unreadEntries(raw, record);
  if (unread > 0) {
    const noun = unread === 1 ? 'entry' : 'entries';
    lines.push(`             ${count(unread)} ${noun} this version cannot read — not sent`);
  }
  if (!named(record.tenantName) || !named(record.userEmail)) {
    lines.push('             not tied to an account — the next `aka attach` starts it empty');
  }
  return lines;
}

/**
 * The note an enrolled REPOSITORY key carries when it is not a key any checkout
 * on this machine now stamps.
 *
 * Enrolment is matched byte for byte (`scopeVerdict` is a set lookup), so an
 * entry stored under a spelling the canonical rules no longer produce enrols
 * nothing — while still being listed as an enrolment. That is the silent shape
 * Architecture principles §8 exists to end, and it is reachable: a key stored
 * before the path-case rule landed can read as enrolled for ever while that
 * repository forwards none of its activity.
 *
 * This REPORTS what `respellStoredEnrolments` cannot repair, and the two divide
 * cleanly: the sweep re-keys every spelling that converges, and what is left is
 * a spelling no rule can work out an answer for — an owner's page, or an
 * identity carrying a transport. Those get this note and the one command that
 * fixes them.
 *
 * `enrollableRepoKey` answers what the current rules accept, so an identity
 * that is not its own answer is one no checkout produces. An ACCOUNT key is not
 * a repository key and is left alone. Fail-open: a throw says nothing rather
 * than marking a healthy entry.
 */
function staleKeyNote(entry: AttachmentScopeEntry): string {
  try {
    if (entry.kind !== 'repo') return '';
    return enrollableRepoKey(entry.identity) === entry.identity
      ? ''
      : ' — NOT a key this machine now stamps; re-run `aka enroll` in its checkout';
  } catch {
    return '';
  }
}

/** One enrolled identity: its key, its label when it has one, the day it was enrolled, and what an account covers. */
function entryLine(entry: AttachmentScopeEntry): string {
  // `max` is the schema's own bound on an identity, so a conforming key is never cut.
  const identity = printableForTerminal(entry.identity, ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH);
  const label = entry.label === undefined ? '' : ` (${printableForTerminal(entry.label)})`;
  const enrolled = printableForTerminal(entry.enrolledAt.slice(0, 10));
  return `${identity}${label}, enrolled ${enrolled}${codingCoverage(entry, identity)}`;
}

/**
 * What a claude.ai account entry covers: Claude Code sessions too when it
 * carries the coding-agent marker, and its chats alone when it does not.
 */
function codingCoverage(entry: AttachmentScopeEntry, shown: string): string {
  const provider =
    entry.kind === 'account' ? parseWebAccountKey(entry.identity)?.provider : undefined;
  if (provider !== WEB_ACCOUNT_PROVIDER.Claude) return '';
  return entry.codingAgents === true
    ? ' — covers Claude Code sessions'
    : ` — claude.ai chats only — run \`aka enroll --account ${shown}\` again to include Claude Code sessions`;
}

/** How many stored entries validation dropped from a record that itself parsed. */
function unreadEntries(raw: unknown, read: AttachmentScope): number {
  const stored =
    typeof raw === 'object' && raw !== null && 'entries' in raw && Array.isArray(raw.entries)
      ? raw.entries.length
      : read.entries.length;
  return stored - read.entries.length;
}

/** A binding field that names someone: present and not empty. */
function named(value: string | undefined): boolean {
  return value !== undefined && value !== '';
}

/**
 * What a SCOPED attachment says about work subscriptions, above its enrolled
 * list: whether it knows the AKA user who attached it, whether recognition is
 * on, and each work account it recognised whose sessions it forwards.
 *
 * The user is known only from an identity record bound to the credential in
 * force (`attachedIdentityHolds`), the check every reader of the record makes,
 * so this line cannot call a record known that the forward paths ignore. A
 * record bound to another key is said to be one, apart from no record at all.
 *
 * Recognition is on unless the scope record turns it off (`workSubscriptionsOn`):
 * no field is on, and any stored value is off. On a scoped device whose
 * connection an administrator now manages, the line says the choice is fixed and
 * names no command, since both refuse there.
 *
 * A learned account is listed only while its agent key is among `extras`, the
 * keys the forward paths add to the scope, so the list is what is forwarded. Its
 * key prints the way `aka enroll --account` takes it. The agent key, the scope
 * tag and the record's digests never print.
 *
 * Reads the identity record; never throws.
 */
function workSubscriptionLines(
  dataDir: string,
  settings: WorkspaceSettings,
  endpoint: string,
  credentialDigest: string,
  extras: readonly AttachmentScopeEntry[],
  managed: boolean,
): string[] {
  try {
    const record = readAttachedIdentity(dataDir);
    const bound =
      record !== undefined &&
      attachedIdentityHolds(record, { endpoint, credentialDigest, mode: 'scoped' })
        ? record
        : undefined;
    const on = workSubscriptionsOn(settings.attachmentScope);
    const lines = [
      bound !== undefined
        ? `  user       the AKA user who attached this device is known (checked ${printableForTerminal(bound.checkedAt.slice(0, 10))})`
        : record === undefined
          ? USER_LINES.unknown
          : USER_LINES.untied,
      workLine(on, managed),
    ];
    if (bound === undefined || !on) return lines;
    const forwarded = new Set(extras.map((entry) => entry.identity));
    const learned = bound.workAccounts.filter((entry) => {
      const key = agentKey(bound.scopeTag, entry.identity);
      return key !== undefined && forwarded.has(key);
    });
    if (learned.length > 0) {
      const noun = learned.length === 1 ? 'account' : 'accounts';
      lines.push(`             ${count(learned.length)} work ${noun} validated automatically:`);
      for (const entry of learned) {
        const provider = parseWebAccountKey(entry.identity)?.provider;
        const reach = provider === undefined ? '' : ` — ${WORK_ACCOUNT_REACH[provider]}`;
        lines.push(
          `             ${printableForTerminal(entry.identity, ATTACHMENT_SCOPE_IDENTITY_MAX_LENGTH)}` +
            ` (validated ${printableForTerminal(entry.enrolledAt.slice(0, 10))})${reach}`,
        );
      }
    }
    return lines;
  } catch {
    return [USER_LINES.unknown];
  }
}

/** The `work` line: on or off, with the command that changes it, or why none can. */
function workLine(on: boolean, managed: boolean): string {
  if (managed) return `  work       subscriptions ${on ? 'on' : 'off'} ${WORK_LINE_FIXED}`;
  return on ? WORK_LINES.on : WORK_LINES.off;
}

/**
 * Policy freshness and the last sync outcome.
 *
 * Separate from the connection block because the two answer different
 * questions — "is this device managed" and "is its policy current" — and a
 * device can be soundly attached with no policy yet, which is the state a fresh
 * attach leaves behind for one session by design.
 */
function policyLines(dataDir: string, nowMs: number): string[] {
  const lines: string[] = [];
  const state = readSyncState(dataDir);
  if (state) {
    lines.push(`  sync       ${OUTCOME_LINES[state.outcome]} (${ageLine(state.atMs, nowMs)})`);
  } else {
    lines.push('  sync       no attempt recorded yet');
  }
  return lines;
}

/**
 * Whether this device is still REPORTING — the other half of "is my machine
 * managed", and the half status used to answer by implication.
 *
 * Policy sync and event forwarding are different requests against different
 * routes, and they can diverge for one credential: `GET /v1/policy-bundle` is a
 * read and carries no write-role guard, while the ingest routes do. Demote an
 * attached device's owner to a read-only role and sync keeps returning 200 —
 * so the sync line above renders `policy synced (just now)` — while every
 * forward 403s. `forward.run` returns rather than throws on each of those (G1:
 * the local write already succeeded and the caller must return it), and its six
 * discarding call sites still discard them — so the breaker's own file is the
 * only thing that outlives the refusal, and the breaker then makes the silence
 * steady: three failures, open, one probe per cooldown.
 *
 * Which is why this reads a file rather than being plumbed a value.
 * `forward-policy.ts` persists the failure count, the breaker stamp and the
 * classified cause into the SAME `dataDir` the sync state is read from, and the
 * process that observed the refusal exited long before anyone ran `/aka:status`.
 * Read strictly read-only, since a status command must never open, close or
 * re-stamp the breaker it is describing.
 *
 * It names a CAUSE only for the two statuses that carry one. `run()` classifies
 * its failure before dropping it and records the classification beside the
 * count, so a 401 and a 403 arrive here as themselves — and the demotion above
 * now renders the remediation that actually applies instead of the one that
 * sends the user to `attach` to mint a credential refused identically. Every
 * other failure — a timeout, a refused connection, a 500 — lands in the
 * `unreachable` bucket, and for those the block still says what it observed and
 * stops. That silence is deliberate rather than residual: the count and the
 * stamp are facts, and a cause guessed from them would be the same kind of
 * overstatement as the clean block this whole surface replaced.
 */
/**
 * What the live forward gave up on, if anything.
 *
 * Rendered INDEPENDENTLY of breaker state, and that is the whole reason it
 * exists for its original cause: the machine a batch-budget drop happens on
 * is the one whose breaker is closed. A plane that answers every request
 * successfully but slowly produces no failures, so every other line in this
 * block reads healthy while the tail of each batch is discarded. Appended to
 * all three of `forwardLines`' outcomes rather than to one — the second cause
 * `forward-drops.ts` now also counts (the breaker opening mid-retry with
 * nothing left to isolate) DOES move the breaker's own file, but that alone
 * says nothing was delivered, never how much; this line is still the only
 * place that number is rendered, so it stays independent of which of the two
 * caused it.
 *
 * "at least" is accuracy, not hedging. Concurrent detached workers increment the
 * tally with an unlocked read-modify-write, so a simultaneous pair can lose one
 * — the same imprecision the breaker's own file carries, and the honest word for
 * a floor.
 */
function dropLines(dataDir: string, nowMs: number): string[] {
  const drops = readForwardDrops(dataDir);
  const labels = readUnsendableLabels(dataDir);
  return [
    ...(drops
      ? [
          `             at least ${String(drops.droppedForwards)} events dropped by the ` +
            `live forward, last ${ageLine(drops.lastDropAtMs, nowMs)}`,
        ]
      : []),
    // A grant or dismissal the wire contract refuses, stamped so it stops
    // holding the queue: counted here so that is not silent.
    ...(labels
      ? [
          `             at least ${String(labels.unsendable)} labels too large to report, ` +
            `last ${ageLine(labels.lastAtMs, nowMs)}`,
        ]
      : []),
  ];
}

/**
 * What has become of the activity recorded before this machine attached.
 *
 * OFFLINE, like every other line here, and read from the drain's own state file
 * rather than from the store: this renderer is synchronous and total, and a
 * count over `audit_events` is neither.
 *
 * The numbers are what that file records — which is a snapshot as of the last
 * pass, not a live figure. That is the honest thing to show: the drain runs in a
 * child spawned by a session, so between sessions nothing moves, and a number
 * that appeared to update would be describing work nobody did.
 *
 * NO ETA and no progress bar, deliberately. The schedule is coupled to how often
 * the user opens a session, so any projection would be a guess dressed as a
 * measurement.
 *
 * On a SCOPED attachment a pass counts only its scope's rows, and records in
 * the file that it did. A file that does not say so was counted for
 * everything recorded on this machine: by an older version of aka, whose drain
 * counted the whole machine in either mode, or by a pass that ran while this
 * machine was attached machine-wide. Read bare, those numbers would describe a
 * queue far larger than the one a scoped drain sends, and one that never
 * completes, so every line with numbers then carries a note saying which. The
 * note describes the pass that wrote the file, and goes once a pass that counts
 * through the scope writes it again. While an older plugin's drain still runs
 * beside a newer one, each pass leaves a line that is true of that pass.
 *
 * A scoped attachment with nothing in its scope for this deployment (no stored
 * entry, and no coding-agent key the forward paths add from the identity record)
 * sends no history at all, and says so instead of any number. That is read from
 * the scope in force now, through the settings this block already read, the keys
 * `renderAttachedStatus` derived from them and the endpoint the drain resolves
 * the scope against, not from the file: a pass over an empty scope records
 * "complete" with nothing sent, which would read as a finished drain rather than
 * one with nothing it may send. A refusal the last pass recorded still comes
 * first: while the deployment refuses this machine's key, enrolling resumes
 * nothing, and re-attaching is the step that does.
 *
 * A machine-wide attachment prints none of this, with one exception: a file
 * marked as counted through a scope, which a re-attach that made the machine
 * machine-wide left behind. Its totals cover only what was enrolled, and read
 * bare they would pass for the whole machine's until the next pass that runs
 * rewrites the file, so each line with numbers carries a note saying so and
 * that the next pass counts everything. A machine-wide file with the other
 * marker, or none, prints exactly as it always has.
 */
function historyLines(
  dataDir: string,
  settings: WorkspaceSettings,
  endpoint: string,
  nowMs: number,
  scoped: boolean,
  extras: readonly AttachmentScopeEntry[],
): string[] {
  // A grant PAUSED by a widening is not the same news as no grant, and the third
  // surface to say so. After a payload bump every machine that opted in holds a
  // stale grant, so a bare "not shared" tells a user who did opt in that they
  // did not — with no hint that a real grant exists or what widened it.
  if (isHistorySyncConsentStale(settings.historySyncConsent, endpoint)) {
    const changes = historySyncChangesSince(
      settings.historySyncConsent?.payloadVersion ?? 0,
      scoped ? 'scoped' : 'machine',
    );
    const what = changes.includes('newer')
      ? 'it was recorded by a newer release of aka'
      : changes.length === 0
        ? 'the change sends nothing new from this device'
        : `it now also covers ${changes
            .map((c) =>
              c === 'backlog-text'
                ? 'the text of what was recorded before'
                : 'the exceptions you grant and the findings you dismiss',
            )
            .join(', and ')}`;
    return [
      '  history    paused — your grant predates a change to what is sent:',
      `             ${what}`,
      '             (run `aka sync-history --on` to grant it again)',
    ];
  }
  // Absent grant is the overwhelmingly common case, and it is not a fault: this
  // is opt-in, and a machine that never opted in should read as settled rather
  // than as pending.
  if (!isHistorySyncConsentValid(settings.historySyncConsent, endpoint)) {
    return ['  history    not shared (run `aka sync-history --on`)'];
  }

  const state = readHistorySyncState(dataDir);
  // A refused key stops the drain whatever is enrolled, so it is said first,
  // ahead of the nothing-to-send line below. It never printed a number, so
  // moving it up changes no line on any attachment.
  if (state?.lastOutcome === 'refused') {
    return [
      "  history    stopped — that deployment refused this machine's key",
      '             re-attach to resume',
    ];
  }
  // Nothing in scope for this deployment, stored or added: no history is sent,
  // whatever the file says. See the docblock for why this is read from the
  // scope, not the file.
  if (
    scoped &&
    resolveScope({ mode: 'scoped', scope: settings.attachmentScope, endpoint }, extras).keys
      .size === 0
  ) {
    return ['  history    nothing to send — nothing is in scope yet'];
  }
  // Granted but nothing recorded yet: the grant is real and the first pass has
  // not run. Saying "waiting" rather than "0 sent" avoids reporting a number
  // that no pass produced.
  if (state === null) return ['  history    sharing — waiting for the first pass'];

  const sent = count(state.sentTotal);
  const total = count(state.sentTotal + state.pendingTotal);
  const skipped = state.skippedTotal > 0 ? `, ${count(state.skippedTotal)} could not be sent` : '';
  // Whether the population the pass counted is the one this attachment sends:
  // see the docblock.
  const caveat = countsNote(scoped, state.countsScope);

  if (state.lastOutcome === 'unreachable') {
    return [
      `  history    paused — deployment unreachable, last tried ${ageLine(state.lastPassAtMs, nowMs)}`,
      `             ${sent} of ${total} records sent${skipped}`,
      ...caveat,
    ];
  }
  if (state.phase === 'complete' && state.pendingTotal === 0) {
    return [`  history    complete — ${sent} records sent${skipped}`, ...caveat];
  }
  return [`  history    sending — ${sent} of ${total} records sent${skipped}`, ...caveat];
}

/** Thousands separators, so a six-figure backlog is readable at a glance. */
function count(n: number): string {
  return n.toLocaleString('en-US');
}

function forwardLines(dataDir: string, nowMs: number): string[] {
  const drops = dropLines(dataDir, nowMs);
  const health = readForwardHealth(dataDir, nowMs);
  // No file is the HAPPY path, not a gap: `run()` writes nothing at all unless
  // something fails. Still phrased as what is known rather than as health —
  // "no failures recorded" is also true of a device that has never forwarded.
  if (!health) return ['  forward    no failures recorded', ...drops];

  const { consecutiveFailures, openedAtMs, lastFailure } = health;
  // Closed at zero means a forward SUCCEEDED and cleared a previous run of
  // failures — the one state in which this file is evidence of health. Returned
  // early because it is also the one state with no cause to name: a success
  // clears `lastFailure` with the count.
  if (openedAtMs === null && consecutiveFailures === 0) {
    return ['  forward    reporting normally', ...drops];
  }

  const lines =
    openedAtMs !== null
      ? // `openedAtMs` is re-stamped on every half-open probe, so the gap to now
        // is bounded by one cooldown however long the control plane has been down — it
        // dates the last ATTEMPT, never the outage. The failure count is the
        // part that grows, so that is the number shown as the magnitude.
        [
          `  forward    NOT REPORTING — ${String(consecutiveFailures)} consecutive ` +
            `failures, last tried ${ageLine(openedAtMs, nowMs)}`,
        ]
      : // Closed but non-zero: failing without having reached the threshold yet.
        [`  forward    ${String(consecutiveFailures)} failures since the last success`];

  // The cause rides on its own line, under both of the above rather than only
  // under the open one. A refusal is terminal from the FIRST failure — three
  // more forwards will be refused the same way — so waiting for the breaker to
  // trip before naming it would withhold the actionable half of the message for
  // exactly as long as the user could still have acted on it early.
  if (lastFailure === 'unauthorized' || lastFailure === 'forbidden') {
    lines.push(`             ${REFUSAL_LINES[lastFailure]}`);
  }
  return [...lines, ...drops];
}

/**
 * Whether this device's hourly posture self-report is LANDING — the thing the
 * control plane actually grades a device on, and until now the one send whose
 * outcome nothing on the machine wrote down.
 *
 * The send goes through the forward breaker, so a refusal moves the breaker's
 * file too — but that file is rewritten by every forward and cleared by the
 * next success, so a posture send refused an hour ago is "disproved" by a tool
 * call that landed a minute ago. The outcome is therefore recorded on its own
 * and rendered with its own age. The age is the point: the plane grades on
 * freshness, and a line that only said "reported" would read healthy on a
 * machine whose last landed report is days old.
 *
 * Same remediation split as the sync and forward lines, and for the same
 * reason: a 401 is fixed by `attach`, a 403 is not, and a wrong instruction is
 * worse than none. The other five name what was observed and stop, because
 * re-attaching fixes none of them. `rejected` is the deployment ANSWERING — a
 * 4xx body refusal, this build's snapshot shape not being one it accepts — so
 * it is not folded into `unreachable`; a 404 on the posture route carries no
 * verdict and reads as `unreachable`. `route-absent` and `invalid-request` are
 * named because the policy can return them, not because today's posture send
 * raises either.
 *
 * An exhaustive Record, not a switch with a default: a reason added to the
 * policy that this table does not name fails typecheck instead of rendering a
 * line with a hole in it.
 */
const POSTURE_FAILURE_LINES: Record<ForwardFailureReason, string> = {
  unauthorized: 'key rejected',
  forbidden: 'access refused',
  unreachable: 'control plane unreachable',
  'breaker-open': 'skipped while the forward breaker was open',
  'invalid-request': 'this build refused to send its own snapshot',
  'route-absent': 'that deployment has no posture route',
  rejected: 'that deployment refused this snapshot',
};

function postureLines(dataDir: string, nowMs: number): string[] {
  const state = readPostureReportState(dataDir);
  // No file is also what a freshly attached device looks like for its first
  // session, and a device whose hourly attempt has not fired yet. Phrased as
  // what is known, never as health.
  if (!state) return ['  posture    no report recorded yet'];
  const age = ageLine(state.atMs, nowMs);
  if (state.outcome === 'ok') return [`  posture    reported (${age})`];
  const lines = [
    `  posture    NOT REPORTED — ${POSTURE_FAILURE_LINES[state.outcome]} (last tried ${age})`,
  ];
  if (state.outcome === 'unauthorized' || state.outcome === 'forbidden') {
    lines.push(`             ${REFUSAL_LINES[state.outcome]}`);
  }
  return lines;
}

/**
 * How often a hook has fallen open on this machine, if ever: thrown out of its
 * main(), or let part of what it was scanning through unscanned — a response
 * the scan deadline or the response size bound cut short, or, on a host with no
 * channel to refuse it, a prompt or response whose bounded scan of a large
 * field did not finish or could not run. "failed open" is the right
 * word for both — each is content the host received with no verdict on it —
 * so the line does not split them, and the tally does not record which it was.
 *
 * A fail-open is silent by contract — no output, exit 0, the session never
 * notices — so a machine whose hooks throw on every call reads exactly like
 * one whose hooks run: nothing is scanned, nothing is forwarded, and every
 * other line here describes a control plane that is simply not being asked.
 * The count the catch writes is the one local trace. Rendered in the attached
 * AND the standalone block, because the guarantee it describes holds on both,
 * and read from the SDK's own file rather than plumbed a value, because the
 * process that failed open exited long before anyone ran `aka status`.
 *
 * "at least", because concurrent hooks increment without a lock — the same
 * floor the forward drop tally states.
 */
function failOpenLines(dataDir: string, nowMs: number): string[] {
  const tally = readHookFailOpens(dataDir);
  if (!tally) return [];
  return [
    `  hooks      failed open at least ${String(tally.failOpens)} time(s), ` +
      `last ${ageLine(tally.lastAtMs, nowMs)}`,
  ];
}

/**
 * A string from outside this process, made safe to print in a terminal.
 *
 * Control and format characters are stripped and the result is bounded, so an
 * ANSI escape cannot repaint the block around it or hide a line, and the worst a
 * hostile value can do is occupy its own field. A label from an administrator's
 * overlay, a policy version from a control plane, a repository read back from
 * settings.json: none of them was authored by the code printing it.
 *
 * Exported so a command that echoes such a string can strip it with this one
 * function rather than a copy that could drift.
 */
export function printableForTerminal(value: string, max = 80): string {
  const stripped = value.replace(/[\p{Cc}\p{Cf}]/gu, '');
  return stripped.length > max ? `${stripped.slice(0, max)}…` : stripped;
}

/** What endpointForTerminal prints in place of an address it will not echo. */
const ENDPOINT_NOT_SHOWN = 'address not shown';

/**
 * A deployment address read back from a file, made safe to print in a terminal.
 *
 * The schema holds a stored address to no more than being a non-empty string,
 * so it can carry what an address must never show: userinfo, a query, a
 * fragment. An http or https address with none of them is printed as stored,
 * through printableForTerminal, so a spelling that differs from another address
 * (a trailing slash, the case of the host) stays visible. One that carries any
 * of them is printed as its origin alone, with "rest not shown" after it.
 * Anything else, a string that does not parse as a URL or one with another
 * scheme, is printed as ENDPOINT_NOT_SHOWN. Never throws.
 *
 * Exported so a command that echoes an address it read from a file prints it
 * with this one function rather than a copy that could drift.
 */
export function endpointForTerminal(endpoint: string): string {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    return ENDPOINT_NOT_SHOWN;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return ENDPOINT_NOT_SHOWN;
  // The serialized URL equals scheme, host and path exactly when the address
  // carries no userinfo, query or fragment, an empty query or fragment included.
  const bare = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  return parsed.href === bare
    ? printableForTerminal(endpoint, 200)
    : `${printableForTerminal(originOnly(endpoint), 200)}, rest not shown`;
}

/**
 * The deployment's name as a terminal shows it: the label, or the settings
 * address when there is none.
 *
 * A label is free text and gets the plain strip at its default bound. The
 * settings address is checked when settings are saved through the product, not
 * when the file is edited by hand or an overlay pins it, and the plain strip
 * leaves userinfo, a query and a fragment in an address. So an address goes
 * through `endpointForTerminal`, which keeps those off the screen and prints a
 * clean address whole up to two hundred characters.
 *
 * The one copy `aka status`, `aka enroll` and the session-start line print a
 * deployment's name with, so the same deployment reads the same on all three.
 */
export function deploymentNameForTerminal(connection: ControlPlaneConnection): string {
  return connection.label === undefined
    ? endpointForTerminal(controlPlaneName(connection))
    : printableForTerminal(controlPlaneName(connection));
}

/**
 * The policy cache half, async because the store is.
 *
 * Kept OUT of `renderAttachedStatus` so that function can stay synchronous and
 * total: a slash-command entry can render the connection block with no awaits at
 * all, and only pay for the cache read when it wants the version line.
 *
 * `PolicyBundle.version` is a bare `z.string()` shared with the local standalone
 * bundle, so it cannot be tightened the way `PluginWhoami`'s members are, and a
 * hostile or compromised plane could put an escape in it. It is printed through
 * printableForTerminal.
 */
export async function renderPolicyLine(dataDir: string, nowMs = Date.now()): Promise<string> {
  try {
    const cached = await createPolicyStore(dataDir).read();
    if (!cached) return '  policy     none cached';
    return `  policy     ${printableForTerminal(cached.bundle.version)} (fetched ${ageLine(cached.fetchedAtMs, nowMs)})`;
  } catch {
    return '  policy     unreadable';
  }
}
