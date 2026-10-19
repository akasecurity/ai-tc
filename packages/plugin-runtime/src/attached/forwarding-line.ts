import { dirname } from 'node:path';

import { managedScopedRefusal } from '@akasecurity/persistence';
import type { AccountBasis, WebAccountProvider } from '@akasecurity/schema';
import {
  isAgentScopeKey,
  isRepoShapedScopeKey,
  parseAgentKey,
  parseWebAccountKey,
} from '@akasecurity/schema';

import { printableForTerminal } from './status.ts';

/**
 * What a session start knows about its session, for the line: handed to the
 * gateway, which folds it into its answer.
 */
export interface ForwardingSession {
  /** The session start left the root to the reconcile. */
  readonly rootDeferred: boolean;
  /** The basis the session start's login view reached, for a work login; undefined otherwise. */
  readonly basis: AccountBasis | undefined;
  /** An administrator manages this machine's connection, so the opt-out command refuses. */
  readonly managed: boolean;
  /**
   * A Codex thread's ChatGPT account is not decided yet, because its first record
   * was not on disk: the line says what the thread's next check can change.
   */
  readonly threadAccountPending?: boolean | undefined;
}

/** Where a forwarding gateway forwards, as the session-start line needs it. */
export type ForwardingScope =
  | {
      /** The deployment's name as a terminal shows it (`deploymentNameForTerminal`). */
      deploymentName: string;
      mode: 'machine';
    }
  | {
      deploymentName: string;
      mode: 'scoped';
      /**
       * The scope key the local store holds for the session's root, or undefined
       * when it holds none. Roots are first-write-wins, so this, not the key a
       * session start resolved, is the key the gateway decides the root by.
       */
      rootKey: string | undefined;
      /**
       * The verdict the gateway recorded on that root when it was written through
       * it: whether its records are sent.
       */
      rootForwards: boolean;
      /** Present when the session's login is a work subscription. */
      work?: { basis: AccountBasis; managed: boolean } | undefined;
    }
  | {
      deploymentName: string;
      /** The root forwards under the session's own key, `rootKey`, an agent key. */
      mode: 'account';
      rootKey: string;
      basis: AccountBasis | undefined;
      managed: boolean;
    }
  | {
      deploymentName: string;
      /** The session start left the root to the reconcile, which keys it by the session's first reply. */
      mode: 'account-pending';
      /** Undefined when the session start could not tell the login, so the first reply decides. */
      basis: AccountBasis | undefined;
      managed: boolean;
      /** False when work subscriptions are off on this device: only an account enrolled by hand can apply. */
      workSubscriptionsOn: boolean;
    };

/**
 * What a gateway that forwards can say about where it forwards.
 *
 * A capability rather than a member of the DataGateway port. A gateway that does
 * not offer it forwards nothing as far as the line is concerned: the local
 * gateway, and any gateway an embedder installs in place of the attached one.
 * The attached gateway offers it, from the attachment, the name it was built
 * with and the session it is handed, and never hands out the credential.
 */
export interface ForwardingScopeReader {
  forwardingScope(rootId: string, session?: ForwardingSession): ForwardingScope | null;
}

function offersForwardingScope<G extends object>(gateway: G): gateway is G & ForwardingScopeReader {
  return typeof (gateway as Partial<ForwardingScopeReader>).forwardingScope === 'function';
}

const LOCAL_ONLY =
  'AKA: local-only (not enrolled); work in an enrolled repository is still forwarded';
const OPT_OUT = '`aka unenroll --work-subscriptions` stops this on this device.';
const MANUAL_STOP =
  'Enrolled by hand; `aka unenroll --account` with its key stops this (`aka status` lists it).';

const LOCAL_OTHERWISE = 'otherwise it stays local, apart from work in an enrolled repository.';

/** `line`, then the sentence naming the command that stops it, where one works. */
function withStop(line: string, basis: AccountBasis | undefined, managed: boolean): string {
  if (basis === 'manual') return `${line} ${MANUAL_STOP}`;
  return managed ? line : `${line} ${OPT_OUT}`;
}

/** How the opening of an account line reads for a login, by the provider the root's account key names. */
type AccountOpening = Record<'work' | 'byHand' | 'keyed', (name: string) => string>;

const ACCOUNT_OPENING: Record<WebAccountProvider, AccountOpening> = {
  claude: {
    work: (name) => `AKA: forwarding this session to ${name} — signed in to a work subscription.`,
    byHand: (name) =>
      `AKA: forwarding this session to ${name} — signed in to an account you enrolled by hand.`,
    keyed: (name) =>
      `AKA: forwarding this session to ${name} — for the account it first ran under.`,
  },
  chatgpt: {
    work: (name) =>
      `AKA: forwarding this thread to ${name} — signed in to a ChatGPT work subscription; it stops if the thread is resumed or its login changes.`,
    byHand: (name) =>
      `AKA: forwarding this thread to ${name} — signed in to a ChatGPT workspace you enrolled by hand; it stops if the thread is resumed or switches to another workspace or login mode.`,
    keyed: (name) =>
      `AKA: this thread first ran under a ChatGPT workspace forwarded to ${name}; from here it follows the repository rule, so only work in an enrolled repository is forwarded.`,
  },
};

/** The sentence a Codex thread's line ends with while its ChatGPT account is not decided. */
function pendingThreadAccount(name: string): string {
  return `This thread's ChatGPT account is checked once more at its next prompt or tool call. If this device then recognises it as a work subscription, or it is a workspace you enrolled by hand, the thread's prompts, tool calls and results are forwarded to ${name} from any folder from then on. Otherwise, including if the account still cannot be read, the thread follows the repository rule.`;
}

/** `line`, then, for a thread whose account is not decided yet, what its next check can change. */
function withPendingAccount(
  line: string,
  name: string,
  session: ForwardingSession | undefined,
): string {
  return session?.threadAccountPending === true ? `${line}. ${pendingThreadAccount(name)}` : line;
}

/** The provider of the account an agent-keyed root names; Claude for any other key. */
function accountProviderOf(rootKey: string): WebAccountProvider {
  const agent = parseAgentKey(rootKey);
  return (
    (agent === undefined ? undefined : parseWebAccountKey(agent.accountKey)?.provider) ?? 'claude'
  );
}

/**
 * The line for a session forwarded from any folder: the work subscription it is
 * signed in to, or, for an account enrolled by hand, that account. The
 * provider of the root's account key picks the wording: a Codex thread says
 * "thread" and names its ChatGPT subscription or workspace.
 *
 * Without a basis the session's login shows no work account, while its stored
 * root is keyed by one (a resumed session). The root's key does not say whether
 * recognition or an enrollment by hand put it in scope, so the line claims
 * neither a work subscription nor the command that stops either. For a Codex
 * thread it says the thread follows the repository rule from there, because a
 * thread with no basis at its session start is on that rule.
 */
function accountLine(
  name: string,
  rootKey: string,
  basis: AccountBasis | undefined,
  managed: boolean,
): string {
  const opening = ACCOUNT_OPENING[accountProviderOf(rootKey)];
  if (basis === undefined) return opening.keyed(name);
  return withStop(basis === 'manual' ? opening.byHand(name) : opening.work(name), basis, managed);
}

/**
 * The line for a root left to the reconcile when the session start could not
 * tell the login. The first reply decides, so the line claims neither a work
 * subscription nor an account enrolled by hand, and names no stop command
 * because neither may apply.
 */
function undeterminedLine(name: string, workSubscriptionsOn: boolean): string {
  const shows = workSubscriptionsOn
    ? 'a work subscription or an account enrolled by hand'
    : 'an account enrolled by hand';
  return `AKA: this session forwards to ${name} only if its first reply shows ${shows}; ${LOCAL_OTHERWISE}`;
}

/**
 * Whether `aka unenroll --work-subscriptions` works on this device: false where
 * an administrator manages the connection (`managedScopedRefusal`), where that
 * command refuses. `settingsDir` is the AKA home's settings directory. A managed
 * file that cannot be read reads as unmanaged. Never throws.
 */
export function workSubscriptionOptOutOffered(settingsDir: string): boolean {
  try {
    return managedScopedRefusal(dirname(settingsDir)) === null;
  } catch {
    return true;
  }
}

/**
 * The one line a session start shows about where this session's activity goes,
 * or null when the gateway forwards nothing.
 *
 * The states, from the gateway the session start writes through:
 *
 *   machine          `AKA: forwarding everything to <name> (machine-wide)`
 *   scoped, in       `AKA: forwarding to <name> (<enrolled repository>)`, and, for a
 *                    work login, that the session also sends its work in other folders;
 *                    a root key that does not name a repository is left out of the line
 *   scoped, out      `AKA: local-only (not enrolled); work in an enrolled repository is still forwarded`
 *   account          `AKA: forwarding this session to <name> — signed in to a work subscription.`
 *   account-pending  `AKA: this session forwards to <name> once Claude confirms the work subscription, from its first reply.`
 *                    Each names the account enrolled by hand in place of the work
 *                    subscription, and never the opt-out, when the login is one. The
 *                    pending line does so too with work subscriptions off on the device.
 *                    A pending line with no login basis (the session start could not
 *                    tell the login) is conditional:
 *                    `AKA: this session forwards to <name> only if its first reply shows a work subscription or an account enrolled by hand; otherwise it stays local, apart from work in an enrolled repository.`
 *                    It drops the work subscription from that condition with work
 *                    subscriptions off on the device.
 *                    An account line with no login basis says
 *                    `AKA: forwarding this session to <name> — for the account it first ran under.`
 *
 * An account line whose root key names a ChatGPT workspace is worded for a Codex
 * thread: it says "thread", names the ChatGPT work subscription (or the workspace
 * enrolled by hand), and says the thread stops being sent when it is resumed or
 * its login changes. With no login basis it says the thread first ran under a
 * ChatGPT workspace and follows the repository rule from there.
 *
 * A scoped line for a Codex thread whose ChatGPT account is not decided yet
 * (`session.threadAccountPending`) ends with a sentence saying the account is
 * checked once more at the thread's next prompt or tool call. If the device then
 * recognises a work subscription, or the workspace is enrolled by hand, the
 * thread's prompts, tool calls and results are sent from any folder; otherwise
 * the thread follows the repository rule.
 *
 * Each work line ends with the command that stops it: the opt-out for a session
 * recognised automatically, or `aka unenroll --account` for an account enrolled
 * by hand. The opt-out is left out where an administrator manages the
 * connection. A line with no login basis names neither command.
 *
 * Taken from that gateway rather than re-derived from the configuration, so the
 * line says what the object doing the forwarding will do. A standalone machine,
 * a half attachment, an unusable credential and a gateway an embedder swapped in
 * all print nothing, because none of them offers a forwarding scope.
 *
 * The scoped verdict is the session ROOT's, the one the gateway recorded when the
 * root was written through it, which decides whether the session's own records
 * (its token usage and tool-call records) are sent. A capture is decided by the
 * key it carries, so a local-only session that edits a file in an enrolled
 * repository still sends that capture, which is why the local-only line says so.
 * Read it after the session root is written, or after the session start left it
 * to the reconcile (`session.rootDeferred`): a gateway that recorded no root and
 * was not told it was deferred has no verdict, and the line is not printed. No
 * line prints an account key, an agent key or an org id.
 *
 * Never throws: a fault prints nothing.
 */
export function forwardingLine(
  gateway: object,
  rootId: string,
  session?: ForwardingSession,
): string | null {
  try {
    if (!offersForwardingScope(gateway)) return null;
    const scope = gateway.forwardingScope(rootId, session);
    if (scope === null) return null;
    const name = scope.deploymentName;
    switch (scope.mode) {
      case 'machine':
        return `AKA: forwarding everything to ${name} (machine-wide)`;
      case 'account':
        return accountLine(name, scope.rootKey, scope.basis, scope.managed);
      case 'account-pending':
        if (scope.basis === undefined) return undeterminedLine(name, scope.workSubscriptionsOn);
        if (!scope.workSubscriptionsOn || scope.basis === 'manual') {
          return `AKA: this session forwards to ${name} once Claude confirms it is signed in to an account you enrolled by hand, from its first reply. ${MANUAL_STOP}`;
        }
        return withStop(
          `AKA: this session forwards to ${name} once Claude confirms the work subscription, from its first reply.`,
          scope.basis,
          scope.managed,
        );
      case 'scoped': {
        if (!scope.rootForwards || scope.rootKey === undefined) {
          return withPendingAccount(LOCAL_ONLY, name, session);
        }
        if (isAgentScopeKey(scope.rootKey)) {
          return accountLine(name, scope.rootKey, scope.work?.basis, scope.work?.managed ?? false);
        }
        const repository = isRepoShapedScopeKey(scope.rootKey)
          ? `AKA: forwarding to ${name} (${printableForTerminal(scope.rootKey, 200)})`
          : `AKA: forwarding to ${name}`;
        if (scope.work === undefined) return withPendingAccount(repository, name, session);
        const because =
          scope.work.basis === 'manual'
            ? 'because it is signed in to an account you enrolled by hand.'
            : 'because it is signed in to a work subscription.';
        return withStop(
          `${repository}. This session also sends its work in other folders, ${because}`,
          scope.work.basis,
          scope.work.managed,
        );
      }
    }
  } catch {
    return null;
  }
}
