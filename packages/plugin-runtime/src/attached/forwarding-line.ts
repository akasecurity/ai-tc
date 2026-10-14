import { dirname } from 'node:path';

import { managedScopedRefusal } from '@akasecurity/persistence';
import type { AccountBasis } from '@akasecurity/schema';
import { isAgentScopeKey } from '@akasecurity/schema';

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
      basis: AccountBasis | undefined;
      managed: boolean;
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

/** `line`, then the sentence naming the command that stops it, where one works. */
function withStop(line: string, basis: AccountBasis | undefined, managed: boolean): string {
  if (basis === 'manual') return `${line} ${MANUAL_STOP}`;
  return managed ? line : `${line} ${OPT_OUT}`;
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
 *                    work login, that the session also sends its work in other folders
 *   scoped, out      `AKA: local-only (not enrolled); work in an enrolled repository is still forwarded`
 *   account          `AKA: forwarding this session to <name> — signed in to a work subscription.`
 *   account-pending  `AKA: this session forwards to <name> once Claude confirms the work subscription, from its first reply.`
 *
 * Each work line ends with the command that stops it: the opt-out for a session
 * recognised automatically, or `aka unenroll --account` for an account enrolled
 * by hand. The opt-out is left out where an administrator manages the
 * connection.
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
    const workLine = `AKA: forwarding this session to ${name} — signed in to a work subscription.`;
    switch (scope.mode) {
      case 'machine':
        return `AKA: forwarding everything to ${name} (machine-wide)`;
      case 'account':
        return withStop(workLine, scope.basis, scope.managed);
      case 'account-pending':
        return withStop(
          `AKA: this session forwards to ${name} once Claude confirms the work subscription, from its first reply.`,
          scope.basis,
          scope.managed,
        );
      case 'scoped': {
        if (!scope.rootForwards || scope.rootKey === undefined) return LOCAL_ONLY;
        if (isAgentScopeKey(scope.rootKey)) {
          return withStop(workLine, scope.work?.basis, scope.work?.managed ?? false);
        }
        const repository = `AKA: forwarding to ${name} (${printableForTerminal(scope.rootKey, 200)})`;
        if (scope.work === undefined) return repository;
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
