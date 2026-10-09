import { printableForTerminal } from './status.ts';

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
      /** The gateway's own verdict on that root: whether its records are sent. */
      rootForwards: boolean;
    };

/**
 * What a gateway that forwards can say about where it forwards.
 *
 * A capability rather than a member of the DataGateway port. A gateway that does
 * not offer it forwards nothing as far as the line is concerned: the local
 * gateway, and any gateway an embedder installs in place of the attached one.
 * The attached gateway offers it, from the attachment and the name it was built
 * with, and never hands out the credential.
 */
export interface ForwardingScopeReader {
  forwardingScope(rootId: string): ForwardingScope | null;
}

function offersForwardingScope<G extends object>(gateway: G): gateway is G & ForwardingScopeReader {
  return typeof (gateway as Partial<ForwardingScopeReader>).forwardingScope === 'function';
}

/**
 * The one line a session start shows about where this session's activity goes,
 * or null when the gateway forwards nothing.
 *
 * Three states, from the gateway the session start writes through:
 *
 *   machine         `AKA: forwarding everything to <name> (machine-wide)`
 *   scoped, in      `AKA: forwarding to <name> (<enrolled repository>)`
 *   scoped, out     `AKA: local-only (not enrolled); work in an enrolled repository is still forwarded`
 *
 * Taken from that gateway rather than re-derived from the configuration, so the
 * line says what the object doing the forwarding will do. A standalone machine,
 * a half attachment, an unusable credential and a gateway an embedder swapped in
 * all print nothing, because none of them offers a forwarding scope.
 *
 * The scoped verdict is the session ROOT's, read from the root the store holds,
 * which decides whether the session's own records (its token usage and tool-call
 * records) are sent. A capture is decided by the key it carries, so a local-only
 * session that edits a file in an enrolled repository still sends that capture,
 * which is why the local-only line says so. Read it after the session root is
 * written: before that the store holds no root, and the answer is local-only.
 *
 * Never throws: a fault prints nothing.
 */
export function forwardingLine(gateway: object, rootId: string): string | null {
  try {
    if (!offersForwardingScope(gateway)) return null;
    const scope = gateway.forwardingScope(rootId);
    if (scope === null) return null;
    const name = scope.deploymentName;
    if (scope.mode === 'machine') return `AKA: forwarding everything to ${name} (machine-wide)`;
    if (scope.rootForwards && scope.rootKey !== undefined) {
      return `AKA: forwarding to ${name} (${printableForTerminal(scope.rootKey, 200)})`;
    }
    return 'AKA: local-only (not enrolled); work in an enrolled repository is still forwarded';
  } catch {
    return null;
  }
}
