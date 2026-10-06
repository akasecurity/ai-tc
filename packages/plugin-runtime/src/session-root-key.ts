import { WebSourceTool } from '@akasecurity/schema';

/**
 * Whether a session under this tool can be keyed to a repository at all.
 *
 * A web chat session never can. It has no working directory: the browser host
 * passes the home directory as a stand-in so that no project resolves. A home
 * directory that is itself a checkout does resolve one, and anything keyed from
 * that project would then carry a repository's key though the session is not in
 * it. The other half of a session root's key rule, that only an absolute working
 * directory is keyed, is `sessionRootScopeKey`'s and needs the directory.
 *
 * ONE PREDICATE for the two places that decide it, so they cannot drift: the
 * session root stamps no key for a session this refuses, and the attached
 * gateway sends no inventory for one.
 */
export function sessionToolIsKeyed(tool: string): boolean {
  return !WebSourceTool.safeParse(tool).success;
}

/**
 * Reading back the scope key the local store holds for a session root.
 *
 * Its own capability rather than a `DataGateway` member, for the reason
 * `CaptureStatusReader` is: only an implementation with a store of its own can
 * answer, and the attached gateway, which decides what to forward from it, is the
 * one caller. It lives here and not in the SDK because it is that gateway's need
 * and no other implementation's.
 *
 * Synchronous, like the delivery stamps beside it: it is one lookup by primary
 * key and there is nothing to await.
 */
export interface StoredRootKeyReader {
  /**
   * The key stored on session root `sessionId`, or undefined when the store holds
   * no such root, the root is a stub or carries no key, or the stored value is not
   * a string. Roots are first-write-wins, so this can differ from the key on the
   * root event a caller just recorded; it is the key the history drain will decide
   * the row by.
   */
  readSessionScopeKey(sessionId: string): string | undefined;
}
