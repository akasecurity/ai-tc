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
