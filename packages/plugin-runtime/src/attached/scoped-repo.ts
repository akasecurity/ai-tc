import type { IngestEvent } from '@akasecurity/schema';

/**
 * A capture as a SCOPED attachment sends it: a copy whose `metadata.repo` is the
 * last path segment of the capture's own scope key.
 *
 * WHY. `metadata.repo` is the producer's display slug, which the hooks resolve
 * from the session's working directory (`resolveRepo`). The scope key is
 * resolved from the capture's own file when it names one, and from the
 * workspace root holding its target on a multi-root host. The two name
 * different repositories exactly when a session in one checkout touches a file
 * in another. On a scoped attachment the key is the one that was enrolled, so
 * sending the producer's slug would label an enrolled repository's capture
 * with a personal repository's name. The gateway calls this only with a key
 * the scope verdict admitted, so the name it sends is an enrolled one.
 *
 * In the common case it is the value the slug already is. `resolveRepo` takes
 * the last `/`- or `:`-separated piece of the remote, with one trailing `.git`
 * dropped. A key is the same remote's host and path, with its slash runs
 * trimmed and one trailing `.git` dropped. For a checkout whose remote is the
 * keyed one, the two agree unless the remote ends in `.git/` or its last path
 * segment holds a `:`, and there the key's segment is sent. Both shapes are
 * pinned in the tests.
 *
 * PURE: `event` is never written to, and the caller's delivery stamps keep the
 * original. A slug already present keeps its place in the metadata, so when it
 * already equals the key's segment the copy serializes byte for byte like the
 * original. A key with no segment to name, which `canonicalRepoUrl` never
 * returns, sends no slug rather than the producer's.
 */
export function withScopedRepo(event: IngestEvent, scopeKey: string): IngestEvent {
  const repo = scopeKey
    .split('/')
    .filter((segment) => segment !== '')
    .pop();
  if (repo !== undefined) return { ...event, metadata: { ...event.metadata, repo } };
  if (event.metadata?.repo === undefined) return event;
  const metadata = { ...event.metadata };
  delete metadata.repo;
  return { ...event, metadata };
}
