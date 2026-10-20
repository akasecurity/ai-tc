import type { IngestBatch, RecordAuditEventRequest } from '@akasecurity/schema';

/**
 * An `owner/repo` label without the query of the git remote it was read from:
 * everything from the first `?` on is removed, then one trailing `.git`. A label
 * with no `?` is returned as given.
 */
export function ownerRepoWithoutQuery(label: string): string {
  const at = label.indexOf('?');
  return at === -1 ? label : cutAt(label, at);
}

/**
 * A repository or project name without the query of the git remote it was read
 * from. Such a name is the checkout's folder name when there is no remote, so it
 * is cut as `ownerRepoWithoutQuery` cuts only when the text after its first `?`
 * contains `=`, as a URL query's `name=value` pairs do. A folder name such as
 * `a?b` is returned as given.
 */
export function repoNameWithoutQuery(label: string): string {
  const at = label.indexOf('?');
  return at === -1 || !label.includes('=', at) ? label : cutAt(label, at);
}

function cutAt(label: string, at: number): string {
  return label.slice(0, at).replace(/\.git$/, '');
}

/**
 * `batch` with each capture's `metadata.repo` passed through
 * `repoNameWithoutQuery`. A batch with nothing to change is returned as given.
 */
export function batchForWire(batch: IngestBatch): IngestBatch {
  const events = batch.events.map((event) => {
    const repo = event.metadata?.repo;
    if (repo === undefined) return event;
    const clean = repoNameWithoutQuery(repo);
    return clean === repo ? event : { ...event, metadata: { ...event.metadata, repo: clean } };
  });
  return events.every((event, i) => event === batch.events[i]) ? batch : { ...batch, events };
}

/**
 * `event` with its `attributes.repo` passed through `ownerRepoWithoutQuery` and
 * its `attributes.project` through `repoNameWithoutQuery`. An event with nothing
 * to change is returned as given.
 */
export function auditEventForWire(event: RecordAuditEventRequest): RecordAuditEventRequest {
  const attributes = event.attributes;
  if (attributes === undefined) return event;
  let changed = false;
  const clean = { ...attributes };
  for (const [key, withoutQuery] of [
    ['repo', ownerRepoWithoutQuery],
    ['project', repoNameWithoutQuery],
  ] as const) {
    const value = attributes[key];
    if (typeof value !== 'string') continue;
    const label = withoutQuery(value);
    if (label === value) continue;
    clean[key] = label;
    changed = true;
  }
  return changed ? { ...event, attributes: clean } : event;
}
