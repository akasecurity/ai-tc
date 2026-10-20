import type { IngestBatch, RecordAuditEventRequest } from '@akasecurity/schema';

/**
 * `label` without the query of the git remote it was read from: everything from
 * the first `?` on is removed, then one trailing `.git`. A label with no `?` is
 * returned as given.
 */
export function repoLabelWithoutQuery(label: string): string {
  const at = label.indexOf('?');
  return at === -1 ? label : label.slice(0, at).replace(/\.git$/, '');
}

/**
 * `batch` with each capture's `metadata.repo` passed through
 * `repoLabelWithoutQuery`. A batch with nothing to change is returned as given.
 */
export function batchForWire(batch: IngestBatch): IngestBatch {
  const events = batch.events.map((event) => {
    const repo = event.metadata?.repo;
    if (repo === undefined) return event;
    const clean = repoLabelWithoutQuery(repo);
    return clean === repo ? event : { ...event, metadata: { ...event.metadata, repo: clean } };
  });
  return events.every((event, i) => event === batch.events[i]) ? batch : { ...batch, events };
}

/**
 * `event` with its `attributes.repo` and `attributes.project` passed through
 * `repoLabelWithoutQuery`. An event with nothing to change is returned as given.
 */
export function auditEventForWire(event: RecordAuditEventRequest): RecordAuditEventRequest {
  const attributes = event.attributes;
  if (attributes === undefined) return event;
  let changed = false;
  const clean = { ...attributes };
  for (const key of ['repo', 'project'] as const) {
    const value = attributes[key];
    if (typeof value !== 'string') continue;
    const label = repoLabelWithoutQuery(value);
    if (label === value) continue;
    clean[key] = label;
    changed = true;
  }
  return changed ? { ...event, attributes: clean } : event;
}
