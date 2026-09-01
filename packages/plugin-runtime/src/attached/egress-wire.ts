// The device-side projection of a project's egress-recording unit onto the
// wire-boundary-safe shape both attached gateways forward. This is the ONLY
// place that builds an `EgressIngestRequest` — neither gateway hand-rolls the
// payload, so the privacy boundary has exactly one implementation.
import { createHash } from 'node:crypto';

import { capHits, withoutDroppedFiles } from '@akasecurity/persistence';
import type {
  EgressIngestHit,
  EgressIngestRequest,
  RecordProjectEgressInput,
  ResolvedEgressHit,
} from '@akasecurity/schema';

/**
 * Digest a local `projectKey` for the wire.
 *
 * Unsalted SHA-256 over the FULL prefixed key (including its `git:` / `path:`
 * prefix), rendered as 64 lowercase hex characters. Uniform across both
 * variants — there is no branch on prefix — which is what keeps `git:X` and
 * `path:X` from aliasing to the same digest while letting the same `git:`
 * identity converge to the same digest across every device that scanned it.
 */
export function hashProjectKey(projectKey: string): string {
  return createHash('sha256').update(projectKey, 'utf8').digest('hex');
}

function toIngestHit(hit: ResolvedEgressHit): EgressIngestHit {
  return {
    host: hit.host,
    kind: hit.kind,
    name: hit.name,
    category: hit.category,
    trust: hit.trust,
    network: hit.network,
    method: hit.method,
    transport: hit.transport,
    url: hit.url,
    template: hit.template,
    dataClass: hit.dataClass,
    site: {
      file: hit.site.file,
      line: hit.site.line,
      dynamic: hit.site.dynamic,
      vendored: hit.site.vendored,
    },
  };
}

/**
 * Build the outbound ingest payload for one project's egress-recording unit.
 *
 * Applies the same per-project cap the local write enforces (`capHits`), drops
 * the corresponding files from the reconcile set (`withoutDroppedFiles`), then
 * strips everything that must not leave the device: `site.snippet` (source
 * text), the plaintext `projectKey` (replaced with its digest), and
 * `projectId` (a device-local id the tenant's inventory cannot resolve).
 */
export function toEgressIngestRequest(input: RecordProjectEgressInput): EgressIngestRequest {
  const { hits, droppedFiles } = capHits(input.hits, input.reconcile.mode);
  const reconcile = withoutDroppedFiles(input.reconcile, droppedFiles);
  return {
    projectKey: hashProjectKey(input.projectKey),
    project: input.project,
    reconcile,
    hits: hits.map(toIngestHit),
  };
}
