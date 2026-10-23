// The device-side projection of a project's egress-recording unit onto the
// wire-boundary-safe shape every forwarding surface sends. This is the ONLY
// place that builds an `EgressIngestRequest` — no caller hand-rolls the
// payload, so the privacy boundary has exactly one implementation.
//
// It sits in this package, beside the cap helpers it applies, because the
// plugin gateways are not the only callers: the CLI and the dashboard record
// the same register and neither may depend on the plugin stack. A projection
// living above that line would have had to be written twice, and two copies of
// a privacy boundary is one copy too many.
//
// How a repository is KEYED lives in ./repo-key.ts and is re-exported here, so
// every existing importer of this module keeps working. That split is not
// cosmetic: the cap helpers below reach a SQLite repository whose syntax Node's
// strip-only loader refuses, which would otherwise make the canonicalization
// unreachable from any raw-Node child. See that module's header.
import type {
  EgressCredentialRef as EgressCredentialRefT,
  EgressIngestHit,
  EgressIngestRequest,
  RecordProjectEgressInput,
  ResolvedEgressHit,
} from '@akasecurity/schema';
import { CREDENTIAL_REFS_PER_CALL_SITE_MAX, EgressCredentialRef } from '@akasecurity/schema';

import { hashProjectKey } from './repo-key.ts';
import { capHits, withoutDroppedFiles } from './repositories/shares.ts';

export {
  canonicalGitUrl,
  canonicalRepoUrl,
  enrollableRepoKey,
  hashProjectKey,
  namesARemoteAddress,
  parseGitRemote,
  PROJECT_KEY_DIGEST_VERSION,
  respelledRepoKey,
  scopeKeyOfProjectKey,
} from './repo-key.ts';

function wireCredentialRefs(hit: ResolvedEgressHit): EgressCredentialRefT[] {
  const refs: EgressCredentialRefT[] = [];
  for (const ref of hit.credentialRefs ?? []) {
    const parsed = EgressCredentialRef.safeParse(ref);
    if (parsed.success) refs.push(parsed.data);
  }
  return refs.slice(0, CREDENTIAL_REFS_PER_CALL_SITE_MAX);
}

function toIngestHit(hit: ResolvedEgressHit, shareCredentialRefs: boolean): EgressIngestHit {
  const refs = shareCredentialRefs ? wireCredentialRefs(hit) : [];
  return {
    host: hit.host,
    kind: hit.kind,
    name: hit.name,
    category: hit.category,
    providerId: hit.providerId,
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
    ...(refs.length === 0 ? {} : { credentialRefs: refs }),
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
 *
 * A call site's credential references are carried only when
 * `opts.credentialRefs` is true, which a caller sets only while this machine
 * shares credential sightings and holds a sighting key.
 */
export function toEgressIngestRequest(
  input: RecordProjectEgressInput,
  opts: { credentialRefs?: boolean } = {},
): EgressIngestRequest {
  const shareCredentialRefs = opts.credentialRefs === true;
  const { hits, droppedFiles } = capHits(input.hits, input.reconcile.mode);
  const reconcile = withoutDroppedFiles(input.reconcile, droppedFiles);
  return {
    projectKey: hashProjectKey(input.projectKey),
    project: input.project,
    reconcile,
    hits: hits.map((hit) => toIngestHit(hit, shareCredentialRefs)),
  };
}
