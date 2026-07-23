// Composes one project's raw extraction output — URL/IP hits per file plus
// manifest SDK hits per file — with the provider registry into the resolved,
// deduplicated shape the store writer consumes.
//
// Pure like everything in @akasecurity/detections: no I/O, no Node-API
// imports.
import type { HttpMethod, ResolvedEgressHit } from '@akasecurity/schema';

import type { RawEndpointHit } from './extract.ts';
import type { ManifestSdkHit } from './manifests.ts';
import { resolveHost, resolveSdk } from './registry.ts';

/** One file's raw extraction output, ready for resolution. */
export interface FileEgressHits {
  /** A posix path relative to the project root, as recorded by the caller. */
  file: string;
  vendored: boolean;
  endpoints: RawEndpointHit[];
  sdkHits: ManifestSdkHit[];
}

const VERB_METHODS: ReadonlySet<HttpMethod> = new Set(['GET', 'POST', 'PUT', 'DELETE']);

/**
 * Resolve every file's raw URL/IP and SDK hits into fully resolved egress
 * observations, ready for the store writer. A URL/IP hit whose host
 * `resolveHost` excludes, or an SDK hit for a package `resolveSdk` does not
 * recognize, is dropped. The remaining hits are then deduplicated: exact
 * `(host, method, url, file, line)` duplicates collapse, and a `REF` hit is
 * dropped when a verb-method hit shares its `(host, url)` anywhere in the
 * batch.
 */
export function resolveEgress(
  files: FileEgressHits[],
  opts?: { internalDomains?: string[] },
): ResolvedEgressHit[] {
  const resolved: ResolvedEgressHit[] = [];

  for (const file of files) {
    for (const endpoint of file.endpoints) {
      const hit = resolveEndpointHit(file, endpoint, opts);
      if (hit !== null) resolved.push(hit);
    }
    for (const sdkHit of file.sdkHits) {
      const hit = resolveSdkHit(file, sdkHit);
      if (hit !== null) resolved.push(hit);
    }
  }

  return dropRefsWithVerbSibling(dedupeExact(resolved));
}

// A URL/IP hit's host decides kind/trust/name/category via the registry.
// Provider hits take the registry's most-sensitive default data class and
// carry no network shape; every other kind carries the observed port with no
// geo/PTR enrichment (this pass performs no DNS or geo lookup).
function resolveEndpointHit(
  file: FileEgressHits,
  endpoint: RawEndpointHit,
  opts?: { internalDomains?: string[] },
): ResolvedEgressHit | null {
  const resolution = resolveHost(endpoint.host, opts);
  if (resolution === null) return null;

  const isProvider = resolution.kind === 'provider';
  return {
    host: endpoint.host,
    kind: resolution.kind,
    name: resolution.name,
    category: resolution.category,
    trust: resolution.trust,
    network: isProvider ? null : { port: endpoint.port, geo: null, ptr: null },
    method: endpoint.method,
    transport: endpoint.transport,
    url: endpoint.url,
    template: endpoint.template,
    dataClass: isProvider ? (resolution.entry?.defaultDataClasses[0] ?? 'none') : 'none',
    site: {
      file: file.file,
      line: endpoint.line,
      snippet: endpoint.snippet,
      dynamic: endpoint.template,
      vendored: file.vendored,
    },
  };
}

// A manifest SDK dependency the registry recognizes becomes a synthetic
// endpoint at the provider's canonical API base — there is no URL literal to
// observe, so the manifest declaration line stands in for the call site.
function resolveSdkHit(file: FileEgressHits, sdkHit: ManifestSdkHit): ResolvedEgressHit | null {
  const entry = resolveSdk(sdkHit.ecosystem, sdkHit.pkg);
  if (entry === null) return null;

  return {
    host: new URL(entry.apiBase).hostname,
    kind: 'provider',
    name: entry.name,
    category: entry.category,
    trust: 'recognized',
    network: null,
    method: 'SDK',
    transport: 'https',
    url: entry.apiBase,
    template: false,
    dataClass: entry.defaultDataClasses[0] ?? 'none',
    site: {
      file: file.file,
      line: sdkHit.line,
      snippet: sdkHit.snippet,
      dynamic: false,
      vendored: file.vendored,
    },
  };
}

// Exact-duplicate collapse: same host, method, url, file, and line.
function dedupeExact(hits: ResolvedEgressHit[]): ResolvedEgressHit[] {
  const seen = new Set<string>();
  const deduped: ResolvedEgressHit[] = [];
  for (const hit of hits) {
    const key = exactKey(hit);
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(hit);
  }
  return deduped;
}

function exactKey(hit: ResolvedEgressHit): string {
  return JSON.stringify([hit.host, hit.method, hit.url, hit.site.file, hit.site.line]);
}

// A REF hit is a URL reference with no method evidence of its own. Once a
// verb-method hit proves the same (host, url) pair really is called, the REF
// hit adds nothing and is dropped — checked across the whole batch, not just
// the file that produced it.
function dropRefsWithVerbSibling(hits: ResolvedEgressHit[]): ResolvedEgressHit[] {
  const verbPairs = new Set<string>();
  for (const hit of hits) {
    if (VERB_METHODS.has(hit.method)) verbPairs.add(pairKey(hit));
  }
  return hits.filter((hit) => hit.method !== 'REF' || !verbPairs.has(pairKey(hit)));
}

function pairKey(hit: ResolvedEgressHit): string {
  return JSON.stringify([hit.host, hit.url]);
}
