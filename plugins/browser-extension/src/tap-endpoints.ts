// The MAIN-world tap's endpoint table, derived from the adapter registry.
//
// The tap takes no commands — it shares the page's window event target, so a
// table it could be told at runtime is a table the page could set — which means
// what it forwards is fixed when the extension is built. scripts/build.mjs
// calls this and injects the result as an esbuild `define`. Nothing about the
// list is hand-written on either side.
//
// Everything below REFUSES rather than skips. A generated table is the only
// thing deciding what the extension observes, and an entry silently dropped
// leaves a tap that matches less than the adapters declare, reporting itself
// healthy — the failure this design cannot see from the outside. A build that
// cannot produce a faithful table must fail loudly instead.
import { ADAPTERS } from './providers/registry.ts';
import type { ProviderAdapter, ProviderEndpoint } from './providers/types.ts';
import type { TapEndpoint } from './tap-protocol.ts';

const ENDPOINT_KINDS: readonly ProviderEndpoint['kind'][] = ['conversation', 'account'];

// Wrapped rather than called inline: TypeScript's Array.isArray narrows a
// `readonly T[]` binding to `any[]` in the branch after it, so every read of
// that binding downstream goes unchecked — the opposite of what a runtime guard
// is for.
function isArray(value: unknown): boolean {
  return Array.isArray(value);
}

function fail(message: string): never {
  throw new Error(`cannot generate the tap endpoint table: ${message}`);
}

/**
 * Turn every adapter's declared endpoints into the host/path pairs the tap
 * compiles against.
 *
 * `path` arrives as a RegExp and leaves as its SOURCE: the table crosses a
 * build-time define as JSON, and the tap rebuilds it as `^(?:<source>)` with no
 * flags. That is why a declaration carrying flags is refused here — they would
 * be dropped in silence, so an adapter's `/x/i` would match case-sensitively
 * while reading as though it did not.
 */
export function toTapEndpoints(adapters: readonly ProviderAdapter[]): TapEndpoint[] {
  // The build reaches this across a type-stripped import, where the interface
  // is erased and these are the only checks standing.
  if (!isArray(adapters)) fail('the adapter registry is not an array');
  if (adapters.length === 0) fail('the adapter registry holds no adapters');

  const table: TapEndpoint[] = [];
  for (const adapter of adapters) {
    const hostnames: readonly string[] = adapter.hostnames;
    if (!isArray(hostnames) || hostnames.length === 0) {
      fail(`adapter "${adapter.id}" declares no hostnames`);
    }
    const endpoints: readonly ProviderEndpoint[] = adapter.endpoints;
    if (!isArray(endpoints)) {
      fail(`adapter "${adapter.id}" declares no endpoints array`);
    }
    for (const endpoint of endpoints) {
      const where = `adapter "${adapter.id}"`;
      if (!hostnames.includes(endpoint.host)) {
        // Content-script `matches` decide which PAGES the tap runs on; this
        // decides which ORIGINS it forwards from. An adapter naming a host it
        // does not drive would have the tap reporting a third party's traffic
        // as this site's own.
        fail(`${where} declares an endpoint on ${endpoint.host}, a host it does not drive`);
      }
      if (!(endpoint.path instanceof RegExp)) {
        fail(`${where} declares an endpoint whose path is not a RegExp`);
      }
      if (endpoint.path.flags !== '') {
        fail(`${where} declares an endpoint whose path carries flags (${endpoint.path.flags})`);
      }
      if (endpoint.path.source === '' || endpoint.path.source === '(?:)') {
        // An empty source anchors to `^(?:)`, which matches every path on the
        // host. A table entry says which requests are AKA's business; one that
        // says "all of them" is the absence of a decision rather than a broad
        // one.
        fail(`${where} declares an endpoint with an empty path pattern`);
      }
      if (!ENDPOINT_KINDS.includes(endpoint.kind)) {
        fail(`${where} declares an endpoint of unknown kind "${endpoint.kind}"`);
      }
      table.push({ host: endpoint.host, path: endpoint.path.source, kind: endpoint.kind });
    }
  }
  return table;
}

// What this build ships. Empty while no adapter declares an endpoint, so the
// shipped tap matches nothing — see each adapter's own note on why a guessed
// URL is worse than none.
export const TAP_ENDPOINTS: readonly TapEndpoint[] = toTapEndpoints(ADAPTERS);
