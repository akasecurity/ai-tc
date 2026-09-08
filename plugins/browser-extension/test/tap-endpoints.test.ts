import { describe, expect, it } from 'vitest';

import { ADAPTERS } from '../src/providers/registry.ts';
import type { ProviderAdapter, ProviderEndpoint } from '../src/providers/types.ts';
import { TAP_ENDPOINTS, toTapEndpoints } from '../src/tap-endpoints.ts';

// The table the MAIN-world tap forwards on is GENERATED from this registry and
// compiled into that bundle. Nothing else decides what the extension observes,
// so what this file holds is the generator: every way a declaration could reach
// the tap as something wider than the adapter meant.

// A complete adapter is mostly DOM half, none of which the generator reads.
// Built here rather than imported so a case can declare an endpoint the shipped
// adapters do not.
function adapterWith(
  hostnames: readonly string[],
  endpoints: readonly ProviderEndpoint[],
): ProviderAdapter {
  return {
    id: 'chatgpt',
    hostnames,
    findComposer: () => null,
    findSendButton: () => null,
    extractText: () => '',
    setText: () => undefined,
    watchSubmit: () => () => undefined,
    submit: () => false,
    endpoints,
    requiredPaths: { request: [], response: [] },
    protocolTokens: [],
    parseRequest: () => ({ requiredPathsSeen: false }),
    parseStream: () => ({ push: () => undefined, end: () => null }),
  };
}

describe('toTapEndpoints', () => {
  it('emits a host and a path SOURCE, never a compiled pattern', () => {
    // The tap has no RegExp to receive — the table crosses an esbuild define as
    // JSON — so the source string is what has to arrive, with the host kept
    // beside it rather than folded into the pattern.
    const table = toTapEndpoints([
      adapterWith(
        ['site.test'],
        [{ host: 'site.test', path: /\/api\/conversation/, kind: 'conversation' }],
      ),
    ]);
    expect(table).toEqual([
      { host: 'site.test', path: '\\/api\\/conversation', kind: 'conversation' },
    ]);
  });

  it('carries every endpoint of every adapter', () => {
    const table = toTapEndpoints([
      adapterWith(
        ['a.test', 'b.test'],
        [
          { host: 'a.test', path: /\/one/, kind: 'conversation' },
          { host: 'b.test', path: /\/two/, kind: 'account' },
        ],
      ),
      adapterWith(['c.test'], [{ host: 'c.test', path: /\/three/, kind: 'conversation' }]),
    ]);
    expect(table.map((entry) => `${entry.host}${entry.path}`)).toEqual([
      'a.test\\/one',
      'b.test\\/two',
      'c.test\\/three',
    ]);
  });

  it('refuses an endpoint on a host the adapter does not drive', () => {
    // The one containment the manifest cannot express. Content-script `matches`
    // decide which PAGES the tap runs on; this decides which ORIGINS it forwards
    // from. An adapter naming a third-party host here would have the tap
    // reporting that host's traffic as the site's own.
    expect(() =>
      toTapEndpoints([
        adapterWith(['site.test'], [{ host: 'other.test', path: /\/x/, kind: 'conversation' }]),
      ]),
    ).toThrow(/other\.test/);
  });

  it('refuses a pattern carrying flags, which the tap drops', () => {
    // The tap recompiles from the source with no flags, so a declared `i` or `g`
    // is discarded in silence — matching that reads case-insensitively here and
    // is not, or a lastIndex that would make matching depend on call order.
    expect(() =>
      toTapEndpoints([
        adapterWith(['site.test'], [{ host: 'site.test', path: /\/x/i, kind: 'conversation' }]),
      ]),
    ).toThrow(/flags/);
  });

  it('refuses a pattern that matches everything', () => {
    // An empty source compiles to `^(?:)`, which matches every path on the host.
    // A table entry says which requests are AKA's business; one that says "all
    // of them" is the absence of a decision, not a broad one.
    expect(() =>
      toTapEndpoints([
        adapterWith(
          ['site.test'],
          [{ host: 'site.test', path: new RegExp(''), kind: 'conversation' }],
        ),
      ]),
    ).toThrow(/empty/);
  });

  it('refuses an adapter that drives no hostname', () => {
    // Reached before the per-endpoint host check, and it has to name the real
    // fault: an adapter with no hostnames also fails `hostnames.includes`, so
    // without this the build would report a valid endpoint as being declared
    // on a host the adapter does not drive.
    expect(() =>
      toTapEndpoints([adapterWith([], [{ host: 'site.test', path: /\/x/, kind: 'conversation' }])]),
    ).toThrow(/no hostnames/);
  });

  it('refuses a path that is not a RegExp', () => {
    // The build reaches this across a type-stripped import, so a string here
    // survives the compiler's absence. It would otherwise fall through to the
    // flags check and be refused as "carries flags (undefined)" — a message
    // pointing an adapter author at a property their declaration does not have.
    const broken = adapterWith(['site.test'], [
      { host: 'site.test', path: '\\/x', kind: 'conversation' },
    ] as unknown as ProviderEndpoint[]);
    expect(() => toTapEndpoints([broken])).toThrow(/not a RegExp/);
  });

  it('refuses an endpoint of a kind nothing classifies', () => {
    // The tap drops `kind` when it compiles its targets, so an unknown one is
    // forwarded exactly like a conversation and then discarded on the far
    // side: traffic left the page for a classification nothing implements.
    const broken = adapterWith(['site.test'], [
      { host: 'site.test', path: /\/x/, kind: 'telemetry' },
    ] as unknown as ProviderEndpoint[]);
    expect(() => toTapEndpoints([broken])).toThrow(/unknown kind "telemetry"/);
  });

  it('refuses an adapter that declares no endpoints array at all', () => {
    // Reached from the build script across a type-stripped import, where the
    // interface is erased and nothing but this check stands between a malformed
    // adapter and a table the tap accepts.
    const broken = { ...adapterWith(['site.test'], []), endpoints: undefined };
    expect(() => toTapEndpoints([broken as unknown as ProviderAdapter])).toThrow(/endpoints/);
  });

  it('refuses an empty registry rather than emitting an empty table', () => {
    // An empty table is indistinguishable from a working tap that matches
    // nothing, which is the one failure this design cannot see from outside. A
    // registry with no adapters in it is a broken read, not a configuration.
    expect(() => toTapEndpoints([])).toThrow(/no adapters/);
  });
});

describe('TAP_ENDPOINTS, the table this build ships', () => {
  it('is derived from the shipped registry', () => {
    expect(TAP_ENDPOINTS).toEqual(toTapEndpoints(ADAPTERS));
  });

  it('names only hosts the registry drives', () => {
    // Vacuous while no adapter declares an endpoint, and deliberately kept:
    // it is the assertion that starts doing work the moment the traffic survey
    // lands one, which is the same moment the tap first observes anything.
    const driven = new Set(ADAPTERS.flatMap((adapter) => adapter.hostnames));
    for (const entry of TAP_ENDPOINTS) {
      expect(driven, `${entry.host} is not a hostname any adapter drives`).toContain(entry.host);
    }
  });
});
