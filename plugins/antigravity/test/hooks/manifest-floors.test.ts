// Every hook event this plugin registers has to be one the running Antigravity
// actually delivers, and nothing else in the suite reads the manifest to check.
//
// The gap that matters is silent, and on this host it arrives two ways that look
// identical from outside. An event name the host does not recognise is dropped
// from the manifest while the rest of the file loads. An event it recognises but
// cannot reach — `Stop` was unreachable behind the built-in termination checks
// until 1.1.10 — loads, lists, and never fires. Either way the plugin installs
// clean, reports healthy, and the protection behind that entry is absent with
// nothing at runtime saying so.
//
// What it cannot degrade into is a DENIAL. This host reads a hook that ran
// and said nothing as a `deny`, but a dropped or unreachable entry spawns no
// process at all, so there is no exit code to misread and the tool call follows
// the host's own permission flow. The failure is absence, not a wedged session.
//
// The floor table is TypeScript and this manifest is JSON, so no compile error
// can bind them. This partition is the binding.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { isParseableBinaryVersion } from '@akasecurity/persistence';
import { ANTIGRAVITY_BASELINE_HOOK_EVENTS, ANTIGRAVITY_HOST_FLOORS } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

// The manifest sits at the PLUGIN ROOT here, not under a `hooks/` directory the
// way the Codex sibling's does, and its shape differs too: the top level maps a
// hook-bundle name to that bundle's event map, where Codex nests everything
// under one `hooks` key.
const manifest: unknown = JSON.parse(
  readFileSync(join(fileURLToPath(new URL('../../', import.meta.url)), 'hooks.json'), 'utf8'),
);

// Keys the host documents INSIDE a bundle that are not events. `enabled` is a
// boolean toggle that sits alongside the event names in the same object, so a
// reader that takes every key as an event would report it as an event with no
// decided floor — a red guard for a reason that is not a defect. Kept as a set
// rather than inlined so the reason has somewhere to be written down.
const NON_EVENT_KEYS = new Set(['enabled']);

// The ONE place a bundle's keys become event names. The manifest reader and the
// case that exercises the filter both drive this function rather than a copy of
// it: an inline second copy goes on passing while this one is removed, which
// leaves the reader the partition actually uses unguarded.
function eventKeysOf(bundle: Record<string, unknown>): string[] {
  return Object.keys(bundle).filter((key) => !NON_EVENT_KEYS.has(key));
}

// A bare `typeof x === 'object'` is not this check: `typeof null` is `'object'`
// and so is `typeof []`. A `hooks.json` holding `null` cleared that form and
// then died in `Object.values(null)` with a raw TypeError naming no gate —
// exactly the un-named red the note below exists to prevent.
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// Both halves are derived inside the cases, never in the describe body. A throw
// while the body evaluates is reported as `Tests no tests` with no gate named,
// which reads green to anything scanning for failed test names; the same throw
// inside a case is an ordinary red with the case's own message on it.
function registeredEvents(): string[] {
  expect(isPlainObject(manifest), 'hooks.json parses to an object').toBe(true);
  const events = Object.values(manifest as Record<string, unknown>).flatMap((bundle) => {
    expect(isPlainObject(bundle), 'each hooks.json bundle is an object').toBe(true);
    return eventKeysOf(bundle as Record<string, unknown>);
  });
  // DEDUPED, because the host's schema maps many bundle names to event maps and
  // two bundles may legitimately hook the same event. The partition halves are
  // compared as sets, so a duplicate left in here fails the exact-set control
  // below on a manifest that is valid and fully classified — a red pointing at
  // the floor table for something that is not a floor problem.
  return [...new Set(events)];
}

function gatedEvents(): string[] {
  return Object.values(ANTIGRAVITY_HOST_FLOORS).flatMap((row) => [...row.hookEvents]);
}

describe('every registered Antigravity hook event has a decided host floor', () => {
  it('gives every floor row the shape the partition reads', () => {
    // Redundant against the table's `Record<AntigravityHostFeature, …>` only
    // while that union is inhabited. Empty the table and `AntigravityHostFeature`
    // collapses to `never`, `Record<never, HostFloorRow>` collapses to `{}`, and
    // the annotation then accepts any non-nullish value — so the next row added
    // without its ANTIGRAVITY_HOST_FEATURE member compiles clean and surfaces
    // as `row.hookEvents is not iterable` from whichever case dereferences it
    // first. Walked as `unknown` deliberately: typing the row as `HostFloorRow`
    // here would assert the very thing this case checks, and the
    // no-unnecessary-condition rule would then reject the guard as dead.
    for (const [feature, row] of Object.entries<unknown>(ANTIGRAVITY_HOST_FLOORS)) {
      const shape = row as { hookEvents?: unknown; since?: unknown } | null;
      expect(Array.isArray(shape?.hookEvents), `${feature} hookEvents is an array`).toBe(true);
      expect(typeof shape?.since, `${feature} since is a string`).toBe('string');
    }
  });

  it('classifies every manifest event as baseline or floor-gated', () => {
    const gated = gatedEvents();
    const unclassified = registeredEvents().filter(
      (event) => !ANTIGRAVITY_BASELINE_HOOK_EVENTS.includes(event) && !gated.includes(event),
    );
    expect(unclassified, 'events with no decided floor').toEqual([]);
  });

  it('names no event the manifest does not register', () => {
    // Both directions, because a row or a baseline entry naming an event this
    // plugin no longer registers is a floor nobody is being warned about.
    // `PostInvocation` is the live example of an event this host has and this
    // plugin does not register: it belongs in neither half, and this case is
    // what would catch it being added to one without being registered.
    const registered = registeredEvents();
    const stranded = [...ANTIGRAVITY_BASELINE_HOOK_EVENTS, ...gatedEvents()].filter(
      (event) => !registered.includes(event),
    );
    expect(stranded, 'floors for events that are not registered').toEqual([]);
  });

  it('puts no event in both halves', () => {
    const gated = gatedEvents();
    const both = registeredEvents().filter(
      (event) => ANTIGRAVITY_BASELINE_HOOK_EVENTS.includes(event) && gated.includes(event),
    );
    expect(both, 'events counted as both baseline and gated').toEqual([]);
  });

  it('gives every floor a version the comparator can actually read', () => {
    // `compareBinaryVersions` answers 0 for an unparseable input and 0 is not
    // < 0, so a typo here makes the row silently never fire — reintroducing the
    // exact silent absence the table exists to report.
    for (const [feature, row] of Object.entries(ANTIGRAVITY_HOST_FLOORS)) {
      expect(isParseableBinaryVersion(row.since), `${feature} since=${row.since}`).toBe(true);
    }
  });

  it('reads past the host non-event keys rather than through them', () => {
    // `enabled` is documented to sit beside the event names inside a bundle, so
    // the filter above is load-bearing rather than defensive: without it,
    // switching a bundle off in the manifest reds the partition as an event with
    // no floor. Driven against a synthetic bundle because the shipped manifest
    // sets no such key — which is exactly why nothing else here would notice.
    expect(eventKeysOf({ enabled: false, Stop: [] })).toEqual(['Stop']);
  });

  it('actually classifies something', () => {
    // The positive control. An EMPTY manifest satisfies every partition above,
    // so without this they would hold vacuously on a file that registers
    // nothing at all — which is also what a manifest read from the wrong path
    // looks like.
    const registered = registeredEvents();
    expect(registered.length).toBeGreaterThan(0);
    // Exact equality against the WHOLE partition, both halves. Comparing
    // against the baseline list alone would red the moment a floor-gated event
    // is registered — the one change this table exists to allow — and say
    // nothing about floors while doing it. Deduped so that an event in both
    // halves is reported by its own case above rather than twice.
    expect([...registered].sort()).toEqual(
      [...new Set([...ANTIGRAVITY_BASELINE_HOOK_EVENTS, ...gatedEvents()])].sort(),
    );
  });

  it('keeps Stop floor-gated rather than baseline', () => {
    // Deliberately an assertion rather than a silence, and the mirror image of
    // the Codex table's "has no floor row" case. Nothing reads an Antigravity
    // version today — the host publishes one through no payload field, no
    // transcript record and no env var — so this row warns nobody, and moving
    // `Stop` into the baseline half would leave every case above green.
    //
    // It would also be false. The baseline half asserts that no supported host
    // is missing the event, and 1.0.0 through 1.1.9 are precisely the hosts
    // where a registered `Stop` hook sits unreachable behind the built-in
    // termination checks and never runs. The row is the honest encoding whether
    // or not anything acts on it; see ANTIGRAVITY_HOST_FLOORS for the release
    // the floor is read from.
    expect(gatedEvents()).toContain('Stop');
    expect(ANTIGRAVITY_BASELINE_HOOK_EVENTS).not.toContain('Stop');
  });
});
