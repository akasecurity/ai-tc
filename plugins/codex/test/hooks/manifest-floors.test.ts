// Every hook event this plugin registers has to be one Codex actually
// recognises, and nothing else in the suite reads the manifest to check.
//
// The gap that matters is silent. Codex parses `hooks.json` into a struct with
// one named field per event; that struct does not opt into rejecting unknown
// fields, so an event Codex does not know is dropped from the parse while the
// rest of the file loads. The plugin then installs clean, reports healthy, and
// the protection behind the dropped entry is simply absent — no error, no
// warning, nothing at runtime that says so.
//
// The floor table is TypeScript and this manifest is JSON, so no compile error
// can bind them. This partition is the binding.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { isParseableBinaryVersion } from '@akasecurity/persistence';
import {
  CODEX_BASELINE_HOOK_EVENTS,
  CODEX_HOST_FLOORS,
  type HostFloorRow,
} from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

const manifest: unknown = JSON.parse(
  readFileSync(
    join(fileURLToPath(new URL('../../', import.meta.url)), 'hooks', 'hooks.json'),
    'utf8',
  ),
);

// Widened to a string key on purpose: the table is declared
// `Record<CodexHostFeature, HostFloorRow>`, and while there are no features that
// key is `never`, which collapses the type to `{}` — so `Object.values` yields
// `unknown` and every row access below fails to compile. It is an assignment
// rather than a cast, so it keeps working unchanged once rows exist.
//
// That collapse is also why the row-shape case below exists. `{}` accepts any
// non-nullish value, so while the table is empty its annotation validates
// NOTHING — a malformed first row typechecks clean.
const floors: Record<string, HostFloorRow> = CODEX_HOST_FLOORS;

// Both halves are derived inside the cases, never in the describe body. A throw
// while the body evaluates is reported as `Tests no tests` with no gate named,
// which reads green to anything scanning for failed test names; the same throw
// inside a case is an ordinary red with the case's own message on it.
function registeredEvents(): string[] {
  const hooks = (manifest as { hooks?: unknown }).hooks;
  expect(hooks, 'hooks.json carries a top-level `hooks` object').toBeTypeOf('object');
  return Object.keys(hooks as Record<string, unknown>);
}

function gatedEvents(): string[] {
  return Object.values(floors).flatMap((row) => [...row.hookEvents]);
}

describe('every registered Codex hook event has a decided host floor', () => {
  it('gives every floor row the shape the partition reads', () => {
    // Runs before anything dereferences a row, because the type cannot: with
    // `CodexHostFeature` at `never` the annotation on the table checks nothing,
    // so a row added without its `CODEX_HOST_FEATURE` member compiles. Without
    // this, such a row surfaces as `row.hookEvents is not iterable`.
    // Walked as `unknown` deliberately. Typing the row as `HostFloorRow` here
    // would assert the very thing this case exists to check, and the
    // no-unnecessary-condition rule would then reject the guard as dead.
    for (const [feature, row] of Object.entries<unknown>(floors)) {
      const shape = row as { hookEvents?: unknown; since?: unknown } | null;
      expect(Array.isArray(shape?.hookEvents), `${feature} hookEvents is an array`).toBe(true);
      expect(typeof shape?.since, `${feature} since is a string`).toBe('string');
    }
  });

  it('classifies every manifest event as baseline or floor-gated', () => {
    const gated = gatedEvents();
    const unclassified = registeredEvents().filter(
      (event) => !CODEX_BASELINE_HOOK_EVENTS.includes(event) && !gated.includes(event),
    );
    expect(unclassified, 'events with no decided floor').toEqual([]);
  });

  it('names no event the manifest does not register', () => {
    // Both directions, because a row or a baseline entry naming an event this
    // plugin no longer registers is a floor nobody is being warned about.
    const registered = registeredEvents();
    const stranded = [...CODEX_BASELINE_HOOK_EVENTS, ...gatedEvents()].filter(
      (event) => !registered.includes(event),
    );
    expect(stranded, 'floors for events that are not registered').toEqual([]);
  });

  it('puts no event in both halves', () => {
    const gated = gatedEvents();
    const both = registeredEvents().filter(
      (event) => CODEX_BASELINE_HOOK_EVENTS.includes(event) && gated.includes(event),
    );
    expect(both, 'events counted as both baseline and gated').toEqual([]);
  });

  it('gives every floor a version the comparator can actually read', () => {
    // `compareBinaryVersions` answers 0 for an unparseable input and 0 is not
    // < 0, so a typo here makes the row silently never fire — reintroducing the
    // exact silent absence the table exists to report.
    for (const [feature, row] of Object.entries(floors)) {
      expect(isParseableBinaryVersion(row.since), `${feature} since=${row.since}`).toBe(true);
    }
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
      [...new Set([...CODEX_BASELINE_HOOK_EVENTS, ...gatedEvents()])].sort(),
    );
  });

  it('has no floor row, because no registered event needs one', () => {
    // Deliberately an assertion rather than a silence. Codex 0.117.0 recognised
    // exactly the five events this plugin registers, and every event added
    // since is one it does not register, so there is nothing to warn about and
    // no row to write.
    //
    // This case is what makes adding the first row a decision rather than an
    // edit: it fails, and the thing to settle before deleting it is that
    // something can SOUNDLY read a Codex version at all. Codex records one only
    // in the `session_meta` line that opens a rollout file, written when the
    // session is created and not rewritten when one is resumed — so on a
    // resumed session that line names the host that started it, not the host
    // running now. A row landing before a reader that gates on a fresh start
    // would tell users who had just upgraded to upgrade.
    expect(Object.keys(floors), 'floor rows with no reader to act on them').toEqual([]);
  });
});
