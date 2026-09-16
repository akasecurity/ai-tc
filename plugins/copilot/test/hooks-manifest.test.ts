/**
 * `hooks.json` is the one file the host reads to decide what to run, and every
 * claim in it is checkable against something else in this tree: the script it
 * names is a build entry, the token it passes is an event this build accepts,
 * and the timeout it registers is the one the watchdog has to beat.
 *
 * None of that is checkable by reading the manifest alone, and all three fail
 * silently in production — a mistyped script path is a hook that never runs, a
 * mistyped token is a hook that returns no opinion, and a timeout under the
 * watchdog is a hook the host kills before it can emit anything. On
 * `preToolUse` the last two are indistinguishable from a deny.
 */
import { existsSync, readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { CLI_EVENTS, VSCODE_EVENTS } from '../src/hooks/event-name.ts';
import { WATCHDOG_MS } from '../src/hooks/shared.ts';

interface HookEntry {
  type?: unknown;
  command?: unknown;
  timeoutSec?: unknown;
}
interface HookGroup {
  hooks?: HookEntry[];
}
interface Manifest {
  hooks?: Record<string, HookGroup[]>;
}

const MANIFEST = JSON.parse(
  readFileSync(new URL('../hooks.json', import.meta.url), 'utf8'),
) as Manifest;

/** The tsup entry KEYS, read out of the build config's own text. */
const ENTRY_KEYS = [
  ...readFileSync(new URL('../tsup.config.ts', import.meta.url), 'utf8').matchAll(
    /^\s*'?([a-z-]+)'?:\s*'src\/[^']+'/gmu,
  ),
].flatMap((m) => (m[1] === undefined ? [] : [m[1]]));

/** Every registered entry, flattened, with the event it is registered under. */
const ENTRIES = Object.entries(MANIFEST.hooks ?? {}).flatMap(([event, groups]) =>
  groups.flatMap((group) => (group.hooks ?? []).map((entry) => ({ event, entry }))),
);

describe('hooks.json', () => {
  it('registers something', () => {
    // The positive control. Every case below loops over ENTRIES and passes on
    // an empty manifest, which is exactly the state a bad edit produces.
    expect(ENTRIES.length).toBeGreaterThan(0);
    expect(ENTRY_KEYS.length).toBeGreaterThan(0);
  });

  it('registers only events this build accepts', () => {
    const known = new Set<string>([...CLI_EVENTS, ...VSCODE_EVENTS]);
    expect(ENTRIES.map(({ event }) => event).filter((event) => !known.has(event))).toEqual([]);
  });

  it('names a script that is a build entry AND was emitted', () => {
    // Both halves, because they fail at different times. A path naming no entry
    // is broken for every install; a path naming an entry the build did not
    // emit is broken only after a build change, and the entry map alone cannot
    // see that. globalSetup has run the real build before this file loads.
    for (const { event, entry } of ENTRIES) {
      const command = String(entry.command);
      const script = /scripts\/([a-z-]+)\.js/u.exec(command)?.[1];
      expect(script, `${event}: no scripts/<name>.js in ${command}`).toBeDefined();
      expect(ENTRY_KEYS, `${event}: ${String(script)} is not a tsup entry`).toContain(script);
      expect(
        existsSync(new URL(`../scripts/${String(script)}.js`, import.meta.url)),
        `${event}: scripts/${String(script)}.js was not emitted`,
      ).toBe(true);
    }
  });

  it('passes its own event name as the argv token', () => {
    // The fact the whole dispatch rests on: seven of the eight recorded CLI
    // payloads carry no event name, so this token is the only thing that tells
    // the script what it was started for. A manifest that registered an event
    // under another one's token would produce a hook that silently declines.
    for (const { event, entry } of ENTRIES) {
      const command = String(entry.command);
      // The token sits between the quoted script path and the quoted manifest
      // path, so it is matched as a bare word rather than by `includes` — which
      // would also match the same string inside a path.
      expect(command, event).toMatch(new RegExp(`\\.js"\\s+${event}(\\s|$)`, 'u'));
    }
  });

  it('passes the plugin manifest at the index build-info reads it from', async () => {
    const { MANIFEST_ARGV_INDEX } = await import('../src/build-info.ts');
    for (const { event, entry } of ENTRIES) {
      // argv[0] and argv[1] are node and the script, so the tokens after the
      // script path start at index 2. The manifest must land on
      // MANIFEST_ARGV_INDEX — one further right than the siblings, because the
      // event token took that place.
      const after = String(entry.command).split(/\s+/u).slice(2);
      expect(after[MANIFEST_ARGV_INDEX - 2], event).toMatch(/plugin\.json"?$/u);
    }
  });

  it('registers a timeout the watchdog can beat', () => {
    // A `timeoutSec` at or under the watchdog means the host kills the hook
    // before it can emit anything — and on `preToolUse` a hook that printed
    // nothing is, at best, unmeasured and at worst a deny.
    for (const { event, entry } of ENTRIES) {
      expect(entry.timeoutSec, event).toBeTypeOf('number');
      expect(Number(entry.timeoutSec) * 1000, event).toBeGreaterThan(WATCHDOG_MS);
    }
  });

  it('declares every entry as a command hook', () => {
    for (const { event, entry } of ENTRIES) expect(entry.type, event).toBe('command');
  });

  it('is the manifest the plugin manifest points at', () => {
    const plugin = JSON.parse(readFileSync(new URL('../plugin.json', import.meta.url), 'utf8')) as {
      hooks?: unknown;
    };
    expect(plugin.hooks).toBe('./hooks.json');
  });
});
