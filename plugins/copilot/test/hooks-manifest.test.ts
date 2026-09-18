/**
 * `hooks.json` is the one file the host reads to decide what to run, and every
 * claim in it is checkable against something else in this tree: the script it
 * names is a build entry, the token it passes is an event this build accepts,
 * and the timeout it registers is the one the watchdog has to beat.
 *
 * None of that is checkable by reading the manifest alone, and all three fail
 * silently in production — a mistyped script path is a hook that never runs, a
 * mistyped token is a hook that returns no opinion, and a timeout under the
 * watchdog is a hook the host kills before it can emit anything. All three end
 * the same way on `preToolUse`: the tool call goes through unscanned, and
 * nothing anywhere says a scan was skipped.
 *
 * The CASING of the keys is checkable here too, and is not cosmetic — the CLI
 * selects its payload format by it, so this file decides how many times the
 * hook runs per tool call as well as when.
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

  it('registers NO PascalCase event, because the CLI honours both casings', () => {
    // This file is read by the Copilot CLI, and its hooks reference selects the
    // payload format by the event name's casing: camelCase gives the CLI's own
    // envelope, PascalCase gives a VS Code-compatible one. Both are valid keys
    // HERE, so registering `preToolUse` and `PreToolUse` together does not
    // serve two hosts — it spawns this script twice per tool call on the one
    // host that ships, the second time with a payload whose `tool_name` is the
    // Claude spelling (`Bash`, not `bash`) that `VSCODE_SCANNABLE_FIELDS` has
    // no row for. A wasted 30s-budget process per call, scanning nothing.
    //
    // A VS Code entry belongs in the file VS Code itself reads. Asserted
    // against the PascalCase vocabulary rather than against a hardcoded
    // 'PreToolUse', so a second PascalCase event added later is caught too.
    const pascal = new Set<string>(VSCODE_EVENTS);
    expect(ENTRIES.map(({ event }) => event).filter((event) => pascal.has(event))).toEqual([]);
    // …and the camelCase half is really there, or the line above passes on an
    // empty manifest and says nothing at all.
    expect(Object.keys(MANIFEST.hooks ?? {})).toEqual(['preToolUse']);
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
    // before it can emit anything. A killed hook is not the same as a silent
    // one: the CLI documents a timeout as fail-open, so the call is allowed
    // through UNSCANNED and any deny the hook had reached is lost.
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
