// The hooks manifest is the only thing that connects a host event to a script
// on disk, and every part of that connection is silent when it is wrong: a
// command naming a script the build does not emit fails at spawn, which on
// `preToolUse` the CLI reads as a DENY, and a command carrying the wrong argv
// token dispatches to no event at all and answers "no opinion" forever.
//
// So each half is checked against the thing it names rather than against a
// restatement: the script path against the BUILT `scripts/` directory (the
// suite's globalSetup runs the real tsup first), and the event token against
// the same frozen vocabulary the dispatcher validates with.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { isHookEventName } from '../src/hooks/event-name.ts';
import { WATCHDOG_MS } from '../src/hooks/shared.ts';

const PLUGIN_ROOT = fileURLToPath(new URL('../', import.meta.url));

interface HookCommand {
  type?: string;
  command?: string;
  timeoutSec?: number;
}
interface HookMatcher {
  hooks?: HookCommand[];
}
interface Manifest {
  hooks?: Record<string, HookMatcher[]>;
}

const manifest = JSON.parse(readFileSync(`${PLUGIN_ROOT}hooks.json`, 'utf8')) as Manifest;

/** Every (event, command) pair the manifest registers, flattened. */
const entries: { event: string; command: HookCommand }[] = Object.entries(
  manifest.hooks ?? {},
).flatMap(([event, matchers]) =>
  matchers.flatMap((m) => (m.hooks ?? []).map((command) => ({ event, command }))),
);

describe('hooks.json', () => {
  it('registers at least one command', () => {
    // The positive control. Every case below iterates `entries`, so an empty or
    // mis-shaped manifest would satisfy all of them vacuously.
    expect(entries.length).toBeGreaterThan(0);
  });

  it('keys every entry on an event name the dispatcher knows', () => {
    for (const { event } of entries) expect(isHookEventName(event), event).toBe(true);
  });

  it('passes the event name as the command’s own argv token, matching its key', () => {
    // The token is argv[2] and the key is what the host dispatches on, so a
    // mismatch means the script is told it is handling a different event than
    // the one that fired. `build-info.ts` reads argv[3], so a manifest path may
    // follow; only the FIRST trailing token is the event.
    for (const { event, command } of entries) {
      const line = command.command ?? '';
      const tokens = [...line.matchAll(/"[^"]*"|\S+/g)].map((m) => m[0]);
      const bare = tokens.filter((t) => !t.startsWith('"') && t !== 'node');
      expect(bare, line).toContain(event);
    }
  });

  it('names a script the build actually emits', () => {
    for (const { command } of entries) {
      const line = command.command ?? '';
      const script = /\/scripts\/([A-Za-z0-9-]+\.js)/.exec(line)?.[1];
      expect(script, line).toBeDefined();
      // Against the built directory, not against the tsup entry map: the entry
      // map is what the build was ASKED to emit, and this is what it did.
      expect(existsSync(`${PLUGIN_ROOT}scripts/${script ?? ''}`), script).toBe(true);
    }
  });

  it('declares a timeout the watchdog can beat', () => {
    // The injectable `watchdogMs` parameter must not be able to hide a
    // regression in the shipped default: a default at or past the host's own
    // timeout means the host kills the hook first and nothing is ever printed —
    // which on `preToolUse` is a deny.
    for (const { command } of entries) {
      expect(typeof command.timeoutSec, command.command).toBe('number');
      expect(WATCHDOG_MS).toBeLessThan((command.timeoutSec ?? 0) * 1000);
    }
  });

  it('declares every entry as a command hook', () => {
    for (const { command } of entries) expect(command.type).toBe('command');
  });

  /**
   * The other direction, and the one the checks above cannot see: a hook script
   * the build emits that NO entry names is a capture surface the host never
   * spawns. Nothing fails, nothing is logged, and the events it was written for
   * are simply not covered — which reads exactly like a host that does not fire
   * them.
   *
   * `scan-worker.js` is deliberately excluded: no hook names it, because
   * plugin-sdk starts it by path from whichever hook is running (see
   * `src/scan-worker.ts`), and `test/e2e/scan-worker-bundle.e2e.test.ts` is
   * what holds it to landing beside its siblings.
   */
  it('registers every hook script the build emits', () => {
    const emitted = readdirSync(`${PLUGIN_ROOT}scripts`)
      .filter((name) => name.endsWith('.js') && name !== 'scan-worker.js')
      .sort();
    // The positive control: an empty scripts/ would satisfy the subset check
    // below for free.
    expect(emitted.length).toBeGreaterThan(0);

    const registered = new Set(
      entries.map(
        ({ command }) => /\/scripts\/([A-Za-z0-9-]+\.js)/.exec(command.command ?? '')?.[1],
      ),
    );
    expect(emitted.filter((name) => !registered.has(name))).toEqual([]);
  });

  /**
   * BOTH DIALECTS OR NEITHER. This package covers two hosts that read the same
   * hooks FILE and spell their event names differently (camelCase on the CLI,
   * PascalCase in VS Code). A script registered under one spelling alone is a
   * surface that silently covers one host — and the CLI's names are the ones a
   * developer reaches for first, so VS Code is the half that goes missing.
   *
   * `userPromptTransformed` is deliberately exempt and is the one asymmetry
   * here: VS Code fires no counterpart event, so there is no PascalCase name
   * for it to be registered under.
   */
  it('registers each script under both hosts’ spellings of the event', () => {
    const CLI_ONLY = new Set(['userPromptTransformed']);
    const byScript = new Map<string, string[]>();
    for (const { event, command } of entries) {
      const script = /\/scripts\/([A-Za-z0-9-]+\.js)/.exec(command.command ?? '')?.[1] ?? '';
      byScript.set(script, [...(byScript.get(script) ?? []), event]);
    }
    expect(byScript.size).toBeGreaterThan(0);

    // A PascalCase first letter is VS Code's; a lowercase one is the CLI's.
    const pascal = (event: string): boolean => /^[A-Z]/.test(event);
    for (const [script, events] of byScript) {
      const named = events.filter((event) => !CLI_ONLY.has(event));
      expect(named.some(pascal), `${script}: no VS Code (PascalCase) event`).toBe(true);
      expect(
        named.some((event) => !pascal(event)),
        `${script}: no CLI (camelCase) event`,
      ).toBe(true);
    }
  });
});

describe('plugin.json', () => {
  it('carries the same version as package.json, and points at the two assets', () => {
    // Copilot reads a FLAT root manifest (like Antigravity, unlike Claude Code
    // and Codex, which use a dotted directory), so this file is the one the
    // host loads. Its version drifting from the package's is what makes a
    // release report a build nobody shipped.
    const plugin = JSON.parse(readFileSync(`${PLUGIN_ROOT}plugin.json`, 'utf8')) as {
      version?: string;
      hooks?: string;
      skills?: string;
    };
    const pkg = JSON.parse(readFileSync(`${PLUGIN_ROOT}package.json`, 'utf8')) as {
      version?: string;
    };
    expect(plugin.version).toBe(pkg.version);
    expect(plugin.hooks).toBe('./hooks.json');
    expect(existsSync(`${PLUGIN_ROOT}hooks.json`)).toBe(true);
  });
});
