import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { readRegisteredCommands, selectRegisteredCommands } from '../src/command-registry.ts';
import { READY_COMMANDS, TRY_COMMANDS } from '../src/render.ts';

// The real shipped command set, read straight from disk the same way the plugin
// registers commands — a renamed or removed command file is caught here, never a
// hardcoded copy that silently rots.
const REGISTERED = readdirSync(fileURLToPath(new URL('../commands', import.meta.url)))
  .filter((f) => f.endsWith('.md'))
  .map((f) => `/aka:${f.replace(/\.md$/, '')}`);

describe('command registry', () => {
  it('reads the shipped commands/*.md set as invokable /aka: names', () => {
    const registry = readRegisteredCommands();
    expect([...registry].sort()).toEqual([...REGISTERED].sort());
    // A known shipped command resolves in its invokable form.
    expect(registry).toContain('/aka:dashboard');
    expect(registry).toContain('/aka:scan');
  });

  it('returns a curated set unchanged once every entry is a registered command', () => {
    expect(selectRegisteredCommands(['/aka:dashboard', '/aka:scan'], REGISTERED)).toEqual([
      '/aka:dashboard',
      '/aka:scan',
    ]);
  });

  it('throws loud when a curated command is absent from the registry', () => {
    expect(() => selectRegisteredCommands(['/aka:nope'], REGISTERED)).toThrow(/aka:nope/);
  });

  it('selects a single specific command — curation down to one, never a full-registry dump', () => {
    // A one-element curated set resolves to exactly that one validated command,
    // not the whole registry. This is the property a chaining line that suggests a
    // single specific continuation command depends on to name exactly one.
    expect(REGISTERED.length).toBeGreaterThan(1);
    const one = selectRegisteredCommands(['/aka:scan'], REGISTERED);
    expect(one).toEqual(['/aka:scan']);
    expect(one).toHaveLength(1);
  });
});

describe('per-surface curated sets resolve against the installed registry', () => {
  // The build-failing guard: every surface's curated command must exist in the
  // shipped command set, so no rendered line can name a command the plugin does
  // not register. A curated command with no matching file fails the build here.
  it('the Try line curated set names only registered commands', () => {
    const registry = readRegisteredCommands();
    expect(() => selectRegisteredCommands(TRY_COMMANDS, registry)).not.toThrow();
    for (const cmd of TRY_COMMANDS) {
      expect(registry).toContain(cmd);
    }
  });

  it('fails when a curated command is removed from the registry', () => {
    const withoutDashboard = readRegisteredCommands().filter((c) => c !== '/aka:dashboard');
    expect(() => selectRegisteredCommands(TRY_COMMANDS, withoutDashboard)).toThrow();
  });

  it('the Ready line curated set names only registered commands', () => {
    const registry = readRegisteredCommands();
    expect(() => selectRegisteredCommands(READY_COMMANDS, registry)).not.toThrow();
    for (const cmd of READY_COMMANDS) {
      expect(registry).toContain(cmd);
    }
  });

  it('fails when a curated Ready command is removed from the registry', () => {
    const withoutHealth = readRegisteredCommands().filter((c) => c !== '/aka:health');
    expect(() => selectRegisteredCommands(READY_COMMANDS, withoutHealth)).toThrow();
  });

  it('curates a Ready subset deliberately distinct from the Try line', () => {
    // The two surfaces suggest different subsets — neither is the whole registry
    // and the Ready line names none of the Try line's commands.
    expect([...READY_COMMANDS]).not.toEqual([...TRY_COMMANDS]);
    const tryable = new Set<string>(TRY_COMMANDS);
    for (const cmd of READY_COMMANDS) {
      expect(tryable.has(cmd)).toBe(false);
    }
  });

  it('neither surface enumerates the full registry — each names a strict curated subset', () => {
    // The contract is per-surface curation, not a full-registry dump: with a
    // registry of ~10 commands, each surface names only its own few. A surface
    // that grew to name every registered command would fail here.
    const registry = readRegisteredCommands();
    expect(registry.length).toBeGreaterThan(TRY_COMMANDS.length);
    expect(registry.length).toBeGreaterThan(READY_COMMANDS.length);
    // Combined, the two surfaces still do not cover the whole registry — proof
    // no line is silently enumerating everything the plugin registers.
    const named = new Set([...TRY_COMMANDS, ...READY_COMMANDS]);
    expect(named.size).toBeLessThan(registry.length);
  });
});
