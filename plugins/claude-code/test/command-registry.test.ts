import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  readRegisteredCommands,
  selectRegisteredCommands,
  selectSecretScanContinuation,
} from '../src/command-registry.ts';
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

describe('chaining-line secret-scan continuation selection', () => {
  // The chaining line names a single specific secret-scan continuation
  // command, resolved against the installed registry through the same per-surface
  // selection mechanism — never a hardcoded bare string, never the full registry.
  // The continuation is registered under `/aka:scan` today and moves to
  // `/aka:secretscan` once the dedicated secret-scan command exists; the selection
  // resolves to whichever name is actually registered, in either ship order.
  it('returns exactly one command, a member of the registered set', () => {
    const selected = selectSecretScanContinuation();
    expect(typeof selected).toBe('string');
    expect(readRegisteredCommands()).toContain(selected);
  });

  it('resolves to the single registered secret-scan command today (/aka:scan)', () => {
    const registry = readRegisteredCommands();
    expect(registry).toContain('/aka:scan');
    expect(registry).not.toContain('/aka:secretscan');
    expect(selectSecretScanContinuation()).toBe('/aka:scan');
  });

  it('is a strict single-element curated subset, never the full registry', () => {
    const registry = readRegisteredCommands();
    expect(registry.length).toBeGreaterThan(1);
    const selected = selectSecretScanContinuation(registry);
    // One specific command drawn from — but not equal to — the whole registry.
    expect(Array.isArray(selected)).toBe(false);
    expect(registry).toContain(selected);
    expect(registry.filter((c) => c === selected)).toHaveLength(1);
  });

  it('resolves to /aka:secretscan once the rename registers it (either ship order)', () => {
    // Post-rename registry: the working-tree scan is `/aka:codescan` and the new
    // `/aka:secretscan` carries the secret-scan continuation.
    const renamed = ['/aka:codescan', '/aka:secretscan', '/aka:dashboard'];
    expect(selectSecretScanContinuation(renamed)).toBe('/aka:secretscan');
  });

  it('prefers /aka:secretscan when both names are briefly registered', () => {
    const both = ['/aka:scan', '/aka:secretscan', '/aka:dashboard'];
    expect(selectSecretScanContinuation(both)).toBe('/aka:secretscan');
  });

  it('fails the build (throws) when no secret-scan continuation is registered', () => {
    // A stubbed registry with the curated command removed — the selection must
    // fail loud rather than render a call-to-action the user cannot invoke.
    const withoutSecretScan = readRegisteredCommands().filter(
      (c) => c !== '/aka:scan' && c !== '/aka:secretscan',
    );
    expect(() => selectSecretScanContinuation(withoutSecretScan)).toThrow();
  });
});

describe('shipped command prose names commands in their invokable form', () => {
  // These files reach the user either way — scan.md's description is shown, and
  // setup.md is the wizard script the model follows and quotes from. A command
  // file `foo.md` registers as `/aka:foo`, so a bare `/foo` in that prose is a
  // call-to-action nobody can invoke. Two had drifted with nothing looking at
  // them, which is what this scan is for.
  const PLUGIN_DIR = fileURLToPath(new URL('..', import.meta.url));
  const COMMANDS_DIR = join(PLUGIN_DIR, 'commands');
  const NAMES = readRegisteredCommands().map((c) => c.replace('/aka:', ''));

  // Every markdown file the tarball carries, not just commands/. npm ships the
  // `files` entries plus README.md whether or not it is listed — confirmed
  // against `npm pack --dry-run`, where README.md appears despite its absence
  // from `files`. Scanning commands/ alone left the README, which names four
  // commands and is the most-read page here, guarded by nothing.
  const pkg = JSON.parse(readFileSync(join(PLUGIN_DIR, 'package.json'), 'utf8')) as {
    files?: string[];
  };
  const SHIPPED_ROOTS = [...(pkg.files ?? []), 'README.md'];

  // `scripts/` is build output and may be absent before a build, so a missing
  // root is skipped rather than fatal — the coverage assertion below is what
  // catches a walk that silently found nothing.
  const shippedMarkdown = (): string[] => {
    const found: string[] = [];
    for (const root of SHIPPED_ROOTS) {
      const abs = join(PLUGIN_DIR, root);
      if (!existsSync(abs)) continue;
      if (statSync(abs).isFile()) {
        if (abs.endsWith('.md')) found.push(root);
        continue;
      }
      for (const entry of readdirSync(abs, { recursive: true, withFileTypes: true })) {
        if (entry.isFile() && entry.name.endsWith('.md')) {
          found.push(relative(PLUGIN_DIR, join(entry.parentPath, entry.name)));
        }
      }
    }
    return found;
  };

  // `/aka:foo` contains no `/foo` substring — its only slash is followed by `a` —
  // so a bare occurrence is exactly what this matches. The leading class rejects a
  // path segment or URL tail (`scripts/scan-worker.js`, `~/.aka/data`), which is
  // the only shape that would otherwise read as a bare command.
  const bareForm = (): RegExp => new RegExp(`(^|[^A-Za-z0-9_:/.\\-])/(${NAMES.join('|')})\\b`, 'g');

  const scan = (text: string): string[] =>
    text
      .split('\n')
      .flatMap((line, i) =>
        [...line.matchAll(bareForm())].map((m) => `${String(i + 1)}: ${m[0].trim()}`),
      );

  it('no shipped markdown names a bare /<command>', () => {
    const offenders = shippedMarkdown().flatMap((rel) =>
      scan(readFileSync(join(PLUGIN_DIR, rel), 'utf8')).map((hit) => `${rel}:${hit}`),
    );
    expect(offenders).toEqual([]);
  });

  it('the walk reaches the README and every command file', () => {
    // A walk that found nothing reports an empty offender list, which reads
    // exactly like a clean tree — so pin what it must have covered.
    const walked = new Set(shippedMarkdown());
    expect(walked).toContain('README.md');
    for (const f of readdirSync(COMMANDS_DIR).filter((n) => n.endsWith('.md'))) {
      expect(walked).toContain(join('commands', f));
    }
  });

  it('the matcher catches a bare form and passes the namespaced one', () => {
    // Without this control a broken pattern reports an empty offender list for
    // ever, which reads exactly like a clean tree.
    expect(scan('visible via `/findings`.')).toHaveLength(1);
    expect(scan('and pointed at `/health`.')).toHaveLength(1);
    expect(scan('Run /recommend to review 5 prioritized actions.')).toHaveLength(1);

    // The namespaced form is what every corrected site uses.
    expect(scan('visible via `/aka:findings`.')).toEqual([]);
    expect(scan('Run /aka:recommend <n> to act on one, or /aka:health.')).toEqual([]);

    // Paths and URLs carry these words after a slash and are not commands.
    expect(scan('scripts/scan-worker.js and ~/.aka/data/aka.db')).toEqual([]);
    expect(scan('see https://example.com/health for more')).toEqual([]);
  });
});
