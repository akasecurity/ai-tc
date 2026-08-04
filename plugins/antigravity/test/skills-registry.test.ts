import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { READY_SKILLS, TRY_SKILLS } from '../src/render.ts';
import {
  readRegisteredSkills,
  selectRegisteredSkills,
  selectSecretScanContinuation,
} from '../src/skills-registry.ts';

// The real shipped skill set, read straight from disk the same way the plugin
// registers skills — a renamed or removed SKILL.md is caught here, never a
// hardcoded copy that silently rots.
const SKILLS_DIR = fileURLToPath(new URL('../skills', import.meta.url));
const REGISTERED = readdirSync(SKILLS_DIR, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => {
    const content = readFileSync(join(SKILLS_DIR, entry.name, 'SKILL.md'), 'utf8');
    return /^name:\s*(.+?)\s*$/m.exec(content)?.[1] ?? '';
  })
  .filter((name) => name !== '');

describe('skill registry', () => {
  it('reads the shipped skills/*/SKILL.md set as the frontmatter-declared names', () => {
    const registry = readRegisteredSkills();
    expect([...registry].sort()).toEqual([...REGISTERED].sort());
    // A known shipped skill resolves under its declared name.
    expect(registry).toContain('aka-dashboard');
    expect(registry).toContain('aka-scan');
  });

  it('returns a curated set unchanged once every entry is a registered skill', () => {
    expect(selectRegisteredSkills(['aka-dashboard', 'aka-scan'], REGISTERED)).toEqual([
      'aka-dashboard',
      'aka-scan',
    ]);
  });

  it('throws loud when a curated skill is absent from the registry', () => {
    expect(() => selectRegisteredSkills(['aka-nope'], REGISTERED)).toThrow(/aka-nope/);
  });

  it('selects a single specific skill — curation down to one, never a full-registry dump', () => {
    // A one-element curated set resolves to exactly that one validated skill,
    // not the whole registry. This is the property a chaining line that suggests a
    // single specific continuation skill depends on to name exactly one.
    expect(REGISTERED.length).toBeGreaterThan(1);
    const one = selectRegisteredSkills(['aka-scan'], REGISTERED);
    expect(one).toEqual(['aka-scan']);
    expect(one).toHaveLength(1);
  });
});

describe('per-surface curated sets resolve against the installed registry', () => {
  // The build-failing guard: every surface's curated skill must exist in the
  // shipped skill set, so no rendered line can name a skill the plugin does
  // not register. A curated skill with no matching SKILL.md fails the build here.
  it('the Try line curated set names only registered skills', () => {
    const registry = readRegisteredSkills();
    expect(() => selectRegisteredSkills(TRY_SKILLS, registry)).not.toThrow();
    for (const skill of TRY_SKILLS) {
      expect(registry).toContain(skill);
    }
  });

  it('fails when a curated skill is removed from the registry', () => {
    const withoutDashboard = readRegisteredSkills().filter((s) => s !== 'aka-dashboard');
    expect(() => selectRegisteredSkills(TRY_SKILLS, withoutDashboard)).toThrow();
  });

  it('the Ready line curated set names only registered skills', () => {
    const registry = readRegisteredSkills();
    expect(() => selectRegisteredSkills(READY_SKILLS, registry)).not.toThrow();
    for (const skill of READY_SKILLS) {
      expect(registry).toContain(skill);
    }
  });

  it('fails when a curated Ready skill is removed from the registry', () => {
    const withoutHealth = readRegisteredSkills().filter((s) => s !== 'aka-health');
    expect(() => selectRegisteredSkills(READY_SKILLS, withoutHealth)).toThrow();
  });

  it('curates a Ready subset deliberately distinct from the Try line', () => {
    // The two surfaces suggest different subsets — neither is the whole registry
    // and the Ready line names none of the Try line's skills.
    expect([...READY_SKILLS]).not.toEqual([...TRY_SKILLS]);
    const tryable = new Set<string>(TRY_SKILLS);
    for (const skill of READY_SKILLS) {
      expect(tryable.has(skill)).toBe(false);
    }
  });

  it('neither surface enumerates the full registry — each names a strict curated subset', () => {
    // The contract is per-surface curation, not a full-registry dump: with a
    // registry of ~10 skills, each surface names only its own few. A surface
    // that grew to name every registered skill would fail here.
    const registry = readRegisteredSkills();
    expect(registry.length).toBeGreaterThan(TRY_SKILLS.length);
    expect(registry.length).toBeGreaterThan(READY_SKILLS.length);
    // Combined, the two surfaces still do not cover the whole registry — proof
    // no line is silently enumerating everything the plugin registers.
    const named = new Set([...TRY_SKILLS, ...READY_SKILLS]);
    expect(named.size).toBeLessThan(registry.length);
  });
});

describe('chaining-line secret-scan continuation selection', () => {
  // The chaining line names a single specific secret-scan continuation
  // skill, resolved against the installed registry through the same per-surface
  // selection mechanism — never a hardcoded bare string, never the full registry.
  // The continuation is registered under `aka-scan` today and moves to
  // `aka-secretscan` once the dedicated secret-scan skill exists; the selection
  // resolves to whichever name is actually registered, in either ship order.
  it('returns exactly one skill, a member of the registered set', () => {
    const selected = selectSecretScanContinuation();
    expect(typeof selected).toBe('string');
    expect(readRegisteredSkills()).toContain(selected);
  });

  it('resolves to the single registered secret-scan skill today (aka-scan)', () => {
    const registry = readRegisteredSkills();
    expect(registry).toContain('aka-scan');
    expect(registry).not.toContain('aka-secretscan');
    expect(selectSecretScanContinuation()).toBe('aka-scan');
  });

  it('is a strict single-element curated subset, never the full registry', () => {
    const registry = readRegisteredSkills();
    expect(registry.length).toBeGreaterThan(1);
    const selected = selectSecretScanContinuation(registry);
    // One specific skill drawn from — but not equal to — the whole registry.
    expect(Array.isArray(selected)).toBe(false);
    expect(registry).toContain(selected);
    expect(registry.filter((s) => s === selected)).toHaveLength(1);
  });

  it('resolves to aka-secretscan once the rename registers it (either ship order)', () => {
    // Post-rename registry: the working-tree scan is `aka-codescan` and the new
    // `aka-secretscan` carries the secret-scan continuation.
    const renamed = ['aka-codescan', 'aka-secretscan', 'aka-dashboard'];
    expect(selectSecretScanContinuation(renamed)).toBe('aka-secretscan');
  });

  it('prefers aka-secretscan when both names are briefly registered', () => {
    const both = ['aka-scan', 'aka-secretscan', 'aka-dashboard'];
    expect(selectSecretScanContinuation(both)).toBe('aka-secretscan');
  });

  it('fails the build (throws) when no secret-scan continuation is registered', () => {
    // A stubbed registry with the curated skill removed — the selection must
    // fail loud rather than render a call-to-action the user cannot invoke.
    const withoutSecretScan = readRegisteredSkills().filter(
      (s) => s !== 'aka-scan' && s !== 'aka-secretscan',
    );
    expect(() => selectSecretScanContinuation(withoutSecretScan)).toThrow();
  });
});
