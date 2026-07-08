import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { resolveConfigInventory } from './config-inventory.ts';

let home: string;
let project: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-config-home-'));
  project = mkdtempSync(join(tmpdir(), 'aka-config-project-'));
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  rmSync(project, { recursive: true, force: true });
});

function write(path: string, content: string): void {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content);
}

function writeJson(path: string, value: unknown): void {
  write(path, JSON.stringify(value, null, 2));
}

const HOOKS = {
  hooks: {
    PreToolUse: [
      {
        matcher: 'Bash',
        hooks: [{ type: 'command', command: 'guard-dangerous-cmds.sh', timeout: 10 }],
      },
    ],
    PostToolUse: [
      // No matcher — applies to all tools.
      { hooks: [{ type: 'command', command: 'prettier --write "$FILE"' }] },
    ],
  },
};

describe('resolveConfigInventory — hooks', () => {
  it('collects hooks from all three settings scopes with their locations', () => {
    writeJson(join(home, '.claude', 'settings.json'), HOOKS);
    writeJson(join(project, '.claude', 'settings.json'), {
      hooks: {
        UserPromptSubmit: [{ hooks: [{ type: 'command', command: 'scan-secrets.sh' }] }],
      },
    });
    writeJson(join(project, '.claude', 'settings.local.json'), {
      hooks: {
        Stop: [{ hooks: [{ type: 'command', command: 'notify.sh' }] }],
      },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.errors).toEqual([]);
    expect(scan.hooks).toHaveLength(4);

    const guard = scan.hooks.find((h) => h.command === 'guard-dangerous-cmds.sh');
    expect(guard).toMatchObject({
      event: 'PreToolUse',
      matcher: 'Bash',
      timeout: 10,
      scope: 'user',
      location: join(home, '.claude', 'settings.json'),
    });

    const prettier = scan.hooks.find((h) => h.command === 'prettier --write "$FILE"');
    expect(prettier?.matcher).toBeUndefined();

    expect(scan.hooks.find((h) => h.command === 'scan-secrets.sh')?.scope).toBe('project');
    expect(scan.hooks.find((h) => h.command === 'notify.sh')?.scope).toBe('local');
  });

  it('a malformed settings file becomes an error entry, other sources still parse', () => {
    write(join(home, '.claude', 'settings.json'), '{ not json');
    writeJson(join(project, '.claude', 'settings.json'), HOOKS);

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.hooks).toHaveLength(2);
    expect(scan.errors).toHaveLength(1);
    expect(scan.errors[0]?.source).toBe(join(home, '.claude', 'settings.json'));
  });

  it('absent settings files are a non-event, not an error', () => {
    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.hooks).toEqual([]);
    expect(scan.skills).toEqual([]);
    expect(scan.errors).toEqual([]);
  });
});

describe('resolveConfigInventory — skills', () => {
  it('collects personal skills with frontmatter, falling back to the dir name', () => {
    write(
      join(home, '.claude', 'skills', 'pdf-tools', 'SKILL.md'),
      '---\nname: pdf\ndescription: Fill & extract PDF forms\nversion: 2.1.0\n---\n\n# pdf\n',
    );
    write(join(home, '.claude', 'skills', 'notes', 'SKILL.md'), '# Skill: notes\nNo frontmatter.');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.skills).toHaveLength(2);

    const pdf = scan.skills.find((s) => s.name === 'pdf');
    expect(pdf).toMatchObject({
      source: 'local',
      scope: 'user',
      version: '2.1.0',
      description: 'Fill & extract PDF forms',
      location: join(home, '.claude', 'skills', 'pdf-tools'),
    });
    expect(pdf?.updatedAt).toBeTruthy();

    // Heading-only SKILL.md → dir name, no version/description.
    const notes = scan.skills.find((s) => s.name === 'notes');
    expect(notes?.version).toBeUndefined();
  });

  it('project skills carry the project-surrogate source (no marketplace collision)', () => {
    write(join(project, '.claude', 'skills', 'pdf', 'SKILL.md'), '# pdf\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    const pdf = scan.skills.find((s) => s.name === 'pdf');
    expect(pdf?.scope).toBe('project');
    expect(pdf?.source.startsWith('project:')).toBe(true);
  });
});

describe('resolveConfigInventory — installed plugins', () => {
  it('attributes plugin hooks and skills via installed_plugins.json', () => {
    const installPath = join(home, '.claude', 'plugins', 'cache', 'acme', 'guard', '1.2.3');
    writeJson(join(home, '.claude', 'plugins', 'installed_plugins.json'), {
      version: 2,
      plugins: {
        'guard@acme-marketplace': [{ scope: 'user', installPath, version: '1.2.3' }],
      },
    });
    writeJson(join(installPath, 'hooks', 'hooks.json'), {
      hooks: {
        PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'node guard.js' }] }],
      },
    });
    // Skill without frontmatter version → falls back to the plugin's version.
    write(join(installPath, 'skills', 'audit', 'SKILL.md'), '---\nname: audit\n---\n# audit\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });

    const hook = scan.hooks.find((h) => h.command === 'node guard.js');
    expect(hook).toMatchObject({ scope: 'plugin', pluginName: 'guard' });

    const skill = scan.skills.find((s) => s.name === 'audit');
    expect(skill).toMatchObject({
      source: 'acme-marketplace',
      scope: 'plugin',
      pluginName: 'guard',
      version: '1.2.3',
    });
  });

  it('never throws — even a directory where a file is expected fails open', () => {
    mkdirSync(join(home, '.claude', 'plugins', 'installed_plugins.json'), { recursive: true });
    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.hooks).toEqual([]);
    expect(scan.skills).toEqual([]);
  });
});

describe('resolveConfigInventory — marketplace + code skills', () => {
  it('scans all non-Claude marketplaces (root + plugins + external), excluding the official catalog', () => {
    const acme = join(home, '.claude', 'plugins', 'marketplaces', 'acme');
    const official = join(home, '.claude', 'plugins', 'marketplaces', 'claude-plugins-official');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      acme: { installLocation: acme, source: { repo: 'acme-co/plugins' } },
      'claude-plugins-official': {
        installLocation: official,
        source: { repo: 'anthropics/claude-plugins-official' },
      },
    });
    write(join(acme, 'skills', 'backend-conventions', 'SKILL.md'), '# backend-conventions\n');
    write(
      join(acme, 'plugins', 'guard', 'skills', 'audit', 'SKILL.md'),
      '---\nname: audit\nversion: 3.0.0\n---\n# audit\n',
    );
    write(join(acme, 'external_plugins', 'discord', 'skills', 'access', 'SKILL.md'), '# access\n');
    // Anthropic's official catalog — must NOT be inventoried.
    write(join(official, 'plugins', 'math-olympiad', 'skills', 'math', 'SKILL.md'), '# math\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.errors).toEqual([]);
    expect(scan.skills.map((s) => s.name).sort()).toEqual([
      'access',
      'audit',
      'backend-conventions',
    ]);
    expect(scan.skills.find((s) => s.name === 'audit')).toMatchObject({
      source: 'acme',
      scope: 'plugin',
      pluginName: 'guard',
      version: '3.0.0',
    });
    expect(scan.skills.some((s) => s.name === 'math')).toBe(false);
  });

  it('excludes a marketplace published by anthropics/ regardless of its name', () => {
    const mp = join(home, '.claude', 'plugins', 'marketplaces', 'renamed');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      renamed: { installLocation: mp, source: { repo: 'anthropics/claude-plugins-official' } },
    });
    write(join(mp, 'skills', 'pdf', 'SKILL.md'), '# pdf\n');

    expect(resolveConfigInventory({ cwd: project, homeDir: home }).skills).toEqual([]);
  });

  it('scans project code skills from the repo top-level skills/ dir', () => {
    write(join(project, 'skills', 'backend-conventions', 'SKILL.md'), '# backend-conventions\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    const skill = scan.skills.find((s) => s.name === 'backend-conventions');
    expect(skill?.scope).toBe('project');
    expect(skill?.source.startsWith('project:')).toBe(true);
  });

  it('keeps a marketplace skill and a same-named project-code skill as distinct rows', () => {
    const mp = join(home, '.claude', 'plugins', 'marketplaces', 'acme');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      acme: { installLocation: mp, source: { repo: 'acme-co/plugins' } },
    });
    write(join(mp, 'skills', 'backend-conventions', 'SKILL.md'), '# backend-conventions\n');
    write(join(project, 'skills', 'backend-conventions', 'SKILL.md'), '# backend-conventions\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    const matches = scan.skills.filter((s) => s.name === 'backend-conventions');
    // Distinct sources (marketplace vs project code) are two inventory identities,
    // so both surface — dedup only collapses the same source + name.
    expect(matches).toHaveLength(2);
    expect(matches.map((s) => s.source).sort()).toEqual(['acme', `project:${project}`]);
  });

  it('keeps a same-named skill from two different marketplaces as distinct rows', () => {
    const acme = join(home, '.claude', 'plugins', 'marketplaces', 'acme');
    const globex = join(home, '.claude', 'plugins', 'marketplaces', 'globex');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      acme: { installLocation: acme, source: { repo: 'acme-co/plugins' } },
      globex: { installLocation: globex, source: { repo: 'globex-co/plugins' } },
    });
    write(join(acme, 'skills', 'audit', 'SKILL.md'), '# audit\n');
    write(join(globex, 'skills', 'audit', 'SKILL.md'), '# audit\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    const sources = scan.skills
      .filter((s) => s.name === 'audit')
      .map((s) => s.source)
      .sort();
    expect(sources).toEqual(['acme', 'globex']);
  });

  it('keeps a personal skill and a same-named marketplace skill as distinct rows', () => {
    const mp = join(home, '.claude', 'plugins', 'marketplaces', 'acme');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      acme: { installLocation: mp, source: { repo: 'acme-co/plugins' } },
    });
    write(join(home, '.claude', 'skills', 'pdf', 'SKILL.md'), '# pdf\n');
    write(join(mp, 'skills', 'pdf', 'SKILL.md'), '# pdf\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    const sources = scan.skills
      .filter((s) => s.name === 'pdf')
      .map((s) => s.source)
      .sort();
    expect(sources).toEqual(['acme', 'local']);
  });

  it('collapses one skill reachable twice under the same source (same identity)', () => {
    const mp = join(home, '.claude', 'plugins', 'marketplaces', 'acme');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      acme: { installLocation: mp, source: { repo: 'acme-co/plugins' } },
    });
    // Same name under both the marketplace root and one of its plugins → the same
    // (source 'acme', name 'audit') identity → one row.
    write(join(mp, 'skills', 'audit', 'SKILL.md'), '# audit\n');
    write(join(mp, 'plugins', 'guard', 'skills', 'audit', 'SKILL.md'), '# audit\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.skills.filter((s) => s.name === 'audit')).toHaveLength(1);
  });
});
