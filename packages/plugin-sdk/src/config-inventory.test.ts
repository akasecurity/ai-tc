import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
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
    expect(scan.mcpServers).toEqual([]);
    expect(scan.errors).toEqual([]);
  });
});

describe('resolveConfigInventory — MCP servers', () => {
  it('collects project .mcp.json servers: stdio command+args, remote url, env NAMES only', () => {
    writeJson(join(project, '.mcp.json'), {
      mcpServers: {
        github: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          // Deliberately bland fixture (a secret-shaped one trips the repo's own
          // detection stack at edit time) — the assertion below is that the
          // VALUE never reaches the scan, whatever it looks like.
          env: { MCP_WORKSPACE: 'env-value-the-scan-must-drop' },
        },
        sentry: { type: 'http', url: 'https://mcp.sentry.io/mcp' },
      },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.errors).toEqual([]);
    expect(scan.mcpServers).toHaveLength(2);

    const github = scan.mcpServers.find((s) => s.name === 'github');
    expect(github).toMatchObject({
      scope: 'project',
      transport: 'stdio',
      command: 'npx -y @modelcontextprotocol/server-github',
      envKeys: ['MCP_WORKSPACE'],
      location: join(project, '.mcp.json'),
    });
    expect(github?.url).toBeUndefined();
    // The env VALUE must never appear anywhere in the scan.
    expect(JSON.stringify(scan)).not.toContain('env-value-the-scan-must-drop');

    const sentry = scan.mcpServers.find((s) => s.name === 'sentry');
    expect(sentry).toMatchObject({
      scope: 'project',
      transport: 'http',
      url: 'https://mcp.sentry.io/mcp',
    });
    expect(sentry?.command).toBeUndefined();
    expect(sentry?.envKeys).toBeUndefined();
  });

  it('collects ~/.claude.json user servers and this project’s local servers only', () => {
    writeJson(join(home, '.claude.json'), {
      mcpServers: {
        filesystem: { command: 'mcp-filesystem' },
      },
      projects: {
        [project]: { mcpServers: { puppeteer: { command: 'mcp-puppeteer' } } },
        '/some/other/repo': { mcpServers: { stripe: { command: 'mcp-stripe' } } },
      },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.mcpServers.map((s) => s.name).sort()).toEqual(['filesystem', 'puppeteer']);
    expect(scan.mcpServers.find((s) => s.name === 'filesystem')?.scope).toBe('user');
    expect(scan.mcpServers.find((s) => s.name === 'puppeteer')?.scope).toBe('local');
    // Another repo's local servers are not this session's surface.
    expect(scan.mcpServers.some((s) => s.name === 'stripe')).toBe(false);
  });

  it('collects a mcpServers key from settings files (managed deployments)', () => {
    writeJson(join(home, '.claude', 'settings.json'), {
      mcpServers: { audit: { type: 'sse', url: 'https://mcp.example.com/audit' } },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.mcpServers).toHaveLength(1);
    expect(scan.mcpServers[0]).toMatchObject({ name: 'audit', scope: 'user', transport: 'sse' });
  });

  it('attributes plugin .mcp.json servers via installed_plugins.json', () => {
    const installPath = join(home, '.claude', 'plugins', 'cache', 'acme', 'guard', '1.2.3');
    writeJson(join(home, '.claude', 'plugins', 'installed_plugins.json'), {
      version: 2,
      plugins: { 'guard@acme-marketplace': [{ installPath, version: '1.2.3' }] },
    });
    writeJson(join(installPath, '.mcp.json'), {
      mcpServers: { scanner: { command: 'node scan-server.js' } },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.mcpServers).toHaveLength(1);
    expect(scan.mcpServers[0]).toMatchObject({
      name: 'scanner',
      scope: 'plugin',
      pluginName: 'guard',
      transport: 'stdio',
    });
  });

  it('dedupes the same (name + scope) across files, canonical source winning the bag', () => {
    // The same user-scope server registered in ~/.claude.json AND user settings:
    // one row, and the ~/.claude.json (canonical, scanned first) command wins.
    writeJson(join(home, '.claude.json'), {
      mcpServers: { github: { command: 'canonical-github-server' } },
    });
    writeJson(join(home, '.claude', 'settings.json'), {
      mcpServers: { github: { command: 'settings-copy' } },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.mcpServers).toHaveLength(1);
    expect(scan.mcpServers[0]?.command).toBe('canonical-github-server');
  });

  it('keeps the same server name at two scopes as two rows', () => {
    writeJson(join(project, '.mcp.json'), {
      mcpServers: { github: { command: 'project-github' } },
    });
    writeJson(join(home, '.claude.json'), {
      mcpServers: { github: { command: 'user-github' } },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.mcpServers.map((s) => s.scope).sort()).toEqual(['project', 'user']);
  });

  it('a malformed .claude.json becomes an error entry; entries without command/url are skipped', () => {
    write(join(home, '.claude.json'), '{ not json');
    writeJson(join(project, '.mcp.json'), {
      mcpServers: {
        github: { command: 'mcp-github' },
        'not-a-server': { disabled: true },
      },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.mcpServers.map((s) => s.name)).toEqual(['github']);
    expect(scan.errors).toHaveLength(1);
    expect(scan.errors[0]?.source).toBe(join(home, '.claude.json'));
  });

  it('folds the repo/project identity into project-scope entries (trust never crosses repos)', () => {
    writeJson(join(project, '.mcp.json'), { mcpServers: { github: { command: 'mcp-github' } } });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    // Fixture project has no git remote → the cwd IS the repo identity.
    expect(scan.mcpServers[0]?.project).toBe(project);
  });

  it('masks secret-shaped tokens out of captured commands and urls (no-secrets rule)', () => {
    // Assembled at runtime so no contiguous token ever sits in this file.
    const token = ['ghp', 'ZaK9mQ2xL7vB4nR8tY3wPd5sF1hJ6cE0uG'].join('_');
    // The real-world shape from the wild: mcp-remote with an auth header arg.
    writeJson(join(project, '.mcp.json'), {
      mcpServers: {
        linear: {
          command: 'npx',
          args: [
            '-y',
            'mcp-remote',
            'https://mcp.linear.app/sse',
            '--header',
            `Authorization: Bearer ${token}`,
          ],
        },
        jira: {
          type: 'http',
          url: `https://bot:${token}@example.atlassian.net/mcp?apiKey=${token}`,
        },
      },
    });
    writeJson(join(home, '.claude', 'settings.json'), {
      hooks: {
        PostToolUse: [
          {
            hooks: [
              {
                type: 'command',
                command: `curl -H "Authorization: Bearer ${token}" https://x.example`,
              },
            ],
          },
        ],
      },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    // The token must appear NOWHERE in the scan — not in commands, urls, or errors.
    expect(JSON.stringify(scan)).not.toContain(token);
    // The surrounding shape survives for review.
    expect(scan.mcpServers.find((m) => m.name === 'linear')?.command).toContain('mcp-remote');
    const jira = scan.mcpServers.find((m) => m.name === 'jira');
    expect(jira?.url).toContain('example.atlassian.net');
    // Structural URL hygiene: userinfo stripped, query VALUES masked, names kept.
    expect(jira?.url).not.toContain('bot:');
    expect(jira?.url).toContain('apiKey=');
    expect(scan.hooks[0]?.command).toContain('curl -H');
  });

  it('sanitizes JSON parse errors so file content never rides the error reason', () => {
    const secretish = ['sk', 'live', 'Qq8Zz7Xx6Cc5Vv4Bb3Nn2Mm1'].join('-');
    // Malformed on purpose: an unquoted value → SyntaxError quoting the source.
    write(join(home, '.claude.json'), `{ "mcpServers": { "a": { "command": ${secretish} } } }`);

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.errors).toHaveLength(1);
    expect(scan.errors[0]?.reason).toMatch(/invalid JSON/);
    expect(JSON.stringify(scan.errors)).not.toContain(secretish);
  });

  it('collects manifest-declared plugin MCP servers (plugin.json mcpServers), inline and path form', () => {
    const inlinePath = join(home, '.claude', 'plugins', 'cache', 'acme', 'inline-plugin', '1.0.0');
    const filePath = join(home, '.claude', 'plugins', 'cache', 'acme', 'file-plugin', '1.0.0');
    writeJson(join(home, '.claude', 'plugins', 'installed_plugins.json'), {
      version: 2,
      plugins: {
        'inline-plugin@acme': [{ installPath: inlinePath, version: '1.0.0' }],
        'file-plugin@acme': [{ installPath: filePath, version: '1.0.0' }],
      },
    });
    writeJson(join(inlinePath, '.claude-plugin', 'plugin.json'), {
      name: 'inline-plugin',
      mcpServers: { scanner: { command: 'node scanner.js' } },
    });
    writeJson(join(filePath, '.claude-plugin', 'plugin.json'), {
      name: 'file-plugin',
      mcpServers: './mcp/servers.json',
    });
    writeJson(join(filePath, 'mcp', 'servers.json'), {
      mcpServers: { relay: { command: 'node relay.js' } },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.mcpServers.map((m) => m.name).sort()).toEqual(['relay', 'scanner']);
    expect(scan.mcpServers.find((m) => m.name === 'scanner')).toMatchObject({
      scope: 'plugin',
      pluginName: 'inline-plugin',
      marketplace: 'acme',
    });
  });

  it('keeps same-named servers from same-named plugins in DIFFERENT marketplaces distinct', () => {
    const a = join(home, '.claude', 'plugins', 'cache', 'acme', 'guard', '1.0.0');
    const b = join(home, '.claude', 'plugins', 'cache', 'evil', 'guard', '1.0.0');
    writeJson(join(home, '.claude', 'plugins', 'installed_plugins.json'), {
      version: 2,
      plugins: {
        'guard@acme': [{ installPath: a, version: '1.0.0' }],
        'guard@evil': [{ installPath: b, version: '1.0.0' }],
      },
    });
    writeJson(join(a, '.mcp.json'), { mcpServers: { scanner: { command: 'trusted-server' } } });
    writeJson(join(b, '.mcp.json'), { mcpServers: { scanner: { command: 'lookalike-server' } } });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    const scanners = scan.mcpServers.filter((m) => m.name === 'scanner');
    // Without marketplace in identity these would collapse to one row and the
    // second would silently inherit the first's trust.
    expect(scanners).toHaveLength(2);
    expect(scanners.map((m) => m.marketplace).sort()).toEqual(['acme', 'evil']);
  });

  it('matches projects[cwd] leniently: resolved symlinks and trailing slashes', () => {
    // macOS tmpdirs are symlinked (/var → /private/var), so realpath differs
    // from the raw fixture path — exactly the mismatch this guards against.
    writeJson(join(home, '.claude.json'), {
      projects: {
        [realpathSync(project)]: { mcpServers: { local1: { command: 'mcp-local' } } },
      },
    });

    const viaRealpath = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(viaRealpath.mcpServers.map((m) => m.name)).toEqual(['local1']);
    expect(viaRealpath.mcpServers[0]?.scope).toBe('local');

    // A trailing slash on the session cwd must not lose the entry either.
    writeJson(join(home, '.claude.json'), {
      projects: { [project]: { mcpServers: { local2: { command: 'mcp-local' } } } },
    });
    const viaSlash = resolveConfigInventory({ cwd: `${project}/`, homeDir: home });
    expect(viaSlash.mcpServers.map((m) => m.name)).toEqual(['local2']);
  });

  it('a malformed project .mcp.json becomes an error entry (its only parse)', () => {
    write(join(project, '.mcp.json'), '{ not json');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.mcpServers).toEqual([]);
    expect(scan.errors).toHaveLength(1);
    expect(scan.errors[0]?.source).toBe(join(project, '.mcp.json'));
  });

  it('a malformed settings file is recorded once, not once per collector pass', () => {
    write(join(home, '.claude', 'settings.json'), '{ not json');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    // collectSettingsHooks records it; the MCP pass over the same file stays silent.
    expect(scan.errors).toHaveLength(1);
  });
});

describe('resolveConfigInventory — config files', () => {
  it('records settings files with a top-level-key shape summary, never values', () => {
    writeJson(join(home, '.claude', 'settings.json'), {
      permissions: { allow: ['Bash(ls:*)'] },
      model: 'opus',
      env: { SOME_FLAG: 'value-that-must-not-leak' },
    });
    writeJson(join(project, '.claude', 'settings.local.json'), { hooks: {} });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.configFiles).toHaveLength(2);

    const user = scan.configFiles.find((f) => f.scope === 'user');
    expect(user).toMatchObject({
      name: 'settings.json',
      path: join(home, '.claude', 'settings.json'),
      kind: 'User settings',
      detail: 'Permissions, model, env',
    });
    expect(user?.updatedAt).toBeTruthy();
    // Shape only: no key values anywhere in the scan.
    expect(JSON.stringify(scan.configFiles)).not.toContain('value-that-must-not-leak');

    const local = scan.configFiles.find((f) => f.scope === 'local');
    expect(local).toMatchObject({ kind: 'Local overrides', detail: 'hooks' });
  });

  it('records memory files with a line count only — content never leaves the file', () => {
    write(join(home, '.claude', 'CLAUDE.md'), 'line one\nsecret project detail\nline three');
    write(join(project, 'CLAUDE.md'), '# Conventions\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });

    const userMemory = scan.configFiles.find((f) => f.kind === 'User memory');
    expect(userMemory).toMatchObject({ name: 'CLAUDE.md', scope: 'user', detail: '3 lines' });
    expect(JSON.stringify(scan.configFiles)).not.toContain('secret project detail');

    const projectMemory = scan.configFiles.find((f) => f.kind === 'Project memory');
    expect(projectMemory?.scope).toBe('project');
  });

  it('records .mcp.json and the commands/agents dirs with entry counts', () => {
    writeJson(join(project, '.mcp.json'), {
      mcpServers: { github: { command: 'mcp-github' }, sentry: { command: 'mcp-sentry' } },
    });
    write(join(project, '.claude', 'commands', 'deploy.md'), '# deploy');
    write(join(project, '.claude', 'commands', 'review.md'), '# review');
    write(join(project, '.claude', 'commands', 'ship.md'), '# ship');
    write(join(project, '.claude', 'agents', 'tester.md'), '# tester');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });

    const mcp = scan.configFiles.find((f) => f.kind === 'MCP servers');
    expect(mcp).toMatchObject({ name: '.mcp.json', entryCount: 2, detail: '2 servers' });

    const commands = scan.configFiles.find((f) => f.kind === 'Slash commands');
    expect(commands).toMatchObject({ name: 'commands', entryCount: 3, detail: '3 commands' });

    const agents = scan.configFiles.find((f) => f.kind === 'Subagents');
    expect(agents).toMatchObject({ name: 'agents', entryCount: 1, detail: '1 subagent' });
  });

  it('dir counts are recursive .md only — dotfiles, stray files and nesting handled', () => {
    write(join(project, '.claude', 'commands', 'deploy.md'), '# deploy');
    write(join(project, '.claude', 'commands', '.DS_Store'), 'junk');
    write(join(project, '.claude', 'commands', 'notes.txt'), 'not a command');
    write(join(project, '.claude', 'commands', 'frontend', 'lint.md'), '# lint');
    write(join(project, '.claude', 'commands', 'frontend', 'test.md'), '# test');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    const commands = scan.configFiles.find((f) => f.kind === 'Slash commands');
    expect(commands).toMatchObject({ entryCount: 3, detail: '3 commands' });
  });

  it('.mcp.json entryCount counts only entries the MCP scanner accepts', () => {
    writeJson(join(project, '.mcp.json'), {
      mcpServers: {
        github: { command: 'mcp-github' },
        'disabled-stub': { disabled: true },
      },
    });

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    const mcp = scan.configFiles.find((f) => f.kind === 'MCP servers');
    // One VALID server — agreeing with the MCP asset list over the same file.
    expect(mcp).toMatchObject({ entryCount: 1, detail: '1 server' });
    expect(scan.mcpServers).toHaveLength(1);
  });

  it('memory line counts ignore the trailing newline; an empty file is 0 lines', () => {
    write(join(project, 'CLAUDE.md'), 'one\ntwo\n');
    write(join(home, '.claude', 'CLAUDE.md'), '');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.configFiles.find((f) => f.kind === 'Project memory')?.detail).toBe('2 lines');
    expect(scan.configFiles.find((f) => f.kind === 'User memory')?.detail).toBe('0 lines');
  });

  it('absent files produce no rows; a malformed settings file still rows on existence', () => {
    write(join(home, '.claude', 'settings.json'), '{ not json');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    // Existence is filesystem truth — the row is there, without a shape summary.
    expect(scan.configFiles).toHaveLength(1);
    expect(scan.configFiles[0]).toMatchObject({ name: 'settings.json', kind: 'User settings' });
    expect(scan.configFiles[0]?.detail).toBeUndefined();
    // And no phantom rows for anything that doesn't exist.
    expect(scan.configFiles.some((f) => f.kind === 'Project memory')).toBe(false);
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

  it('excludes the built-in catalog by its canonical repo even when locally renamed', () => {
    const mp = join(home, '.claude', 'plugins', 'marketplaces', 'renamed');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      renamed: { installLocation: mp, source: { repo: 'anthropics/claude-plugins-official' } },
    });
    write(join(mp, 'skills', 'pdf', 'SKILL.md'), '# pdf\n');

    expect(resolveConfigInventory({ cwd: project, homeDir: home }).skills).toEqual([]);
  });

  it('surfaces a user-added Anthropic-published marketplace that is NOT the built-in catalog', () => {
    // `anthropics/skills` (the public skills collection) is config the user opted
    // into — it must appear, unlike the tool's bundled `claude-plugins-official`.
    const mp = join(home, '.claude', 'plugins', 'marketplaces', 'anthropic-skills');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      'anthropic-skills': { installLocation: mp, source: { repo: 'anthropics/skills' } },
    });
    write(join(mp, 'skills', 'pdf', 'SKILL.md'), '# pdf\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    expect(scan.skills.map((s) => s.name)).toEqual(['pdf']);
    expect(scan.skills[0]?.source).toBe('anthropic-skills');
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

  it('keeps same-named skills from two different plugins in one marketplace', () => {
    const mp = join(home, '.claude', 'plugins', 'marketplaces', 'acme');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      acme: { installLocation: mp, source: { repo: 'acme-co/plugins' } },
    });
    write(join(mp, 'plugins', 'guard', 'skills', 'audit', 'SKILL.md'), '# audit\n');
    write(join(mp, 'plugins', 'sentinel', 'skills', 'audit', 'SKILL.md'), '# audit\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    const audits = scan.skills.filter((s) => s.name === 'audit');
    // Both share source 'acme'; pluginName is folded into identity, so neither is
    // dropped — the inventory doesn't under-report two distinct plugins.
    expect(audits).toHaveLength(2);
    expect(audits.map((s) => s.pluginName).sort()).toEqual(['guard', 'sentinel']);
  });

  it('keeps a marketplace-root skill and a plugin skill of the same name distinct', () => {
    const mp = join(home, '.claude', 'plugins', 'marketplaces', 'acme');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      acme: { installLocation: mp, source: { repo: 'acme-co/plugins' } },
    });
    write(join(mp, 'skills', 'audit', 'SKILL.md'), '# audit\n');
    write(join(mp, 'plugins', 'guard', 'skills', 'audit', 'SKILL.md'), '# audit\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    const audits = scan.skills.filter((s) => s.name === 'audit');
    // Same source 'acme', but the plugin folds pluginName in → two distinct rows.
    expect(audits).toHaveLength(2);
    expect(audits.map((s) => s.pluginName ?? '(root)').sort()).toEqual(['(root)', 'guard']);
  });

  it('collapses a plugin skill reached via both installed_plugins and its marketplace clone', () => {
    const mp = join(home, '.claude', 'plugins', 'marketplaces', 'acme');
    const pluginDir = join(mp, 'plugins', 'guard');
    writeJson(join(home, '.claude', 'plugins', 'known_marketplaces.json'), {
      acme: { installLocation: mp, source: { repo: 'acme-co/plugins' } },
    });
    // installed_plugins points at the same on-disk dir the marketplace scan walks.
    writeJson(join(home, '.claude', 'plugins', 'installed_plugins.json'), {
      version: 2,
      plugins: { 'guard@acme': [{ installPath: pluginDir, version: '3.0.0' }] },
    });
    write(join(pluginDir, 'skills', 'audit', 'SKILL.md'), '# audit\n');

    const scan = resolveConfigInventory({ cwd: project, homeDir: home });
    // Both scans resolve to (source 'acme', name 'audit', plugin 'guard') → one row.
    expect(scan.skills.filter((s) => s.name === 'audit')).toHaveLength(1);
  });
});
