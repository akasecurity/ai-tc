import { describe, expect, it } from 'vitest';

import type {
  ConfigFileScanEntry,
  ConfigScanResult,
  HookScanEntry,
  McpServerScanEntry,
  SkillScanEntry,
} from '../../src/zod/config-inventory.ts';
import {
  configFileIdentityKey,
  configInventoryInputs,
  ConfigScanRecord,
  configScopeKey,
  hookIdentityKey,
  mcpServerIdentityKey,
  skillIdentityKey,
} from '../../src/zod/config-inventory.ts';
import {
  AuditEventType,
  INVENTORY_ATTRIBUTE_VOCAB,
  InventoryObjectType,
} from '../../src/zod/meta.ts';

const skill: SkillScanEntry = {
  name: 'pdf',
  source: 'anthropics/skills',
  scope: 'plugin',
  pluginName: 'anthropic-skills',
  version: '2.1.0',
  description: 'Fill, extract & merge PDF forms',
  updatedAt: '2026-07-01T10:00:00.000Z',
  location: '/home/u/.claude/plugins/cache/anthropics/skills/pdf',
};

const hook: HookScanEntry = {
  event: 'PostToolUse',
  matcher: 'Edit|Write',
  command: 'prettier --write "$FILE"',
  timeout: 10,
  scope: 'project',
  location: '/repo/.claude/settings.json',
};

const mcpServer: McpServerScanEntry = {
  name: 'github',
  scope: 'project',
  project: 'https://github.com/acme/repo-a.git',
  transport: 'stdio',
  command: 'npx @modelcontextprotocol/server-github',
  envKeys: ['GITHUB_TOKEN'],
  location: '/repo/.mcp.json',
};

const configFile: ConfigFileScanEntry = {
  name: 'settings.json',
  path: '/home/u/.claude/settings.json',
  scope: 'user',
  kind: 'User settings',
  detail: 'Permissions, model, env',
  updatedAt: '2026-07-01T10:00:00.000Z',
};

describe('config-inventory enums ride the meta model', () => {
  it('inventory object types include skill, hook, mcp_server and config_file', () => {
    expect(InventoryObjectType.options).toContain('skill');
    expect(InventoryObjectType.options).toContain('hook');
    expect(InventoryObjectType.options).toContain('mcp_server');
    expect(InventoryObjectType.options).toContain('config_file');
  });

  it('audit event types include config_scan', () => {
    expect(AuditEventType.options).toContain('config_scan');
  });

  it('the attribute vocabulary covers the new object types', () => {
    expect(INVENTORY_ATTRIBUTE_VOCAB.skill.parse({ version: '1.0.0' })).toEqual({
      version: '1.0.0',
    });
    expect(INVENTORY_ATTRIBUTE_VOCAB.hook.parse({ event: 'PreToolUse' })).toEqual({
      event: 'PreToolUse',
    });
    expect(INVENTORY_ATTRIBUTE_VOCAB.mcp_server.parse({ transport: 'stdio' })).toEqual({
      transport: 'stdio',
    });
    expect(INVENTORY_ATTRIBUTE_VOCAB.config_file.parse({ kind: 'User settings' })).toEqual({
      kind: 'User settings',
    });
  });
});

describe('identity keys', () => {
  it('skill identity hashes source + name only — version is volatile', () => {
    const updated = { ...skill, version: '2.3.1' };
    expect(skillIdentityKey(updated)).toBe(skillIdentityKey(skill));
  });

  it('the same skill name from different sources is two identities', () => {
    expect(skillIdentityKey({ source: 'local', name: 'pdf' })).not.toBe(
      skillIdentityKey({ source: 'anthropics/skills', name: 'pdf' }),
    );
  });

  it('hook command IS identity — an edited command is a new hook', () => {
    const edited = { ...hook, command: 'prettier --write --cache "$FILE"' };
    expect(hookIdentityKey(edited)).not.toBe(hookIdentityKey(hook));
  });

  it('the same command at two scopes is two identities', () => {
    expect(hookIdentityKey({ ...hook, scope: 'user' })).not.toBe(hookIdentityKey(hook));
  });

  it('plugin scope folds the owning plugin into the key', () => {
    const a = { ...hook, scope: 'plugin' as const, pluginName: 'aka' };
    const b = { ...hook, scope: 'plugin' as const, pluginName: 'other' };
    expect(hookIdentityKey(a)).not.toBe(hookIdentityKey(b));
    expect(configScopeKey('plugin', 'aka')).toBe('plugin:aka');
    expect(configScopeKey('user')).toBe('user');
  });

  it('hook timeout is volatile — same identity either way', () => {
    expect(hookIdentityKey({ ...hook, timeout: 30 } as HookScanEntry)).toBe(hookIdentityKey(hook));
  });

  it('mcp identity is name + scope — a changed command/url is drift, not a new row', () => {
    const moved = { ...mcpServer, command: undefined, url: 'https://evil.example/mcp' };
    expect(mcpServerIdentityKey(moved)).toBe(mcpServerIdentityKey(mcpServer));
  });

  it('the same mcp server name at two scopes is two identities', () => {
    expect(mcpServerIdentityKey({ ...mcpServer, scope: 'user' })).not.toBe(
      mcpServerIdentityKey(mcpServer),
    );
  });

  it('plugin scope folds the owning plugin into the mcp key', () => {
    const a = { ...mcpServer, scope: 'plugin' as const, pluginName: 'aka' };
    const b = { ...mcpServer, scope: 'plugin' as const, pluginName: 'other' };
    expect(mcpServerIdentityKey(a)).not.toBe(mcpServerIdentityKey(b));
  });

  it('same-named project servers in DIFFERENT repos are two identities — trust never crosses repos', () => {
    const repoB = { ...mcpServer, project: 'https://github.com/evil/clone.git' };
    expect(mcpServerIdentityKey(repoB)).not.toBe(mcpServerIdentityKey(mcpServer));
    // Same repo, drifted command → still the same row.
    const drifted = { ...mcpServer, command: 'changed' };
    expect(mcpServerIdentityKey(drifted)).toBe(mcpServerIdentityKey(mcpServer));
  });

  it('same-named plugins from DIFFERENT marketplaces are two identities', () => {
    const a = { ...mcpServer, scope: 'plugin' as const, pluginName: 'guard', marketplace: 'acme' };
    const b = { ...mcpServer, scope: 'plugin' as const, pluginName: 'guard', marketplace: 'evil' };
    expect(mcpServerIdentityKey(a)).not.toBe(mcpServerIdentityKey(b));
  });

  it('config-file identity is path + scope — edited contents refresh the row', () => {
    const edited = { ...configFile, detail: 'Permissions, hooks', updatedAt: undefined };
    expect(configFileIdentityKey(edited)).toBe(configFileIdentityKey(configFile));
    expect(configFileIdentityKey({ ...configFile, path: '/repo/.claude/settings.json' })).not.toBe(
      configFileIdentityKey(configFile),
    );
  });
});

describe('configInventoryInputs', () => {
  const scan: ConfigScanResult = {
    scannedAt: '2026-07-02T12:00:00.000Z',
    skills: [skill],
    hooks: [hook],
    mcpServers: [mcpServer],
    configFiles: [configFile],
    errors: [],
  };

  it('maps entries to complete Type-1 bags (partial bags erase facets)', () => {
    const inputs = configInventoryInputs(scan);
    expect(inputs).toHaveLength(4);

    const skillInput = inputs.find((i) => i.objectType === 'skill');
    expect(skillInput).toMatchObject({
      identityKey: skillIdentityKey(skill),
      title: 'pdf',
      location: skill.location,
      attributes: {
        source: 'anthropics/skills',
        scope: 'plugin:anthropic-skills',
        version: '2.1.0',
        description: 'Fill, extract & merge PDF forms',
        updated_at: '2026-07-01T10:00:00.000Z',
        plugin_name: 'anthropic-skills',
      },
    });

    const hookInput = inputs.find((i) => i.objectType === 'hook');
    expect(hookInput).toMatchObject({
      identityKey: hookIdentityKey(hook),
      location: hook.location,
      attributes: {
        event: 'PostToolUse',
        matcher: 'Edit|Write',
        command: 'prettier --write "$FILE"',
        scope: 'project',
        timeout: 10,
      },
    });

    const mcpInput = inputs.find((i) => i.objectType === 'mcp_server');
    expect(mcpInput).toMatchObject({
      identityKey: mcpServerIdentityKey(mcpServer),
      title: 'github',
      location: '/repo/.mcp.json',
      attributes: {
        // The QUALIFIED scope — the identity qualifier is also what renders.
        scope: 'project:https://github.com/acme/repo-a.git',
        transport: 'stdio',
        command: 'npx @modelcontextprotocol/server-github',
        env_keys: ['GITHUB_TOKEN'],
        project: 'https://github.com/acme/repo-a.git',
      },
    });

    const fileInput = inputs.find((i) => i.objectType === 'config_file');
    expect(fileInput).toMatchObject({
      identityKey: configFileIdentityKey(configFile),
      title: 'settings.json',
      location: '/home/u/.claude/settings.json',
      attributes: {
        kind: 'User settings',
        scope: 'user',
        detail: 'Permissions, model, env',
        updated_at: '2026-07-01T10:00:00.000Z',
      },
    });
  });

  it('bags validate against the canonical vocabulary', () => {
    for (const input of configInventoryInputs(scan)) {
      const vocab =
        input.objectType === 'skill'
          ? INVENTORY_ATTRIBUTE_VOCAB.skill
          : input.objectType === 'hook'
            ? INVENTORY_ATTRIBUTE_VOCAB.hook
            : input.objectType === 'mcp_server'
              ? INVENTORY_ATTRIBUTE_VOCAB.mcp_server
              : INVENTORY_ATTRIBUTE_VOCAB.config_file;
      expect(() => vocab.parse(input.attributes)).not.toThrow();
    }
  });

  it('omits absent optionals rather than writing undefined into the bag', () => {
    const bare: ConfigScanResult = {
      scannedAt: '2026-07-02T12:00:00.000Z',
      skills: [{ name: 'notes', source: 'local', scope: 'user' }],
      hooks: [],
      mcpServers: [],
      configFiles: [],
      errors: [],
    };
    const [input] = configInventoryInputs(bare);
    expect(input?.attributes).toEqual({ source: 'local', scope: 'user' });
  });

  it('a remote server maps url (no command) and env-key NAMES only', () => {
    const remote: ConfigScanResult = {
      scannedAt: '2026-07-02T12:00:00.000Z',
      skills: [],
      hooks: [],
      mcpServers: [
        { name: 'sentry', scope: 'user', transport: 'http', url: 'https://mcp.sentry.io/mcp' },
      ],
      configFiles: [],
      errors: [],
    };
    const [input] = configInventoryInputs(remote);
    expect(input?.attributes).toEqual({
      scope: 'user',
      transport: 'http',
      url: 'https://mcp.sentry.io/mcp',
    });
  });
});

describe('ConfigScanRecord', () => {
  it('parses a minimal scan record (definitions/findings optional)', () => {
    const record = ConfigScanRecord.parse({
      items: configInventoryInputs({
        scannedAt: '2026-07-02T12:00:00.000Z',
        skills: [skill],
        hooks: [hook],
        mcpServers: [],
        configFiles: [],
        errors: [],
      }),
      scanEvent: {
        id: 'scan-1',
        eventType: 'config_scan',
        startedAt: '2026-07-02T12:00:00.000Z',
        parentId: 'session-1',
        rootSessionId: 'session-1',
        attributes: { skills: 1, hooks: 1 },
      },
    });
    expect(record.definitions).toBeUndefined();
    expect(record.scanEvent.eventType).toBe('config_scan');
  });
});
