import { describe, expect, it } from 'vitest';

import { configAssetRow, type ConfigInventoryRow } from '../src/config-assets.ts';

function row(
  objectType: ConfigInventoryRow['objectType'],
  over: Partial<ConfigInventoryRow> = {},
): ConfigInventoryRow {
  return { id: `${objectType}-1`, objectType, title: null, location: null, ...over };
}

describe('configAssetRow', () => {
  it('projects a skill with its source, scope and version', () => {
    const asset = configAssetRow(row('skill', { title: 'pdf' }), {
      source: 'anthropics/skills',
      scope: 'plugin:docs',
      version: '1.2.0',
      description: 'Fill PDF forms',
      updated_at: '2026-10-01T00:00:00.000Z',
    });

    expect(asset).toMatchObject({
      id: 'skill-1',
      assetType: 'skill',
      name: 'pdf',
      sub: 'Skill · anthropics/skills',
      description: 'Fill PDF forms',
      flagsJson: '[]',
      trust: null,
      toolsJson: null,
      effectiveTrust: null,
    });
    expect(JSON.parse(asset.metaJson)).toEqual({
      source: 'anthropics/skills',
      scope: 'plugin:docs',
      installedVersion: '1.2.0',
      updatedAt: '2026-10-01T00:00:00.000Z',
    });
  });

  it('reads a bag whose fields have the wrong type as unknown', () => {
    const asset = configAssetRow(row('skill', { title: 's' }), { source: 42, version: ['x'] });

    expect(asset.sub).toBe('Skill · unknown');
    expect(JSON.parse(asset.metaJson)).toEqual({ source: 'unknown', scope: 'unknown' });
  });

  describe('hooks', () => {
    const bag = { event: 'PreToolUse', matcher: 'Bash', command: './guard.sh', scope: 'user' };
    const finding = (ruleId: string, name: string) => ({ maskedMatch: './guard.sh', ruleId, name });

    it('is active with no findings and labels the event and matcher', () => {
      const asset = configAssetRow(row('hook'), bag);

      expect(asset).toMatchObject({
        assetType: 'hook',
        name: './guard.sh',
        sub: 'Hook · PreToolUse · Bash',
        description: null,
        flagsJson: '[]',
      });
      expect(JSON.parse(asset.metaJson)).toMatchObject({ status: 'active' });
    });

    it('lets the highest-severity finding on the command win the single flag', () => {
      const flagsFor = (...findings: ReturnType<typeof finding>[]) =>
        JSON.parse(configAssetRow(row('hook'), bag, { findings }).flagsJson) as string[];

      expect(flagsFor(finding('hook-unknown', 'Unknown hook'))).toEqual(['unknown']);
      expect(
        flagsFor(finding('hook-unknown', 'Unknown hook'), finding('hook-conflict', 'Overlap')),
      ).toEqual(['conflict']);
      expect(
        flagsFor(
          finding('hook-conflict', 'Overlap'),
          finding('hook-external-egress', 'Sends data externally'),
        ),
      ).toEqual(['risk']);
    });

    it('joins the matched rule names into the description and ignores other commands', () => {
      const asset = configAssetRow(row('hook'), bag, {
        findings: [
          { maskedMatch: './guard.sh', ruleId: 'hook-unknown', name: 'Unknown hook' },
          { maskedMatch: './other.sh', ruleId: 'hook-external-egress', name: 'Egress' },
        ],
      });

      expect(asset.description).toBe('Unknown hook');
      expect(JSON.parse(asset.metaJson)).toMatchObject({ status: 'unknown' });
    });

    it('truncates a long command to 64 characters', () => {
      const asset = configAssetRow(row('hook'), { ...bag, command: `  ${'x'.repeat(100)}  ` });

      expect(asset.name).toHaveLength(64);
      expect(asset.name.endsWith('…')).toBe(true);
    });
  });

  describe('MCP servers', () => {
    it('defaults to unapproved and labels a remote server by its host', () => {
      const asset = configAssetRow(row('mcp_server', { title: 'github' }), {
        scope: 'user',
        transport: 'http',
        url: 'https://api.example.test/mcp?x=1',
        env_keys: ['GITHUB_TOKEN'],
      });

      expect(asset).toMatchObject({
        assetType: 'mcp',
        sub: 'MCP server · http · api.example.test',
        trust: 'unapproved',
        effectiveTrust: 'unapproved',
      });
      expect(JSON.parse(asset.metaJson)).toMatchObject({ envKeys: ['GITHUB_TOKEN'] });
    });

    it('applies a trust override to the effective trust and keeps the base trust', () => {
      const asset = configAssetRow(
        row('mcp_server', { id: 'mcp-9', title: 's' }),
        { transport: 'stdio', command: 'npx -y server' },
        { trustOverrides: new Map([['mcp-9', 'known-good' as const]]) },
      );

      expect(asset).toMatchObject({
        sub: 'MCP server · stdio · npx -y server',
        trust: 'unapproved',
        effectiveTrust: 'known-good',
      });
    });

    it('labels an unparseable url as given', () => {
      const asset = configAssetRow(row('mcp_server', { title: 'b' }), {
        transport: 'sse',
        url: 'not a url',
      });

      expect(asset.sub).toBe('MCP server · sse · not a url');
    });
  });

  it('projects a config file and flags only the local override as untracked', () => {
    const user = configAssetRow(
      row('config_file', { title: 'settings.json', location: '/home/u/.claude/settings.json' }),
      { kind: 'User settings', scope: 'user', detail: '4 keys', entry_count: 4 },
    );
    const local = configAssetRow(row('config_file', { title: 'settings.local.json' }), {
      scope: 'local',
    });

    expect(user).toMatchObject({
      assetType: 'config',
      sub: 'User settings',
      description: '4 keys',
      flagsJson: '[]',
    });
    expect(JSON.parse(user.metaJson)).toMatchObject({
      path: '/home/u/.claude/settings.json',
      entryCount: 4,
    });
    expect(JSON.parse(local.flagsJson)).toEqual(['untracked']);
  });
});
