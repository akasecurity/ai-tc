import { describe, expect, it } from 'vitest';

import {
  AccessLevel,
  AssetDetail,
  AssetGroup,
  AssetSummary,
  AssetType,
  ConnectProjectBody,
  FileDetail,
  FileSummary,
  Flag,
  FolderSummary,
  GetHarnessEventsQuery,
  GetProjectFileQuery,
  GetProjectTreeQuery,
  HarnessEventItem,
  HarnessEventKind,
  HarnessEventsResponse,
  HarnessId,
  HarnessSummary,
  InventoryStats,
  ListAssetsQuery,
  ListAssetsResponse,
  ListHarnessesResponse,
  ListProjectsResponse,
  McpTool,
  Origin,
  ProjectSummary,
  ProjectTreeResponse,
  RescanResponse,
  SetFileAccessBody,
  SetFileAccessResponse,
  SetMcpTrustBody,
  TrustLevel,
  Visibility,
} from '../../src/zod/inventory.ts';

// ─── Enums ────────────────────────────────────────────────────────────────────

describe('AssetType enum', () => {
  it('accepts all 5 valid values', () => {
    for (const v of ['project', 'skill', 'mcp', 'hook', 'config']) {
      expect(AssetType.safeParse(v).success).toBe(true);
    }
  });

  it('rejects unknown values', () => {
    expect(AssetType.safeParse('tool').success).toBe(false);
    expect(AssetType.safeParse('').success).toBe(false);
    expect(AssetType.safeParse(null).success).toBe(false);
  });
});

describe('AccessLevel enum', () => {
  it('accepts open, approved, blocked', () => {
    for (const v of ['open', 'approved', 'blocked']) {
      expect(AccessLevel.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(AccessLevel.safeParse('private').success).toBe(false);
    expect(AccessLevel.safeParse('allowed').success).toBe(false);
  });
});

describe('Origin enum', () => {
  it('accepts all 7 valid values', () => {
    for (const v of ['source', 'public-dep', 'vendored', 'config', 'data', 'docs', 'generated']) {
      expect(Origin.safeParse(v).success).toBe(true);
    }
  });

  it('rejects unknown values', () => {
    expect(Origin.safeParse('external').success).toBe(false);
  });
});

describe('TrustLevel enum', () => {
  it('accepts known-good, risky, unapproved', () => {
    for (const v of ['known-good', 'risky', 'unapproved']) {
      expect(TrustLevel.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(TrustLevel.safeParse('trusted').success).toBe(false);
    expect(TrustLevel.safeParse('unknown').success).toBe(false);
  });
});

describe('Flag enum', () => {
  it('accepts all 8 valid flag values', () => {
    for (const v of [
      'update',
      'stale',
      'conflict',
      'unknown',
      'change',
      'untracked',
      'risk',
      'findings',
    ]) {
      expect(Flag.safeParse(v).success).toBe(true);
    }
  });

  it('rejects unknown flag values', () => {
    expect(Flag.safeParse('warn').success).toBe(false);
    expect(Flag.safeParse('alert').success).toBe(false);
  });
});

describe('Visibility enum', () => {
  it('accepts public and private', () => {
    expect(Visibility.safeParse('public').success).toBe(true);
    expect(Visibility.safeParse('private').success).toBe(true);
  });

  it('rejects invalid values', () => {
    expect(Visibility.safeParse('internal').success).toBe(false);
  });
});

describe('HarnessEventKind enum', () => {
  it('accepts block, redact, warn', () => {
    for (const v of ['block', 'redact', 'warn']) {
      expect(HarnessEventKind.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(HarnessEventKind.safeParse('allow').success).toBe(false);
    expect(HarnessEventKind.safeParse('log').success).toBe(false);
  });
});

describe('HarnessId enum', () => {
  it('accepts claudecode, cursor, codex', () => {
    for (const v of ['claudecode', 'cursor', 'codex']) {
      expect(HarnessId.safeParse(v).success).toBe(true);
    }
  });

  it('rejects invalid values', () => {
    expect(HarnessId.safeParse('copilot').success).toBe(false);
    expect(HarnessId.safeParse('claude-code').success).toBe(false);
  });
});

// ─── AssetSummary ─────────────────────────────────────────────────────────────

describe('AssetSummary', () => {
  const validAsset = {
    id: 'mcp-notion',
    type: 'mcp',
    name: 'notion-bridge',
    sub: 'mcp://notion-bridge',
    flags: ['change'],
    trust: 'unapproved',
  };

  it('parses a valid mcp asset with trust', () => {
    const result = AssetSummary.safeParse(validAsset);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.trust).toBe('unapproved');
    }
  });

  it('parses a valid skill asset without trust (trust is optional)', () => {
    const skillAsset = {
      id: 'skill-bash',
      type: 'skill',
      name: 'bash',
      sub: 'shell',
      flags: [],
    };
    const result = AssetSummary.safeParse(skillAsset);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.trust).toBeUndefined();
    }
  });

  it('flags must be an array of Flag enum values', () => {
    expect(AssetSummary.safeParse({ ...validAsset, flags: ['risk', 'stale'] }).success).toBe(true);
    expect(AssetSummary.safeParse({ ...validAsset, flags: ['invalid-flag'] }).success).toBe(false);
  });

  it('rejects missing required fields', () => {
    expect(AssetSummary.safeParse({ id: 'x', type: 'mcp', name: 'x' }).success).toBe(false);
  });
});

// ─── ProjectSummary ───────────────────────────────────────────────────────────

const validProjectSummary = {
  id: 'payments-api',
  name: 'payments-api',
  repo: 'globex/payments-api',
  visibility: 'private',
  language: 'TypeScript',
  policyDefault: 'approved',
  updatedAt: '2026-06-30T16:41:00Z',
  accessCounts: { open: 4, approved: 13, blocked: 2, total: 19 },
  findingsCount: 2,
};

describe('ProjectSummary', () => {
  it('parses a valid project summary', () => {
    const result = ProjectSummary.safeParse(validProjectSummary);
    expect(result.success).toBe(true);
  });

  it('updatedAt must be an ISO datetime string', () => {
    expect(
      ProjectSummary.safeParse({ ...validProjectSummary, updatedAt: '2026-06-30T16:41:00Z' })
        .success,
    ).toBe(true);
    expect(
      ProjectSummary.safeParse({ ...validProjectSummary, updatedAt: 'not-a-date' }).success,
    ).toBe(false);
  });

  it('policyDefault must be an AccessLevel value', () => {
    expect(
      ProjectSummary.safeParse({ ...validProjectSummary, policyDefault: 'blocked' }).success,
    ).toBe(true);
    expect(
      ProjectSummary.safeParse({ ...validProjectSummary, policyDefault: 'invalid' }).success,
    ).toBe(false);
  });

  it('accessCounts must have open, approved, blocked, total as non-negative integers', () => {
    expect(
      ProjectSummary.safeParse({
        ...validProjectSummary,
        accessCounts: { open: 0, approved: 0, blocked: 0, total: 0 },
      }).success,
    ).toBe(true);
    expect(
      ProjectSummary.safeParse({
        ...validProjectSummary,
        accessCounts: { open: -1, approved: 0, blocked: 0, total: 0 },
      }).success,
    ).toBe(false);
  });

  it('findingsCount must be a non-negative integer', () => {
    expect(ProjectSummary.safeParse({ ...validProjectSummary, findingsCount: 0 }).success).toBe(
      true,
    );
    expect(ProjectSummary.safeParse({ ...validProjectSummary, findingsCount: -1 }).success).toBe(
      false,
    );
  });
});

// ─── HarnessSummary ───────────────────────────────────────────────────────────

describe('HarnessSummary', () => {
  const validHarness = {
    id: 'claudecode',
    label: 'Claude Code',
    kind: 'CLI agent',
    version: 'Claude Code 2.1.4',
    sessions: 5,
    assetCount: 25,
    flagCount: 3,
    projects: [validProjectSummary],
    categories: [
      {
        type: 'mcp',
        assets: [
          {
            id: 'mcp-notion',
            type: 'mcp',
            name: 'notion-bridge',
            sub: 'mcp://notion-bridge',
            flags: ['change'],
            trust: 'unapproved',
          },
        ],
      },
    ],
  };

  it('parses a valid harness summary with projects and categories', () => {
    const result = HarnessSummary.safeParse(validHarness);
    expect(result.success).toBe(true);
  });

  it('sessions, assetCount, flagCount must be non-negative integers', () => {
    expect(HarnessSummary.safeParse({ ...validHarness, sessions: 0 }).success).toBe(true);
    expect(HarnessSummary.safeParse({ ...validHarness, sessions: -1 }).success).toBe(false);
  });

  it('projects array can be empty', () => {
    const result = HarnessSummary.safeParse({ ...validHarness, projects: [] });
    expect(result.success).toBe(true);
  });

  it('categories array can be empty', () => {
    const result = HarnessSummary.safeParse({ ...validHarness, categories: [] });
    expect(result.success).toBe(true);
  });
});

// ─── ListHarnessesResponse ────────────────────────────────────────────────────

describe('ListHarnessesResponse', () => {
  it('accepts empty items array', () => {
    expect(ListHarnessesResponse.safeParse({ items: [] }).success).toBe(true);
  });

  it('rejects missing items field', () => {
    expect(ListHarnessesResponse.safeParse({}).success).toBe(false);
  });
});

// ─── AssetGroup ───────────────────────────────────────────────────────────────

describe('AssetGroup', () => {
  it('parses mcp group with trustRollup', () => {
    const group = {
      type: 'mcp',
      total: 6,
      trustRollup: { unapproved: 1, risky: 2 },
      flagRollup: { change: 1 },
      items: [
        {
          id: 'mcp-filesystem',
          type: 'mcp',
          name: 'filesystem',
          sub: 'local · stdio',
          flags: [],
          trust: 'known-good',
        },
      ],
    };
    const result = AssetGroup.safeParse(group);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.trustRollup).toBeDefined();
    }
  });

  it('parses skill group without trustRollup', () => {
    const group = {
      type: 'skill',
      total: 3,
      flagRollup: {},
      items: [{ id: 'skill-bash', type: 'skill', name: 'bash', sub: 'shell', flags: [] }],
    };
    const result = AssetGroup.safeParse(group);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.trustRollup).toBeUndefined();
    }
  });

  it('total must be a non-negative integer', () => {
    expect(
      AssetGroup.safeParse({ type: 'skill', total: -1, flagRollup: {}, items: [] }).success,
    ).toBe(false);
  });

  // RED before fix #6: z.record(z.string()) accepts any key — contract: enum-keyed
  it('trustRollup rejects keys outside TrustLevel enum — contract: enum-keyed', () => {
    const result = AssetGroup.safeParse({
      type: 'mcp',
      total: 1,
      trustRollup: { invalid_trust_key: 1 },
      flagRollup: {},
      items: [],
    });
    expect(result.success).toBe(false);
  });

  // RED before fix #6: z.record(z.string()) accepts any key — contract: enum-keyed
  it('flagRollup rejects keys outside Flag enum — contract: enum-keyed', () => {
    const result = AssetGroup.safeParse({
      type: 'skill',
      total: 1,
      flagRollup: { not_a_valid_flag: 1 },
      items: [],
    });
    expect(result.success).toBe(false);
  });
});

// ─── ListAssetsResponse ───────────────────────────────────────────────────────

describe('ListAssetsResponse', () => {
  it('accepts empty groups array', () => {
    expect(ListAssetsResponse.safeParse({ groups: [] }).success).toBe(true);
  });

  it('rejects missing groups field', () => {
    expect(ListAssetsResponse.safeParse({}).success).toBe(false);
  });
});

// ─── McpTool ─────────────────────────────────────────────────────────────────

describe('McpTool', () => {
  it('parses a tool with null risk', () => {
    const tool = {
      name: 'search',
      signature: '(query)',
      description: 'Search workspace',
      write: false,
      risk: null,
    };
    const result = McpTool.safeParse(tool);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.risk).toBeNull();
    }
  });

  it('parses a tool with a non-null risk string', () => {
    const tool = {
      name: 'create_page',
      signature: '(parent, properties)',
      description: 'Create a page',
      write: true,
      risk: 'Unverified publisher — calls blocked at proxy',
    };
    const result = McpTool.safeParse(tool);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.risk).toBe('Unverified publisher — calls blocked at proxy');
    }
  });

  it('risk must be string or null, not undefined', () => {
    const tool = {
      name: 'search',
      signature: '(query)',
      description: 'Search workspace',
      write: false,
    };
    expect(McpTool.safeParse(tool).success).toBe(false);
  });
});

// ─── AssetDetail ─────────────────────────────────────────────────────────────

describe('AssetDetail (trust/tools omitted for non-mcp)', () => {
  const validMcpDetail = {
    id: 'mcp-notion',
    type: 'mcp',
    name: 'notion-bridge',
    sub: 'mcp://notion-bridge',
    flags: ['change'],
    description: 'Notion workspace sync',
    trust: 'unapproved',
    meta: { host: 'mcp://notion-bridge', toolCount: 11 },
    finding: { id: 'cfg-risk-mcp', title: 'Unverified MCP server added', note: 'Appeared 2h ago' },
    tools: [
      {
        name: 'search',
        signature: '(query)',
        description: 'Search workspace',
        write: false,
        risk: 'Blocked',
      },
    ],
  };

  it('parses a full MCP asset detail with trust and tools', () => {
    const result = AssetDetail.safeParse(validMcpDetail);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.trust).toBe('unapproved');
      expect(result.data.tools).toHaveLength(1);
    }
  });

  it('parses a skill asset with trust null and no tools — non-MCP assets carry trust null', () => {
    const skillDetail = {
      id: 'skill-bash',
      type: 'skill',
      name: 'bash',
      sub: 'shell',
      flags: [],
      description: null,
      meta: { source: 'plugin', installed: '1.0.0' },
      finding: null,
      trust: null, // contract: non-MCP assets carry trust = null, not absent
    };
    const result = AssetDetail.safeParse(skillDetail);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.trust).toBeNull();
      expect(result.data.tools).toBeUndefined();
    }
  });

  it('finding can be null', () => {
    const result = AssetDetail.safeParse({ ...validMcpDetail, finding: null });
    expect(result.success).toBe(true);
  });

  // RED before fix #2: .optional() rejects null — description must accept null
  it('description: null is valid — description is string | null', () => {
    const result = AssetDetail.safeParse({ ...validMcpDetail, description: null });
    expect(result.success).toBe(true);
  });

  // RED before fix #1: .optional() rejects null — trust must accept null
  it('trust: null is valid — trust is trustLevel | null', () => {
    const result = AssetDetail.safeParse({ ...validMcpDetail, trust: null });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.trust).toBeNull();
    }
  });

  // RED before fix #7: nullable().optional() allows absent finding — finding must always be present
  it('finding absent fails — finding is always present (object | null)', () => {
    const withoutFinding = {
      id: validMcpDetail.id,
      type: validMcpDetail.type,
      name: validMcpDetail.name,
      sub: validMcpDetail.sub,
      flags: validMcpDetail.flags,
      description: validMcpDetail.description,
      trust: validMcpDetail.trust,
      meta: validMcpDetail.meta,
      tools: validMcpDetail.tools,
      // finding intentionally omitted
    };
    expect(AssetDetail.safeParse(withoutFinding).success).toBe(false);
  });
});

// ─── ListProjectsResponse ─────────────────────────────────────────────────────

describe('ListProjectsResponse', () => {
  it('accepts a list of project summaries', () => {
    const result = ListProjectsResponse.safeParse({ items: [validProjectSummary] });
    expect(result.success).toBe(true);
  });

  it('accepts empty items array', () => {
    expect(ListProjectsResponse.safeParse({ items: [] }).success).toBe(true);
  });
});

// ─── InventoryStats ───────────────────────────────────────────────────────────

describe('InventoryStats', () => {
  it('parses all-zero empty stats', () => {
    const result = InventoryStats.safeParse({
      attention: 0,
      byType: { project: 0, skill: 0, mcp: 0, hook: 0, config: 0 },
      harnesses: 0,
      mcpTrust: { 'known-good': 0, risky: 0, unapproved: 0 },
    });
    expect(result.success).toBe(true);
  });

  it('parses realistic stats', () => {
    const result = InventoryStats.safeParse({
      attention: 7,
      byType: { project: 7, skill: 8, mcp: 6, hook: 8, config: 13 },
      harnesses: 3,
      mcpTrust: { 'known-good': 3, risky: 2, unapproved: 1 },
    });
    expect(result.success).toBe(true);
  });

  it('attention must be a non-negative integer', () => {
    expect(
      InventoryStats.safeParse({
        attention: -1,
        byType: { project: 0, skill: 0, mcp: 0, hook: 0, config: 0 },
        harnesses: 0,
        mcpTrust: { 'known-good': 0, risky: 0, unapproved: 0 },
      }).success,
    ).toBe(false);
  });

  it('rejects missing byType fields', () => {
    expect(
      InventoryStats.safeParse({
        attention: 0,
        byType: { project: 0, skill: 0, mcp: 0 },
        harnesses: 0,
        mcpTrust: { 'known-good': 0, risky: 0, unapproved: 0 },
      }).success,
    ).toBe(false);
  });
});

// ─── FileSummary ──────────────────────────────────────────────────────────────

describe('FileSummary', () => {
  const validFile = {
    path: 'src/config/aws.ts',
    name: 'aws.ts',
    origin: 'config',
    access: 'blocked',
    isCustom: false,
    findings: 1,
    blockedAt: '2026-06-30T16:39:00Z',
    note: 'AWS access key detected',
  };

  it('parses a valid file summary', () => {
    const result = FileSummary.safeParse(validFile);
    expect(result.success).toBe(true);
  });

  it('blockedAt is optional (null or absent)', () => {
    expect(FileSummary.safeParse({ ...validFile, blockedAt: null }).success).toBe(true);
    const withoutBlockedAt = {
      path: validFile.path,
      name: validFile.name,
      origin: validFile.origin,
      access: validFile.access,
      isCustom: validFile.isCustom,
      findings: validFile.findings,
      note: validFile.note,
    };
    expect(FileSummary.safeParse(withoutBlockedAt).success).toBe(true);
  });

  it('blockedAt must be an ISO datetime when present', () => {
    expect(FileSummary.safeParse({ ...validFile, blockedAt: 'not-a-date' }).success).toBe(false);
  });

  it('note is optional (null or absent)', () => {
    expect(FileSummary.safeParse({ ...validFile, note: null }).success).toBe(true);
    const withoutNote = {
      path: validFile.path,
      name: validFile.name,
      origin: validFile.origin,
      access: validFile.access,
      isCustom: validFile.isCustom,
      findings: validFile.findings,
      blockedAt: validFile.blockedAt,
    };
    expect(FileSummary.safeParse(withoutNote).success).toBe(true);
  });

  it('findings must be a non-negative integer', () => {
    expect(FileSummary.safeParse({ ...validFile, findings: 0 }).success).toBe(true);
    expect(FileSummary.safeParse({ ...validFile, findings: -1 }).success).toBe(false);
  });
});

// ─── FolderSummary ────────────────────────────────────────────────────────────

describe('FolderSummary', () => {
  it('parses a valid folder summary', () => {
    const result = FolderSummary.safeParse({
      name: 'config',
      path: 'src/config',
      accessCounts: { open: 0, approved: 2, blocked: 2, total: 4 },
    });
    expect(result.success).toBe(true);
  });

  it('rejects negative accessCounts', () => {
    expect(
      FolderSummary.safeParse({
        name: 'config',
        path: 'src/config',
        accessCounts: { open: -1, approved: 2, blocked: 2, total: 4 },
      }).success,
    ).toBe(false);
  });
});

// ─── ProjectTreeResponse ──────────────────────────────────────────────────────

describe('ProjectTreeResponse', () => {
  const validTree = {
    project: { id: 'payments-api', repo: 'globex/payments-api', visibility: 'private' },
    path: 'src/config',
    folders: [
      {
        name: 'config',
        path: 'src/config',
        accessCounts: { open: 0, approved: 2, blocked: 2, total: 4 },
      },
    ],
    files: [
      {
        path: 'src/config/aws.ts',
        name: 'aws.ts',
        origin: 'config',
        access: 'blocked',
        isCustom: false,
        findings: 1,
        blockedAt: '2026-06-30T16:39:00Z',
        note: 'AWS access key detected',
      },
    ],
  };

  it('parses a valid browse-mode tree response', () => {
    expect(ProjectTreeResponse.safeParse(validTree).success).toBe(true);
  });

  it('folders is optional (search mode omits it)', () => {
    const withoutFolders = {
      project: validTree.project,
      path: validTree.path,
      files: validTree.files,
    };
    expect(ProjectTreeResponse.safeParse(withoutFolders).success).toBe(true);
  });

  it('files can be empty array', () => {
    expect(ProjectTreeResponse.safeParse({ ...validTree, files: [] }).success).toBe(true);
  });
});

// ─── FileDetail ───────────────────────────────────────────────────────────────

describe('FileDetail', () => {
  it('parses a valid file detail with project context and findingsRefs', () => {
    const result = FileDetail.safeParse({
      path: 'src/config/aws.ts',
      name: 'aws.ts',
      origin: 'config',
      access: 'blocked',
      isCustom: false,
      findings: 1,
      blockedAt: '2026-06-30T16:39:00Z',
      note: 'AWS access key detected',
      project: {
        repo: 'globex/payments-api',
        visibility: 'private',
        language: 'TypeScript',
        policyDefault: 'approved',
        updatedAt: '2026-06-30T16:41:00Z',
      },
      findingsRefs: [{ id: 'D-4790', title: 'Postgres connection string detected' }],
    });
    expect(result.success).toBe(true);
  });

  it('findingsRefs can be an empty array', () => {
    const result = FileDetail.safeParse({
      path: 'src/main.ts',
      name: 'main.ts',
      origin: 'source',
      access: 'approved',
      isCustom: false,
      findings: 0,
      project: {
        repo: 'globex/payments-api',
        visibility: 'private',
        language: 'TypeScript',
        policyDefault: 'approved',
        updatedAt: '2026-06-30T16:41:00Z',
      },
      findingsRefs: [],
    });
    expect(result.success).toBe(true);
  });
});

// ─── SetFileAccessBody ────────────────────────────────────────────────────────

describe('SetFileAccessBody', () => {
  it('parses valid body', () => {
    const result = SetFileAccessBody.safeParse({ path: 'src/config/aws.ts', access: 'approved' });
    expect(result.success).toBe(true);
  });

  it('rejects invalid access value', () => {
    expect(
      SetFileAccessBody.safeParse({ path: 'src/config/aws.ts', access: 'invalid' }).success,
    ).toBe(false);
  });

  it('rejects missing path', () => {
    expect(SetFileAccessBody.safeParse({ access: 'blocked' }).success).toBe(false);
  });
});

// ─── SetFileAccessResponse ────────────────────────────────────────────────────

describe('SetFileAccessResponse', () => {
  it('parses a valid response with file and accessCounts', () => {
    const result = SetFileAccessResponse.safeParse({
      file: {
        path: 'src/config/aws.ts',
        name: 'aws.ts',
        origin: 'config',
        access: 'approved',
        isCustom: true,
        findings: 1,
        blockedAt: null,
        note: null,
      },
      accessCounts: { open: 4, approved: 14, blocked: 1, total: 19 },
    });
    expect(result.success).toBe(true);
  });
});

// ─── SetMcpTrustBody ──────────────────────────────────────────────────────────

describe('SetMcpTrustBody', () => {
  it('parses valid trust values', () => {
    for (const v of ['known-good', 'risky', 'unapproved']) {
      expect(SetMcpTrustBody.safeParse({ trust: v }).success).toBe(true);
    }
  });

  it('rejects invalid trust value', () => {
    expect(SetMcpTrustBody.safeParse({ trust: 'invalid' }).success).toBe(false);
  });
});

// ─── HarnessEventItem ─────────────────────────────────────────────────────────

describe('HarnessEventItem', () => {
  it('parses a valid event item with findingId', () => {
    const result = HarnessEventItem.safeParse({
      kind: 'redact',
      title: 'Redacted Postgres connection string',
      detail: 'src/config/database.ts · sent with secret masked',
      occurredAt: '2026-06-30T09:19:00Z',
      findingId: 'D-4790',
    });
    expect(result.success).toBe(true);
  });

  it('findingId is optional (null allowed)', () => {
    const result = HarnessEventItem.safeParse({
      kind: 'block',
      title: 'Blocked request',
      detail: 'detail text',
      occurredAt: '2026-06-30T09:19:00Z',
      findingId: null,
    });
    expect(result.success).toBe(true);
  });

  it('occurredAt must be an ISO datetime string', () => {
    expect(
      HarnessEventItem.safeParse({
        kind: 'warn',
        title: 'Warning',
        detail: 'detail',
        occurredAt: 'not-a-date',
      }).success,
    ).toBe(false);
  });
});

// ─── HarnessEventsResponse ────────────────────────────────────────────────────

describe('HarnessEventsResponse', () => {
  it('parses a valid response with counts and items', () => {
    const result = HarnessEventsResponse.safeParse({
      counts: { block: 1, redact: 2, warn: 2 },
      items: [
        {
          kind: 'redact',
          title: 'Redacted secret',
          detail: 'detail text',
          occurredAt: '2026-06-30T09:19:00Z',
          findingId: 'D-4790',
        },
      ],
    });
    expect(result.success).toBe(true);
  });

  it('counts must have block, redact, warn as non-negative integers', () => {
    expect(
      HarnessEventsResponse.safeParse({
        counts: { block: 0, redact: 0, warn: 0 },
        items: [],
      }).success,
    ).toBe(true);

    expect(
      HarnessEventsResponse.safeParse({
        counts: { block: -1, redact: 0, warn: 0 },
        items: [],
      }).success,
    ).toBe(false);
  });

  it('accepts empty items array', () => {
    expect(
      HarnessEventsResponse.safeParse({
        counts: { block: 0, redact: 0, warn: 0 },
        items: [],
      }).success,
    ).toBe(true);
  });
});

// ─── RescanResponse ───────────────────────────────────────────────────────────

describe('RescanResponse', () => {
  it('parses a valid rescan response', () => {
    const result = RescanResponse.safeParse({
      jobId: 'scan_abc123',
      startedAt: '2026-06-30T16:45:00Z',
    });
    expect(result.success).toBe(true);
  });

  it('startedAt must be an ISO datetime string', () => {
    expect(
      RescanResponse.safeParse({ jobId: 'scan_abc123', startedAt: 'not-a-date' }).success,
    ).toBe(false);
  });

  it('rejects missing jobId', () => {
    expect(RescanResponse.safeParse({ startedAt: '2026-06-30T16:45:00Z' }).success).toBe(false);
  });
});

// ─── ConnectProjectBody ───────────────────────────────────────────────────────

describe('ConnectProjectBody', () => {
  it('parses a valid repo string', () => {
    const result = ConnectProjectBody.safeParse({ repo: 'globex/new-service' });
    expect(result.success).toBe(true);
  });

  it('rejects missing repo', () => {
    expect(ConnectProjectBody.safeParse({}).success).toBe(false);
  });

  it('rejects non-string repo', () => {
    expect(ConnectProjectBody.safeParse({ repo: 123 }).success).toBe(false);
  });
});

// ─── ListAssetsQuery ──────────────────────────────────────────────────────────

describe('ListAssetsQuery', () => {
  it('all fields optional — empty object succeeds', () => {
    expect(ListAssetsQuery.safeParse({}).success).toBe(true);
  });

  it('accepts type array filter', () => {
    expect(ListAssetsQuery.safeParse({ type: ['mcp', 'skill'] }).success).toBe(true);
  });

  it('accepts free-text q', () => {
    expect(ListAssetsQuery.safeParse({ q: 'notion' }).success).toBe(true);
  });
});

// ─── GetProjectTreeQuery ──────────────────────────────────────────────────────

describe('GetProjectTreeQuery', () => {
  it('all fields optional — empty object succeeds', () => {
    expect(GetProjectTreeQuery.safeParse({}).success).toBe(true);
  });

  it('accepts path and q together', () => {
    expect(GetProjectTreeQuery.safeParse({ path: 'src', q: 'aws' }).success).toBe(true);
  });
});

// ─── GetProjectFileQuery ──────────────────────────────────────────────────────

describe('GetProjectFileQuery', () => {
  it('requires path — absent must fail', () => {
    expect(GetProjectFileQuery.safeParse({}).success).toBe(false);
  });

  it('accepts valid path', () => {
    expect(GetProjectFileQuery.safeParse({ path: 'src/main.ts' }).success).toBe(true);
  });
});

// ─── GetHarnessEventsQuery ────────────────────────────────────────────────────

describe('GetHarnessEventsQuery', () => {
  it('defaults limit to 7 when absent', () => {
    const result = GetHarnessEventsQuery.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(7);
    }
  });

  it('accepts limit = 1 (min boundary)', () => {
    expect(GetHarnessEventsQuery.safeParse({ limit: 1 }).success).toBe(true);
  });

  it('accepts limit = 50 (max boundary)', () => {
    expect(GetHarnessEventsQuery.safeParse({ limit: 50 }).success).toBe(true);
  });

  it('rejects limit = 0 — below minimum of 1', () => {
    expect(GetHarnessEventsQuery.safeParse({ limit: 0 }).success).toBe(false);
  });

  it('rejects limit = 51 — above maximum of 50', () => {
    expect(GetHarnessEventsQuery.safeParse({ limit: 51 }).success).toBe(false);
  });
});
