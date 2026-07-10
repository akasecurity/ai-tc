import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';

import { sampleAssetId, sampleHarnessId, sampleProjectId } from './sample-ids.ts';

/**
 * TEST FIXTURE (see ./index.ts): the Inventory sample dataset — an authored asset
 * model (harnesses → skills/MCP/hooks/config, projects → files with per-file LLM
 * access) written to the schema shapes. Everything is tagged provenance='sample' —
 * exactly what sample-purge.ts deletes, which the inventory tests exercise: the
 * asset tables (inventory_asset) carry a provenance COLUMN; the shared
 * inventory (harness) / source_project (project) tables — which stay byte-identical
 * to their base-row contracts — carry it (plus per-project extras + the
 * harness↔project/session linkage) inside their `attributes` JSON.
 */

interface SampleTool {
  name: string;
  signature: string;
  description: string;
  write: boolean;
  risk: string | null;
}
interface SampleAsset {
  slug: string;
  type: 'skill' | 'mcp' | 'hook' | 'config';
  name: string;
  sub: string;
  description: string;
  flags: string[];
  trust?: 'known-good' | 'risky' | 'unapproved';
  tools?: SampleTool[];
  meta?: Record<string, unknown>;
}
interface SampleFile {
  path: string;
  origin: 'source' | 'public-dep' | 'vendored' | 'config' | 'data' | 'docs' | 'generated';
  access: 'open' | 'approved' | 'blocked';
  findings?: number;
  blockedMinAgo?: number;
  note?: string;
}
interface SampleProject {
  slug: string;
  url: string;
  name: string;
  visibility: 'public' | 'private';
  language: string;
  policyDefault: 'open' | 'approved' | 'blocked';
  files: SampleFile[];
}
interface SampleHarness {
  slug: string;
  provider: 'claudecode' | 'cursor' | 'codex';
  label: string;
  kind: string;
  version: string;
  sessions: number;
  projectSlugs: string[];
  assetSlugs: string[];
}

const PROJECTS: SampleProject[] = [
  {
    slug: 'payments-api',
    url: 'https://github.com/globex/payments-api',
    name: 'payments-api',
    visibility: 'private',
    language: 'TypeScript',
    policyDefault: 'approved',
    files: [
      { path: 'src/services/charge.ts', origin: 'source', access: 'approved', findings: 2 },
      { path: 'src/services/customer.ts', origin: 'source', access: 'approved', findings: 1 },
      {
        path: 'src/config/secrets.ts',
        origin: 'config',
        access: 'blocked',
        blockedMinAgo: 12,
        note: 'Contains references to the secrets vault path.',
      },
      { path: 'src/observability/logger.ts', origin: 'source', access: 'approved' },
      { path: 'src/observability/metrics.ts', origin: 'source', access: 'approved' },
      { path: 'src/jobs/settlement.ts', origin: 'source', access: 'approved', findings: 1 },
      { path: 'src/index.ts', origin: 'source', access: 'approved' },
      {
        path: '.env.example',
        origin: 'config',
        access: 'blocked',
        blockedMinAgo: 240,
        note: 'Environment template — blocked from LLM access.',
      },
      { path: 'vendor/payment-sdk/lib/client.js', origin: 'vendored', access: 'open' },
      { path: 'vendor/analytics-sdk/client.rs', origin: 'vendored', access: 'open' },
      { path: 'docs/architecture.md', origin: 'docs', access: 'open' },
      { path: 'package.json', origin: 'config', access: 'approved' },
    ],
  },
  {
    slug: 'matching-core',
    url: 'https://github.com/globex/matching-core',
    name: 'matching-core',
    visibility: 'private',
    language: 'Rust',
    policyDefault: 'blocked',
    files: [
      { path: 'src/engine/match.rs', origin: 'source', access: 'blocked' },
      { path: 'src/engine/score.rs', origin: 'source', access: 'blocked', findings: 3 },
      { path: 'Cargo.toml', origin: 'config', access: 'approved' },
      { path: 'README.md', origin: 'docs', access: 'open' },
    ],
  },
  {
    slug: 'crm-sync',
    url: 'https://github.com/globex/crm-sync',
    name: 'crm-sync',
    visibility: 'public',
    language: 'Python',
    policyDefault: 'open',
    files: [
      { path: 'src/log.py', origin: 'source', access: 'open' },
      { path: 'src/sync.py', origin: 'source', access: 'open' },
      { path: 'requirements.txt', origin: 'config', access: 'open' },
    ],
  },
];

const ASSETS: SampleAsset[] = [
  {
    slug: 'commit-helper',
    type: 'skill',
    name: 'commit-helper',
    sub: 'Skill · authored',
    description: 'Drafts Conventional Commit messages from the staged diff.',
    flags: ['update'],
  },
  {
    slug: 'pr-summarizer',
    type: 'skill',
    name: 'pr-summarizer',
    sub: 'Skill · authored',
    description: 'Summarizes a pull request from its commits and diff.',
    flags: [],
  },
  {
    slug: 'test-writer',
    type: 'skill',
    name: 'test-writer',
    sub: 'Skill · authored',
    description: 'Generates unit tests for the selected module.',
    flags: ['stale'],
  },
  {
    slug: 'github-mcp',
    type: 'mcp',
    name: 'github',
    sub: 'MCP server · @modelcontextprotocol/server-github',
    description: 'Read and write GitHub issues, PRs and repository contents.',
    flags: [],
    trust: 'known-good',
    meta: { transport: 'stdio', command: 'npx @modelcontextprotocol/server-github' },
    tools: [
      {
        name: 'list_issues',
        signature: 'list_issues(repo)',
        description: 'List issues in a repository.',
        write: false,
        risk: null,
      },
      {
        name: 'create_issue',
        signature: 'create_issue(repo, title, body)',
        description: 'Open a new issue.',
        write: true,
        risk: null,
      },
    ],
  },
  {
    slug: 'postgres-mcp',
    type: 'mcp',
    name: 'postgres',
    sub: 'MCP server · @modelcontextprotocol/server-postgres',
    description: 'Run read-only SQL against the analytics database.',
    flags: ['unknown'],
    trust: 'risky',
    meta: { transport: 'stdio', database: 'analytics (read replica)' },
    tools: [
      {
        name: 'query',
        signature: 'query(sql)',
        description: 'Run a SELECT statement.',
        write: false,
        risk: 'Can read any table the connection can access.',
      },
    ],
  },
  {
    slug: 'shell-runner-mcp',
    type: 'mcp',
    name: 'shell-runner',
    sub: 'MCP server · unverified',
    description: 'Executes arbitrary shell commands on the host.',
    flags: ['risk'],
    trust: 'unapproved',
    meta: { transport: 'stdio', command: './bin/shell-mcp' },
    tools: [
      {
        name: 'run',
        signature: 'run(cmd)',
        description: 'Execute a shell command.',
        write: true,
        risk: 'Arbitrary command execution on the host.',
      },
    ],
  },
  {
    slug: 'pre-commit-scan',
    type: 'hook',
    name: 'pre-commit-scan',
    sub: 'Hook · PreToolUse',
    description: 'Scans staged changes for secrets before a commit.',
    flags: [],
  },
  {
    slug: 'session-logger',
    type: 'hook',
    name: 'session-logger',
    sub: 'Hook · SessionStart',
    description: 'Records a session-start audit event.',
    flags: ['change'],
  },
  {
    slug: 'claude-md',
    type: 'config',
    name: 'CLAUDE.md',
    sub: 'Project config',
    description: 'Repository conventions loaded into every session.',
    flags: [],
  },
  {
    slug: 'settings-json',
    type: 'config',
    name: 'settings.json',
    sub: 'Local config · ~/.claude',
    description: 'Claude Code permissions and hook configuration.',
    flags: ['untracked'],
  },
];

const HARNESSES: SampleHarness[] = [
  {
    slug: 'claudecode',
    provider: 'claudecode',
    label: 'Claude Code',
    kind: 'claude_code',
    version: '2.1.0',
    sessions: 128,
    projectSlugs: ['payments-api', 'matching-core', 'crm-sync'],
    assetSlugs: [
      'commit-helper',
      'pr-summarizer',
      'test-writer',
      'github-mcp',
      'postgres-mcp',
      'shell-runner-mcp',
      'pre-commit-scan',
      'session-logger',
      'claude-md',
      'settings-json',
    ],
  },
  {
    slug: 'cursor',
    provider: 'cursor',
    label: 'Cursor',
    kind: 'cursor',
    version: '0.43.0',
    sessions: 42,
    projectSlugs: ['payments-api'],
    assetSlugs: ['github-mcp', 'commit-helper', 'claude-md'],
  },
];

// Shared with the Data Shares seed so cross-domain ids line up (see sample-ids.ts).
const projectId = sampleProjectId;
const assetId = sampleAssetId;
const harnessId = sampleHarnessId;

/**
 * Inserts the sample Inventory dataset (provenance='sample').
 */
export function seedSampleInventory(db: DatabaseSync, now: number = Date.now()): void {
  const insAsset = db.prepare(
    `INSERT OR IGNORE INTO inventory_asset
       (id, asset_type, name, sub, description, flags_json, meta_json, trust, tools_json, provenance, created_at, updated_at)
     VALUES (:id, :type, :name, :sub, :description, :flags, :meta, :trust, :tools, 'sample', :now, :now)`,
  );
  const insProject = db.prepare(
    `INSERT OR IGNORE INTO source_project (id, url, name, attributes, first_seen, last_seen)
     VALUES (:id, :url, :name, :attributes, :now, :now)`,
  );
  const insFile = db.prepare(
    `INSERT OR IGNORE INTO project_file
       (id, project_id, path, name, origin, default_access, findings_count, blocked_at, note, created_at, updated_at)
     VALUES (:id, :projectId, :path, :name, :origin, :access, :findings, :blockedAt, :note, :now, :now)`,
  );
  const insHarness = db.prepare(
    `INSERT OR IGNORE INTO inventory (id, object_type, location, title, attributes, first_seen, last_seen)
     VALUES (:id, 'harness', NULL, :title, :attributes, :now, :now)`,
  );
  const insLink = db.prepare(
    `INSERT OR IGNORE INTO harness_asset (id, harness_id, asset_id, created_at)
     VALUES (:id, :harnessId, :assetId, :now)`,
  );

  for (const a of ASSETS) {
    insAsset.run({
      id: assetId(a.slug),
      type: a.type,
      name: a.name,
      sub: a.sub,
      description: a.description,
      flags: JSON.stringify(a.flags),
      meta: JSON.stringify(a.meta ?? {}),
      trust: a.trust ?? null,
      tools: a.tools ? JSON.stringify(a.tools) : null,
      now,
    });
  }

  for (const p of PROJECTS) {
    insProject.run({
      id: projectId(p.slug),
      url: p.url,
      name: p.name,
      attributes: JSON.stringify({
        provenance: 'sample',
        visibility: p.visibility,
        language: p.language,
        policyDefault: p.policyDefault,
      }),
      now,
    });
    for (const f of p.files) {
      const name = f.path.slice(f.path.lastIndexOf('/') + 1);
      insFile.run({
        id: `sample:file:${p.slug}:${f.path}`,
        projectId: projectId(p.slug),
        path: f.path,
        name,
        origin: f.origin,
        access: f.access,
        findings: f.findings ?? 0,
        blockedAt: f.blockedMinAgo != null ? now - f.blockedMinAgo * 60_000 : null,
        note: f.note ?? null,
        now,
      });
    }
  }

  for (const h of HARNESSES) {
    insHarness.run({
      id: harnessId(h.slug),
      title: h.label,
      attributes: JSON.stringify({
        provenance: 'sample',
        provider: h.provider,
        kind: h.kind,
        label: h.label,
        harness_version: h.version,
        sessions: h.sessions,
        projectIds: h.projectSlugs.map(projectId),
      }),
      now,
    });
    for (const slug of h.assetSlugs) {
      insLink.run({ id: randomUUID(), harnessId: harnessId(h.slug), assetId: assetId(slug), now });
    }
  }
}
