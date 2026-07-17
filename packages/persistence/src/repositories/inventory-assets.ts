import { randomUUID } from 'node:crypto';
import type { DatabaseSync, SQLInputValue } from 'node:sqlite';

import type {
  AccessCounts,
  AccessLevel,
  AssetDetail,
  AssetGroup,
  AssetSummary,
  ConfigFileInventoryItem,
  FileDetail,
  FileSummary,
  Flag,
  FolderSummary,
  GetProjectTreeQuery,
  HarnessId,
  HarnessSummary,
  HookInventoryItem,
  InventoryStats,
  ListAssetsQuery,
  ListAssetsResponse,
  ListHarnessesResponse,
  ListProjectsResponse,
  McpInventoryItem,
  McpTool,
  Origin,
  ProjectSummary,
  ProjectTreeResponse,
  SkillInventoryItem,
  TrustLevel,
  Visibility,
} from '@akasecurity/schema';
import { HarnessId as HarnessIdSchema } from '@akasecurity/schema';

import { safeJson } from '../internal/json.ts';
import { allRows, countBy, countScalar, getRow } from '../internal/rows.ts';
import { containsPattern, escapeLikePattern, likeAny, placeholders } from '../internal/sql-text.ts';
import type { InventoryReadPort } from '../ports.ts';
import { SqliteConfigInventoryRepository } from './config-inventory.ts';
import { latestConfigScan } from './config-scan.ts';

// ─── Raw row shapes (post-projection, JS-normalised) ─────────────────────────

interface HarnessRow {
  id: string;
  title: string | null;
  attributes: string;
  harnessVersion: string | null;
}
interface AssetRow {
  id: string;
  assetType: 'skill' | 'mcp' | 'hook' | 'config';
  name: string;
  sub: string | null;
  description: string | null;
  flagsJson: string;
  metaJson: string;
  trust: TrustLevel | null;
  toolsJson: string | null;
  effectiveTrust: TrustLevel | null;
}
interface ProjectRow {
  id: string;
  url: string | null;
  name: string | null;
  attributes: string;
  lastSeen: number;
}
interface ProjectFileRow {
  path: string;
  name: string;
  origin: Origin;
  defaultAccess: AccessLevel;
  findingsCount: number;
  blockedAtMs: number | null;
  note: string | null;
  effectiveAccess: AccessLevel;
  overrideAccess: AccessLevel | null;
}

// Ordering: config → skill → mcp → hook (never project).
const CATEGORY_ORDER: readonly AssetRow['assetType'][] = ['config', 'skill', 'mcp', 'hook'];
// Derived from the HarnessId enum, so a new harness lands here automatically
// instead of being silently dropped by resolveHarnessId. Widened to string so
// `.has` accepts the raw (unvalidated) attributes.provider.
const VALID_HARNESS_IDS: ReadonlySet<string> = new Set(HarnessIdSchema.options);

// A source_project row whose url is a Claude Code WORKTREE CHECKOUT path is a
// ghost: pre-worktree-fix plugin versions minted one per `.claude/worktrees/*`
// session instead of attributing it to the head repo. The SessionStart sweep
// (reconcileWorktreeProjects) deletes them, but an older plugin can re-mint one
// at any time — so the Inventory read views ALSO refuse to surface them. The
// checkout is already part of its head project; it is never a project itself.
// Ghosts minted on Windows carry `\`-separated urls (the old resolver never
// normalized its path fallback), so both separator flavors are filtered.
const WORKTREE_CHECKOUT_FILTER =
  "(url IS NULL OR (url NOT LIKE '%/.claude/worktrees/%' AND url NOT LIKE '%\\.claude\\worktrees\\%'))";

// Display labels per resolved HarnessId, derived at read time. REAL scanned
// harness rows carry only a machine-ish title ('claude-code') and no label
// attribute — the SessionStart inventory pass records facts, not presentation —
// so without this map the card renders the raw title while sample rows (which
// author a label attr) render "Claude Code". Record<HarnessId, string> keeps it
// total: a new enum value without a label is a typecheck failure, not a raw id
// leaking into the UI.
const HARNESS_LABELS: Record<HarnessId, string> = {
  claudecode: 'Claude Code',
  cursor: 'Cursor',
  codex: 'Codex',
};

// A harness (AI tool) is "live" only if its inventory row was seen within this
// window. Unlike config_scan — which re-sees every skill/hook each pass, so their
// liveness is exact ("seen by the latest scan") — the inventory pass upserts only
// the ONE harness running the current session and can't observe other installed
// tools. So harness liveness is a recency window, not exact-pass matching: a tool
// used in the last 30 days stays; one abandoned longer than that drops off.
// Seeded sample harnesses (attributes.provenance='sample') are EXEMPT: their
// last_seen is frozen at seed time, so the window would otherwise blank a demo/eval
// store's harness cards after 30 days while its sample assets still render.
const HARNESS_LIVENESS_WINDOW_MS = 30 * 24 * 60 * 60 * 1000;

// Per-project file rollup (effective access counts + findings), assembled once by
// projectAggregates and shared by listHarnesses/listProjects.
interface ProjectAggregate {
  accessCounts: AccessCounts;
  findingsCount: number;
}
// The rollup for a project with no files (or one not in the aggregate map).
const EMPTY_PROJECT_AGG: ProjectAggregate = {
  accessCounts: { open: 0, approved: 0, blocked: 0, total: 0 },
  findingsCount: 0,
};

// Extra per-project fields (visibility/language/policyDefault) + the harness↔project/
// session linkage are carried in the shared inventory/source_project tables'
// `attributes` JSON (those tables stay byte-identical to their base-row contracts;
// see the schema note). This reads them back.
interface ProjectAttrs {
  visibility?: Visibility;
  language?: string;
  policyDefault?: AccessLevel;
  provenance?: string;
}
interface HarnessAttrs {
  provider?: string;
  kind?: string;
  label?: string;
  harness_version?: string;
  sessions?: number;
  projectIds?: string[];
  // 'sample' on seeded harness rows; absent on real (scanned) ones. Gates whether
  // the projected config-inventory assets (skills/hooks) attach to this harness.
  provenance?: string;
}

function resolveHarnessId(attrs: HarnessAttrs, row: HarnessRow): HarnessId | null {
  if (attrs.provider && VALID_HARNESS_IDS.has(attrs.provider)) {
    return attrs.provider as HarnessId;
  }
  const t = (row.title ?? '').toLowerCase().replace(/[\s-]/g, '');
  if (t.includes('claudecode') || t === 'claude') return 'claudecode';
  if (t.includes('cursor')) return 'cursor';
  if (t.includes('codex')) return 'codex';
  return null;
}

// Whether the given harness rows contain a live, real (non-sample) Claude Code
// harness — the exact card listHarnesses attaches config assets to. Config-asset
// visibility (stats/listAssets/getAsset) is gated on this so the unconditional
// counts can't diverge from the conditional harness attach. Callers pass rows that
// are ALREADY liveness-filtered by fetchHarnessRows, so a non-sample match here is
// necessarily live.
function isLiveRealClaudeCode(rows: HarnessRow[]): boolean {
  return rows.some((r) => {
    const attrs = safeJson<HarnessAttrs>(r.attributes, {});
    return attrs.provenance !== 'sample' && resolveHarnessId(attrs, r) === 'claudecode';
  });
}

// ─── Row → schema shape ──────────────────────────────────────────────────────

function toAssetSummary(row: AssetRow): AssetSummary {
  const summary: AssetSummary = {
    id: row.id,
    type: row.assetType,
    name: row.name,
    sub: row.sub ?? '',
    flags: safeJson(row.flagsJson, [] as Flag[]),
  };
  if (row.assetType === 'mcp' && row.effectiveTrust) summary.trust = row.effectiveTrust;
  return summary;
}

function buildAssetDetail(row: AssetRow): AssetDetail {
  const detail: AssetDetail = {
    id: row.id,
    type: row.assetType,
    name: row.name,
    sub: row.sub ?? '',
    flags: safeJson(row.flagsJson, [] as Flag[]),
    description: row.description ?? null,
    trust: row.assetType === 'mcp' ? (row.effectiveTrust ?? null) : null,
    meta: safeJson<Record<string, unknown>>(row.metaJson, {}),
    // No asset↔finding join in the local model yet — always null.
    finding: null,
  };
  // Real scanned MCP rows have NO tools list (toolsJson null): enumerating
  // tools needs a live MCP handshake the read-only scanner never performs, so
  // `tools` is omitted — an empty list would render as a hollow "Exposed
  // tools 0" section (the view only checks truthiness).
  if (row.assetType === 'mcp' && row.toolsJson !== null) {
    const rawTools = safeJson(row.toolsJson, [] as McpTool[]);
    detail.tools =
      row.effectiveTrust === 'unapproved'
        ? rawTools.map((t) => ({
            ...t,
            risk: t.risk ?? 'Tool access blocked: MCP server trust is unapproved.',
          }))
        : rawTools;
  }
  return detail;
}

// ─── Config-inventory (real skills/hooks/MCP servers) → AssetRow ──────────────
// Real scanned skills/hooks/MCP servers live in the meta `inventory` table
// (object_type skill|hook|mcp_server), NOT inventory_asset. We project the
// config-inventory report into the shared AssetRow shape so they render through
// the same toAssetSummary/buildAssetDetail path as sample assets. Posture status
// collapses onto the Flag vocabulary the Inventory page already understands; the
// richer fields (command, matcher, warnings, versions, env keys) ride the
// detail-pane `meta` grid. MCP trust is the report's EFFECTIVE trust (user
// override ?? review-required default).

function skillAssetRow(item: SkillInventoryItem): AssetRow {
  const flags: Flag[] = item.status === 'update_available' ? ['update'] : [];
  const meta: Record<string, unknown> = { source: item.source, scope: item.scope };
  if (item.installedVersion !== undefined) meta.installedVersion = item.installedVersion;
  if (item.latestVersion !== undefined) meta.latestVersion = item.latestVersion;
  if (item.updatedAt !== undefined) meta.updatedAt = item.updatedAt;
  return {
    id: item.id,
    assetType: 'skill',
    name: item.name,
    sub: `Skill · ${item.source}`,
    description: item.description ?? null,
    flagsJson: JSON.stringify(flags),
    metaJson: JSON.stringify(meta),
    trust: null,
    toolsJson: null,
    effectiveTrust: null,
  };
}

function hookAssetRow(item: HookInventoryItem): AssetRow {
  // Highest-severity posture status wins the single Flag slot; 'egress' maps to
  // 'risk' — the one badge a UI must not soften into plain 'active'.
  const flags: Flag[] =
    item.status === 'egress'
      ? ['risk']
      : item.status === 'conflict'
        ? ['conflict']
        : item.status === 'unknown'
          ? ['unknown']
          : [];
  const meta: Record<string, unknown> = {
    event: item.event,
    command: item.command,
    scope: item.scope,
    status: item.status,
  };
  if (item.matcher !== undefined) meta.matcher = item.matcher;
  if (item.pluginName !== undefined) meta.pluginName = item.pluginName;
  if (item.warnings.length > 0) meta.warnings = item.warnings;
  return {
    id: item.id,
    assetType: 'hook',
    name: truncateInline(item.command.trim(), 64),
    sub: item.matcher ? `Hook · ${item.event} · ${item.matcher}` : `Hook · ${item.event}`,
    description: item.warnings.length > 0 ? item.warnings.join(' · ') : null,
    flagsJson: JSON.stringify(flags),
    metaJson: JSON.stringify(meta),
    trust: null,
    toolsJson: null,
    effectiveTrust: null,
  };
}

function mcpAssetRow(item: McpInventoryItem): AssetRow {
  const meta: Record<string, unknown> = { scope: item.scope, transport: item.transport };
  if (item.command !== undefined) meta.command = item.command;
  if (item.url !== undefined) meta.url = item.url;
  if (item.envKeys !== undefined) meta.envKeys = item.envKeys;
  if (item.pluginName !== undefined) meta.pluginName = item.pluginName;
  if (item.marketplace !== undefined) meta.marketplace = item.marketplace;
  if (item.project !== undefined) meta.project = item.project;
  return {
    id: item.id,
    assetType: 'mcp',
    name: item.name,
    sub: `MCP server · ${item.transport} · ${truncateInline(mcpEndpointLabel(item), 48)}`,
    description: null,
    flagsJson: '[]',
    metaJson: JSON.stringify(meta),
    // Base trust is the constant review-required default — never stored, so
    // setMcpTrust's clear-on-default compare works without a stored column.
    trust: 'unapproved',
    // No tools: a static scan can't enumerate them (needs a live handshake).
    toolsJson: null,
    // Effective = the user's override when set, else the default (applied in
    // the report builder). toAssetSummary copies this onto summary.trust.
    effectiveTrust: item.trust,
  };
}

// The human half of the sub label: a remote server's host, a stdio server's
// command. URL parsing is best-effort — a malformed url renders raw.
function mcpEndpointLabel(item: McpInventoryItem): string {
  if (item.url !== undefined) {
    try {
      return new URL(item.url).host;
    } catch {
      return item.url;
    }
  }
  return item.command ?? item.name;
}

function configFileAssetRow(item: ConfigFileInventoryItem): AssetRow {
  // The one PR-scope flag: the gitignored local override. Posture flags
  // (change/risk) arrive with the config posture rules, not this projection.
  const flags: Flag[] = item.untracked ? ['untracked'] : [];
  const meta: Record<string, unknown> = { kind: item.kind, scope: item.scope, path: item.path };
  if (item.detail !== undefined) meta.detail = item.detail;
  if (item.entryCount !== undefined) meta.entryCount = item.entryCount;
  if (item.updatedAt !== undefined) meta.updatedAt = item.updatedAt;
  return {
    id: item.id,
    assetType: 'config',
    name: item.name,
    sub: item.kind,
    description: item.detail ?? null,
    flagsJson: JSON.stringify(flags),
    metaJson: JSON.stringify(meta),
    trust: null,
    toolsJson: null,
    effectiveTrust: null,
  };
}

function truncateInline(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function toProjectSummary(
  row: ProjectRow,
  accessCounts: AccessCounts,
  findingsCount: number,
): ProjectSummary {
  const attrs = safeJson<ProjectAttrs>(row.attributes, {});
  return {
    id: row.id,
    name: row.name ?? '',
    repo: row.url ?? '',
    visibility: attrs.visibility ?? 'private',
    language: attrs.language ?? '',
    policyDefault: attrs.policyDefault ?? 'approved',
    updatedAt: new Date(row.lastSeen).toISOString(),
    accessCounts,
    findingsCount,
  };
}

function toFileSummary(file: ProjectFileRow): FileSummary {
  return {
    path: file.path,
    name: file.name,
    origin: file.origin,
    access: file.effectiveAccess,
    isCustom: file.overrideAccess !== null && file.overrideAccess !== file.defaultAccess,
    findings: file.findingsCount,
    blockedAt: file.blockedAtMs !== null ? new Date(file.blockedAtMs).toISOString() : null,
    note: file.note,
  };
}

function accessCountsFromFiles(files: ProjectFileRow[]): AccessCounts {
  const counts: AccessCounts = { open: 0, approved: 0, blocked: 0, total: 0 };
  for (const f of files) {
    counts.total++;
    counts[f.effectiveAccess]++;
  }
  return counts;
}

/**
 * Inventory read views over the tenant-free local store — the read side of the
 * Inventory page. Reads inventory_asset / harness_asset / project_file (+ their
 * overrides) and the shared inventory (harnesses) / source_project (projects)
 * tables, and shapes the finished @akasecurity/schema responses (the local store IS
 * the inventory service). The
 * per-project extras + harness↔project/session linkage ride in the shared tables'
 * `attributes` JSON (those tables stay identical to their base-row contracts).
 * Writes (file access / MCP trust / connect / rescan) surface errors to the caller.
 */
export class SqliteInventoryAssetsRepository implements InventoryReadPort {
  constructor(private readonly db: DatabaseSync) {}

  // Projected config rows (skills/hooks) cached by the config_scan id that produced
  // them — see liveConfigAssetRows. Instance-scoped; safe because a new scan mints a
  // new id and invalidates it.
  private configRowsCache: { scanId: string; rows: AssetRow[] } | undefined;

  // ─── stats ─────────────────────────────────────────────────────────────────

  getInventoryStats(): Promise<InventoryStats> {
    const typeCounts = countBy(
      this.db,
      'SELECT asset_type AS k, count(*) AS n FROM inventory_asset GROUP BY asset_type',
    );
    const byType: InventoryStats['byType'] = {
      project: 0,
      skill: typeCounts.get('skill') ?? 0,
      mcp: typeCounts.get('mcp') ?? 0,
      hook: typeCounts.get('hook') ?? 0,
      config: typeCounts.get('config') ?? 0,
    };
    byType.project = countScalar(
      this.db,
      `SELECT count(*) AS n FROM source_project WHERE ${WORKTREE_CHECKOUT_FILTER}`,
    );

    const mcpTrustCounts = countBy(
      this.db,
      `SELECT coalesce(o.trust, a.trust) AS k, count(*) AS n
         FROM inventory_asset a
         LEFT JOIN mcp_trust_override o ON o.asset_id = a.id
         WHERE a.asset_type = 'mcp' AND coalesce(o.trust, a.trust) IS NOT NULL
         GROUP BY coalesce(o.trust, a.trust)`,
    );
    const mcpTrust: InventoryStats['mcpTrust'] = {
      'known-good': mcpTrustCounts.get('known-good') ?? 0,
      risky: mcpTrustCounts.get('risky') ?? 0,
      unapproved: mcpTrustCounts.get('unapproved') ?? 0,
    };

    // Live harnesses only — hide a tool not seen within the recency window (sample
    // harnesses exempt; see HARNESS_LIVENESS_WINDOW_MS).
    const harnesses = countScalar(
      this.db,
      `SELECT count(*) AS n FROM inventory
           WHERE object_type = 'harness'
             AND (last_seen >= :liveSince OR json_extract(attributes, '$.provenance') = 'sample')`,
      { liveSince: Date.now() - HARNESS_LIVENESS_WINDOW_MS },
    );

    // Attention: assets with ≥1 flag + projects with ≥1 finding.
    const flaggedAssets = countScalar(
      this.db,
      "SELECT count(*) AS n FROM inventory_asset WHERE flags_json <> '[]'",
    );
    const flaggedProjects = countScalar(
      this.db,
      `SELECT count(DISTINCT project_id) AS n FROM project_file WHERE findings_count > 0`,
    );

    // Fold in the real scanned skills/hooks/MCP servers (meta table) — byType
    // counts, their flagged (posture-attention) rows, and the projected MCP
    // rows' effective trust into the same rollup the SQL filled from
    // inventory_asset.
    const configRows = this.configAssetRows();
    for (const r of configRows) {
      byType[r.assetType] += 1;
      if (r.assetType === 'mcp' && r.effectiveTrust) mcpTrust[r.effectiveTrust] += 1;
    }
    const flaggedConfig = configRows.filter((r) => r.flagsJson !== '[]').length;

    return Promise.resolve({
      attention: flaggedAssets + flaggedProjects + flaggedConfig,
      byType,
      harnesses,
      mcpTrust,
    });
  }

  // ─── harnesses ───────────────────────────────────────────────────────────────

  listHarnesses(q?: string): Promise<ListHarnessesResponse> {
    const harnessRows = this.fetchHarnessRows();
    if (harnessRows.length === 0) return Promise.resolve({ items: [] });

    // Group inventory rows by resolved HarnessId (many rows → one card).
    const byHarnessId = new Map<HarnessId, HarnessRow[]>();
    for (const row of harnessRows) {
      const id = resolveHarnessId(safeJson<HarnessAttrs>(row.attributes, {}), row);
      if (!id) continue;
      const group = byHarnessId.get(id);
      if (group) group.push(row);
      else byHarnessId.set(id, [row]);
    }

    // One grouped fetch of every harness's assets, one fetch of every referenced
    // project, and one aggregate pass over their files — instead of a query per
    // harness row and 3 per project. A project shared by several harnesses is
    // aggregated exactly once.
    const assetsByInvId = this.assetsByHarness(
      harnessRows.map((r) => r.id),
      q,
    );
    const allProjectIds = [
      ...new Set(
        harnessRows.flatMap((r) => safeJson<HarnessAttrs>(r.attributes, {}).projectIds ?? []),
      ),
    ];
    const projectsById = this.fetchProjectsByIds(allProjectIds);
    const aggregates = this.projectAggregates(allProjectIds);

    // Real scanned skills/hooks aren't linked via harness_asset — attribute them
    // to the real Claude Code harness card that ran the scan. Reuse the harness rows
    // already fetched above (via isLiveRealClaudeCode) so configAssetRows doesn't
    // query them a second time.
    const configAssets = this.configAssetRows(q, isLiveRealClaudeCode(harnessRows));

    const items: HarnessSummary[] = [];
    for (const [harnessId, rows] of byHarnessId) {
      const harnessAssets = rows.flatMap((r) => assetsByInvId.get(r.id) ?? []);
      const isRealHarness = rows.some(
        (r) => safeJson<HarnessAttrs>(r.attributes, {}).provenance !== 'sample',
      );
      // Skills/hooks are Claude Code config concepts — attach them ONLY to the real
      // Claude Code card, never a future (real) Cursor/Codex harness, and on exactly
      // one card so assetCount here agrees with getInventoryStats' single count.
      const attachConfig = isRealHarness && harnessId === 'claudecode' && configAssets.length > 0;
      const assets = attachConfig
        ? [...harnessAssets, ...configAssets].sort((a, b) => a.name.localeCompare(b.name))
        : harnessAssets;
      if (q && assets.length === 0) continue;

      const firstRow = rows[0];
      if (!firstRow) continue;
      const firstAttrs = safeJson<HarnessAttrs>(firstRow.attributes, {});

      const projectIds = [
        ...new Set(rows.flatMap((r) => safeJson<HarnessAttrs>(r.attributes, {}).projectIds ?? [])),
      ];
      const projects = projectIds
        .map((pid) => projectsById.get(pid))
        .filter((p): p is ProjectRow => p !== undefined)
        .map((p) => {
          const agg = aggregates.get(p.id) ?? EMPTY_PROJECT_AGG;
          return toProjectSummary(p, agg.accessCounts, agg.findingsCount);
        });

      const sessions = rows.reduce(
        (sum, r) => sum + (safeJson<HarnessAttrs>(r.attributes, {}).sessions ?? 0),
        0,
      );
      const flagCount = assets.reduce(
        (sum, a) => sum + safeJson(a.flagsJson, [] as Flag[]).length,
        0,
      );

      const grouped = new Map<string, AssetSummary[]>();
      for (const a of assets) {
        const arr = grouped.get(a.assetType);
        if (arr) arr.push(toAssetSummary(a));
        else grouped.set(a.assetType, [toAssetSummary(a)]);
      }
      const categories = CATEGORY_ORDER.filter((t) => grouped.has(t)).map((type) => ({
        type,
        assets: grouped.get(type) ?? [],
      }));

      items.push({
        id: harnessId,
        // An authored label attr (sample rows) wins; real scanned rows fall to
        // the display map for their resolved id — never the raw row title.
        label: firstAttrs.label ?? HARNESS_LABELS[harnessId],
        kind: firstAttrs.kind ?? firstAttrs.provider ?? harnessId,
        version: firstAttrs.harness_version ?? firstRow.harnessVersion ?? '',
        sessions,
        assetCount: assets.length,
        flagCount,
        projects,
        categories,
      });
    }

    return Promise.resolve({ items });
  }

  // ─── assets ───────────────────────────────────────────────────────────────

  listAssets(query: ListAssetsQuery): Promise<ListAssetsResponse> {
    const assets = this.fetchAssets(query.type, query.q);
    if (assets.length === 0) return Promise.resolve({ groups: [] });

    const grouped = new Map<string, AssetRow[]>();
    for (const a of assets) {
      const arr = grouped.get(a.assetType);
      if (arr) arr.push(a);
      else grouped.set(a.assetType, [a]);
    }

    const groups: AssetGroup[] = [...grouped.entries()].map(([type, rows]) => {
      const flagMap = new Map<string, number>();
      for (const r of rows) {
        for (const f of safeJson(r.flagsJson, [] as Flag[])) {
          flagMap.set(f, (flagMap.get(f) ?? 0) + 1);
        }
      }
      const group: AssetGroup = {
        type: type as AssetGroup['type'],
        total: rows.length,
        flagRollup: Object.fromEntries(flagMap),
        items: rows.map(toAssetSummary),
      };
      if (type === 'mcp') {
        const trustMap = new Map<TrustLevel, number>();
        for (const r of rows) {
          if (r.effectiveTrust)
            trustMap.set(r.effectiveTrust, (trustMap.get(r.effectiveTrust) ?? 0) + 1);
        }
        group.trustRollup = Object.fromEntries(trustMap);
      }
      return group;
    });

    groups.sort(
      (a, b) =>
        CATEGORY_ORDER.indexOf(a.type as AssetRow['assetType']) -
        CATEGORY_ORDER.indexOf(b.type as AssetRow['assetType']),
    );
    return Promise.resolve({ groups });
  }

  getAsset(assetId: string): Promise<AssetDetail | null> {
    const row = this.fetchAssetById(assetId);
    return Promise.resolve(row ? buildAssetDetail(row) : null);
  }

  // ─── projects ───────────────────────────────────────────────────────────────

  listProjects(q?: string): Promise<ListProjectsResponse> {
    const rows = this.fetchProjects(q);
    // One aggregate pass over every project's files (shared with listHarnesses),
    // not 2 queries per project.
    const aggregates = this.projectAggregates(rows.map((r) => r.id));
    const items = rows.map((r) => {
      const agg = aggregates.get(r.id) ?? EMPTY_PROJECT_AGG;
      return toProjectSummary(r, agg.accessCounts, agg.findingsCount);
    });
    return Promise.resolve({ items });
  }

  getProjectTree(
    projectId: string,
    query: GetProjectTreeQuery,
  ): Promise<ProjectTreeResponse | null> {
    const project = this.fetchProjectById(projectId);
    if (!project) return Promise.resolve(null);

    const attrs = safeJson<ProjectAttrs>(project.attributes, {});
    const projectCtx: ProjectTreeResponse['project'] = {
      id: project.id,
      repo: project.url ?? '',
      visibility: attrs.visibility ?? 'private',
    };
    const prefix = query.path ?? '';

    if (query.filter === 'blocked') {
      const files = this.fetchProjectFilesBlocked(projectId);
      files.sort((a, b) => (b.blockedAtMs ?? 0) - (a.blockedAtMs ?? 0));
      return Promise.resolve({
        project: projectCtx,
        path: prefix,
        files: files.map(toFileSummary),
      });
    }

    if (query.q !== undefined && query.q !== '') {
      const files = this.fetchProjectFilesSearch(projectId, query.q);
      return Promise.resolve({
        project: projectCtx,
        path: prefix,
        files: files.map(toFileSummary),
      });
    }

    // Browse mode: files at this level + folder summaries with descendant rollup.
    const allUnder = this.fetchProjectFilesUnder(projectId, prefix);
    const prefixSlash = prefix === '' ? '' : `${prefix}/`;
    const filesAtLevel: ProjectFileRow[] = [];
    const folderFiles = new Map<string, ProjectFileRow[]>();
    for (const file of allUnder) {
      const remaining = prefixSlash.length > 0 ? file.path.slice(prefixSlash.length) : file.path;
      const slashIdx = remaining.indexOf('/');
      if (slashIdx === -1) {
        filesAtLevel.push(file);
      } else {
        const segment = remaining.slice(0, slashIdx);
        const arr = folderFiles.get(segment) ?? [];
        arr.push(file);
        folderFiles.set(segment, arr);
      }
    }
    const folders: FolderSummary[] = [...folderFiles.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, descendants]) => ({
        name,
        path: prefixSlash.length > 0 ? `${prefix}/${name}` : name,
        accessCounts: accessCountsFromFiles(descendants),
      }));

    return Promise.resolve({
      project: projectCtx,
      path: prefix,
      folders,
      files: filesAtLevel.map(toFileSummary),
    });
  }

  getProjectFile(projectId: string, path: string): Promise<FileDetail | null> {
    const project = this.fetchProjectById(projectId);
    if (!project) return Promise.resolve(null);
    const file = this.fetchProjectFile(projectId, path);
    if (!file) return Promise.resolve(null);

    const attrs = safeJson<ProjectAttrs>(project.attributes, {});
    return Promise.resolve({
      ...toFileSummary(file),
      project: {
        repo: project.url ?? '',
        visibility: attrs.visibility ?? 'private',
        language: attrs.language ?? '',
        policyDefault: attrs.policyDefault ?? 'approved',
        updatedAt: new Date(project.lastSeen).toISOString(),
      },
      // No path-scoped finding linkage in the local model — [].
      findingsRefs: [],
    });
  }

  // ─── writes ───────────────────────────────────────────────────────────────

  /** Set or clear-on-default the per-file LLM access override. Returns whether the file exists. */
  setFileAccess(projectId: string, path: string, access: AccessLevel): boolean {
    const file = this.fetchProjectFile(projectId, path);
    if (!file) return false;
    if (access === file.defaultAccess) {
      this.db
        .prepare('DELETE FROM file_access_override WHERE project_id = ? AND path = ?')
        .run(projectId, path);
    } else {
      this.db
        .prepare(
          `INSERT INTO file_access_override (id, project_id, path, access, created_at, updated_at)
           VALUES (:id, :projectId, :path, :access, :now, :now)
           ON CONFLICT (project_id, path) DO UPDATE SET access = excluded.access, updated_at = excluded.updated_at`,
        )
        .run({ id: randomUUID(), projectId, path, access, now: Date.now() });
    }
    return true;
  }

  /**
   * Set or clear-on-default the MCP trust override. Returns 'ok' | 'not_found' | 'not_mcp'.
   * Works for both id namespaces: sample inventory_asset rows AND projected
   * real scanned servers (fetchAssetById falls back to the projection; the
   * override table's asset_id is deliberately FK-free — see migration 0005).
   */
  setMcpTrust(assetId: string, trust: TrustLevel): 'ok' | 'not_found' | 'not_mcp' {
    const asset = this.fetchAssetById(assetId);
    if (!asset) return 'not_found';
    if (asset.assetType !== 'mcp') return 'not_mcp';
    if (trust === asset.trust) {
      this.db.prepare('DELETE FROM mcp_trust_override WHERE asset_id = ?').run(assetId);
    } else {
      this.db
        .prepare(
          `INSERT INTO mcp_trust_override (id, asset_id, trust, created_at, updated_at)
           VALUES (:id, :assetId, :trust, :now, :now)
           ON CONFLICT (asset_id) DO UPDATE SET trust = excluded.trust, updated_at = excluded.updated_at`,
        )
        .run({ id: randomUUID(), assetId, trust, now: Date.now() });
    }
    // The projected rows memo bakes in effective trust, and its key (latest
    // scan id) doesn't move on a trust write — drop it or the page would serve
    // the old badge until the next scan.
    this.configRowsCache = undefined;
    return 'ok';
  }

  // ─── raw fetchers ────────────────────────────────────────────────────────────

  private fetchHarnessRows(): HarnessRow[] {
    return allRows<HarnessRow>(
      this.db.prepare(
        `SELECT id, title, attributes, harness_version AS harnessVersion
         FROM inventory
         WHERE object_type = 'harness'
           AND (last_seen >= :liveSince OR json_extract(attributes, '$.provenance') = 'sample')`,
      ),
      { liveSince: Date.now() - HARNESS_LIVENESS_WINDOW_MS },
    );
  }

  // Every harness's assets in ONE grouped query, keyed by harness inventory id —
  // replaces the per-harness-row query the listHarnesses loop used to make.
  private assetsByHarness(harnessInvIds: string[], q?: string): Map<string, AssetRow[]> {
    const map = new Map<string, AssetRow[]>();
    if (harnessInvIds.length === 0) return map;
    const params: unknown[] = [...harnessInvIds];
    let where = `ha.harness_id IN (${placeholders(harnessInvIds.length)})`;
    if (q) {
      const pat = containsPattern(q);
      where += ` AND ${likeAny(['a.name', 'a.sub'])}`;
      params.push(pat, pat);
    }
    const rows = allRows<Record<string, unknown>>(
      this.db.prepare(
        `SELECT ha.harness_id AS harnessInvId, a.id, a.asset_type AS assetType, a.name, a.sub,
                a.description, a.flags_json AS flagsJson, a.meta_json AS metaJson, a.trust,
                a.tools_json AS toolsJson, coalesce(o.trust, a.trust) AS effectiveTrust
         FROM harness_asset ha
         JOIN inventory_asset a ON a.id = ha.asset_id
         LEFT JOIN mcp_trust_override o ON o.asset_id = a.id
         WHERE ${where}
         ORDER BY a.name ASC`,
      ),
      params as SQLInputValue[],
    );
    for (const raw of rows) {
      const harnessInvId = raw.harnessInvId as string;
      const [asset] = this.mapAssetRows([raw]);
      if (!asset) continue;
      const arr = map.get(harnessInvId);
      if (arr) arr.push(asset);
      else map.set(harnessInvId, [asset]);
    }
    return map;
  }

  private fetchAssets(types: string[] | undefined, q: string | undefined): AssetRow[] {
    const conditions: string[] = [];
    const params: unknown[] = [];
    if (types && types.length > 0) {
      conditions.push(`a.asset_type IN (${placeholders(types.length)})`);
      params.push(...types);
    }
    if (q) {
      const pat = containsPattern(q);
      conditions.push(likeAny(['a.name', 'a.sub']));
      params.push(pat, pat);
    }
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const sampleRows = this.mapAssetRows(
      allRows<Record<string, unknown>>(
        this.db.prepare(
          `SELECT a.id, a.asset_type AS assetType, a.name, a.sub, a.description,
                  a.flags_json AS flagsJson, a.meta_json AS metaJson, a.trust,
                  a.tools_json AS toolsJson, coalesce(o.trust, a.trust) AS effectiveTrust
           FROM inventory_asset a
           LEFT JOIN mcp_trust_override o ON o.asset_id = a.id
           ${where}
           ORDER BY a.name ASC`,
        ),
        params as SQLInputValue[],
      ),
    );
    // Merge in the real scanned skills/hooks (meta table), honouring the same
    // type/query filters the SQL applied to inventory_asset.
    const configRows = this.configAssetRows(q).filter(
      (r) => !types || types.length === 0 || types.includes(r.assetType),
    );
    // Re-sort by name only when config rows are actually merged in — keeps the
    // sample-only path byte-identical to the SQL ORDER BY (no collation drift).
    return configRows.length > 0
      ? [...sampleRows, ...configRows].sort((a, b) => a.name.localeCompare(b.name))
      : sampleRows;
  }

  private fetchAssetById(assetId: string): AssetRow | null {
    const rows = this.mapAssetRows(
      allRows<Record<string, unknown>>(
        this.db.prepare(
          `SELECT a.id, a.asset_type AS assetType, a.name, a.sub, a.description,
                  a.flags_json AS flagsJson, a.meta_json AS metaJson, a.trust,
                  a.tools_json AS toolsJson, coalesce(o.trust, a.trust) AS effectiveTrust
           FROM inventory_asset a
           LEFT JOIN mcp_trust_override o ON o.asset_id = a.id
           WHERE a.id = ?`,
        ),
        [assetId],
      ),
    );
    // Fall back to the projected real skills/hooks (meta table) when the id isn't
    // an inventory_asset row.
    return rows[0] ?? this.configAssetRows().find((r) => r.id === assetId) ?? null;
  }

  private mapAssetRows(rows: unknown[]): AssetRow[] {
    return (rows as Record<string, unknown>[]).map((r) => ({
      id: r.id as string,
      assetType: r.assetType as AssetRow['assetType'],
      name: r.name as string,
      sub: (r.sub as string | null) ?? null,
      description: (r.description as string | null) ?? null,
      flagsJson: (r.flagsJson as string | null) ?? '[]',
      metaJson: (r.metaJson as string | null) ?? '{}',
      trust: (r.trust as TrustLevel | null) ?? null,
      toolsJson: (r.toolsJson as string | null) ?? null,
      effectiveTrust: (r.effectiveTrust as TrustLevel | null) ?? null,
    }));
  }

  // Real scanned skills/hooks, projected from the config-inventory report into the
  // AssetRow shape. Empty unless a config_scan has run AND a live real Claude Code
  // harness exists to own them — the SAME precondition listHarnesses attaches on, so
  // getInventoryStats / listAssets / listHarnesses stay in lockstep (all surface them
  // or none do). Optionally filtered by the free-text query (name/sub contains),
  // mirroring the SQL LIKE on inventory_asset.
  // `liveClaudeCode` lets listHarnesses pass the result it already computed from its
  // fetched harness rows, so this doesn't fetch them a second time; other callers omit
  // it and we compute it once here.
  private configAssetRows(q?: string, liveClaudeCode?: boolean): AssetRow[] {
    const rows = this.liveConfigAssetRows(liveClaudeCode);
    if (!q) return rows;
    const needle = q.toLowerCase();
    return rows.filter(
      (r) => r.name.toLowerCase().includes(needle) || (r.sub ?? '').toLowerCase().includes(needle),
    );
  }

  // The projected config rows, memoized by the latest config_scan id. report()
  // (latest-scan lookup + inventory + findings queries + bag parsing + topic rollup)
  // used to run on every call — one page load hits this 3× (plus once per getAsset).
  // A new scan, written out-of-process by the plugin, changes the id and invalidates
  // the memo, so it never serves stale rows despite the process-lifetime repo singleton.
  private liveConfigAssetRows(liveClaudeCode?: boolean): AssetRow[] {
    // Config skills/hooks are the Claude Code harness's config — surface them only
    // while that harness is live (checked fresh each call, since harness liveness is
    // time-based) so the count and the harness attach can never disagree.
    if (!(liveClaudeCode ?? isLiveRealClaudeCode(this.fetchHarnessRows()))) return [];
    const scanId = this.latestConfigScanId();
    if (scanId === null) return [];
    if (this.configRowsCache?.scanId === scanId) return this.configRowsCache.rows;
    const report = new SqliteConfigInventoryRepository(this.db).report();
    const rows = [
      ...report.skills.map(skillAssetRow),
      ...report.hooks.map(hookAssetRow),
      ...report.mcpServers.map(mcpAssetRow),
      ...report.configFiles.map(configFileAssetRow),
    ].sort((a, b) => a.name.localeCompare(b.name));
    this.configRowsCache = { scanId, rows };
    return rows;
  }

  private latestConfigScanId(): string | null {
    return latestConfigScan(this.db)?.id ?? null;
  }

  private fetchProjects(q: string | undefined): ProjectRow[] {
    let sql = `SELECT id, url, name, attributes, last_seen AS lastSeen FROM source_project
               WHERE ${WORKTREE_CHECKOUT_FILTER}`;
    const params: unknown[] = [];
    if (q) {
      const pat = containsPattern(q);
      sql += ` AND ${likeAny(['name', 'url'])}`;
      params.push(pat, pat);
    }
    sql += ' ORDER BY name ASC';
    return allRows<ProjectRow>(this.db.prepare(sql), params as SQLInputValue[]);
  }

  private fetchProjectById(projectId: string): ProjectRow | null {
    return (
      getRow<ProjectRow>(
        this.db.prepare(
          'SELECT id, url, name, attributes, last_seen AS lastSeen FROM source_project WHERE id = ?',
        ),
        [projectId],
      ) ?? null
    );
  }

  // The referenced projects in ONE `id IN (…)` fetch, keyed by id.
  private fetchProjectsByIds(projectIds: string[]): Map<string, ProjectRow> {
    const map = new Map<string, ProjectRow>();
    if (projectIds.length === 0) return map;
    const rows = allRows<ProjectRow>(
      this.db.prepare(
        `SELECT id, url, name, attributes, last_seen AS lastSeen
         FROM source_project WHERE id IN (${placeholders(projectIds.length)})`,
      ),
      projectIds,
    );
    for (const r of rows) map.set(r.id, r);
    return map;
  }

  // Effective-access counts AND findings per project in ONE grouped pass over
  // project_file — replaces the two per-project queries listHarnesses/listProjects
  // used to make (findings summed across the per-(project, access) groups gives
  // the project total). A project with no files is simply absent from the map.
  private projectAggregates(projectIds: string[]): Map<string, ProjectAggregate> {
    const map = new Map<string, ProjectAggregate>();
    if (projectIds.length === 0) return map;
    const rows = allRows<{
      projectId: string;
      eff: AccessLevel;
      n: number;
      findings: number;
    }>(
      this.db.prepare(
        `SELECT f.project_id AS projectId,
                coalesce(o.access, f.default_access) AS eff,
                count(*) AS n,
                coalesce(sum(f.findings_count), 0) AS findings
         FROM project_file f
         LEFT JOIN file_access_override o ON o.project_id = f.project_id AND o.path = f.path
         WHERE f.project_id IN (${placeholders(projectIds.length)})
         GROUP BY f.project_id, eff`,
      ),
      projectIds,
    );
    for (const r of rows) {
      let agg = map.get(r.projectId);
      if (!agg) {
        agg = { accessCounts: { open: 0, approved: 0, blocked: 0, total: 0 }, findingsCount: 0 };
        map.set(r.projectId, agg);
      }
      agg.accessCounts.total += r.n;
      agg.accessCounts[r.eff] += r.n;
      agg.findingsCount += r.findings;
    }
    return map;
  }

  private fileSelect(where: string): string {
    return `SELECT f.path, f.name, f.origin, f.default_access AS defaultAccess,
                   f.findings_count AS findingsCount, f.blocked_at AS blockedAtMs, f.note,
                   coalesce(o.access, f.default_access) AS effectiveAccess,
                   o.access AS overrideAccess
            FROM project_file f
            LEFT JOIN file_access_override o ON o.project_id = f.project_id AND o.path = f.path
            WHERE ${where}`;
  }

  private mapFileRows(rows: unknown[]): ProjectFileRow[] {
    return (rows as Record<string, unknown>[]).map((r) => ({
      path: r.path as string,
      name: r.name as string,
      origin: r.origin as Origin,
      defaultAccess: r.defaultAccess as AccessLevel,
      findingsCount: (r.findingsCount as number | null) ?? 0,
      blockedAtMs: (r.blockedAtMs as number | null) ?? null,
      note: (r.note as string | null) ?? null,
      effectiveAccess: r.effectiveAccess as AccessLevel,
      overrideAccess: (r.overrideAccess as AccessLevel | null) ?? null,
    }));
  }

  private fetchProjectFilesUnder(projectId: string, prefix: string): ProjectFileRow[] {
    if (prefix === '') {
      return this.mapFileRows(
        allRows<Record<string, unknown>>(
          this.db.prepare(this.fileSelect('f.project_id = ? ORDER BY f.path ASC')),
          [projectId],
        ),
      );
    }
    return this.mapFileRows(
      allRows<Record<string, unknown>>(
        this.db.prepare(
          this.fileSelect("f.project_id = ? AND f.path LIKE ? ESCAPE '\\' ORDER BY f.path ASC"),
        ),
        [projectId, `${escapeLikePattern(prefix)}/%`],
      ),
    );
  }

  private fetchProjectFilesSearch(projectId: string, q: string): ProjectFileRow[] {
    const pat = containsPattern(q);
    return this.mapFileRows(
      allRows<Record<string, unknown>>(
        this.db.prepare(
          this.fileSelect(
            "f.project_id = ? AND (f.path LIKE ? ESCAPE '\\' OR f.name LIKE ? ESCAPE '\\') ORDER BY f.path ASC",
          ),
        ),
        [projectId, pat, pat],
      ),
    );
  }

  private fetchProjectFilesBlocked(projectId: string): ProjectFileRow[] {
    return this.mapFileRows(
      allRows<Record<string, unknown>>(
        this.db.prepare(
          this.fileSelect(
            "f.project_id = ? AND coalesce(o.access, f.default_access) = 'blocked' AND f.blocked_at IS NOT NULL",
          ),
        ),
        [projectId],
      ),
    );
  }

  private fetchProjectFile(projectId: string, path: string): ProjectFileRow | null {
    const rows = this.mapFileRows(
      allRows<Record<string, unknown>>(
        this.db.prepare(this.fileSelect('f.project_id = ? AND f.path = ?')),
        [projectId, path],
      ),
    );
    return rows[0] ?? null;
  }
}
