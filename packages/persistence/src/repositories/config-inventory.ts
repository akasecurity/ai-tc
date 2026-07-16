import type { DatabaseSync } from 'node:sqlite';

import type {
  ConfigFileInventoryItem,
  ConfigInventoryReport,
  ConfigTopicStatus,
  HookInventoryItem,
  McpInventoryItem,
  SkillInventoryItem,
  TrustLevel,
} from '@akasecurity/schema';

import { parseJsonObject } from '../internal/json.ts';
import { allRows } from '../internal/rows.ts';
import { latestConfigScan } from './config-scan.ts';

/**
 * Read side of the Skills & Hooks config inventory. Everything here is DERIVED
 * at read time — statuses come from the latest scan's open posture findings and
 * (later) the skills catalog; nothing is stored on the inventory rows.
 *
 * Liveness: an uninstalled artifact simply stops getting `last_seen` bumps, so
 * "live" = seen by the latest `config_scan` (last_seen >= its started_at). No
 * tombstones, no generation counters — ghosts don't render, history survives.
 *
 * NB this liveness is SCAN-authoritative and independent of harness liveness. The
 * web-ui Inventory projection additionally gates config assets on a live Claude
 * Code harness (isLiveRealClaudeCode in inventory-assets.ts), so a
 * stale-harness store shows nothing there while this report would still return the
 * last scan's rows. Harmless today (this report has no OSS render consumer), but a
 * future Skills & Hooks page must reconcile the two before relying on report().
 */
export class SqliteConfigInventoryRepository {
  constructor(private readonly db: DatabaseSync) {}

  report(): ConfigInventoryReport {
    const scan = latestConfigScan(this.db);
    if (!scan) {
      return {
        scannedAt: null,
        skills: [],
        hooks: [],
        mcpServers: [],
        configFiles: [],
        topics: [],
      };
    }

    const rows = allRows<InventoryReadRow>(
      this.db.prepare(
        `SELECT id, object_type AS objectType, title, location, attributes FROM inventory
          WHERE object_type IN ('skill', 'hook', 'mcp_server', 'config_file') AND last_seen >= :startedAt
          ORDER BY object_type, title`,
      ),
      { startedAt: scan.started_at },
    );

    // The latest scan's posture findings, joined to their definition for the
    // rule id + human name. Empty when no posture rules have recorded findings.
    const findings = allRows<FindingReadRow>(
      this.db.prepare(
        `SELECT f.masked_match AS maskedMatch, d.rule_id AS ruleId, d.name AS name
           FROM inspection_findings f
           JOIN inspection_definitions d ON d.id = f.inspection_definition_id
          WHERE f.audit_event_id = :scanId`,
      ),
      { scanId: scan.id },
    );

    const skills: SkillInventoryItem[] = [];
    const hooks: HookInventoryItem[] = [];
    const mcpServers: McpInventoryItem[] = [];
    const configFiles: ConfigFileInventoryItem[] = [];
    // The user's trust decisions, applied at read time — they live in a side
    // table precisely so the scanner's Type-1 bag replace can't erase them.
    const overrides = this.trustOverrides();
    for (const row of rows) {
      const bag = parseBag(row.attributes);
      if (!bag) continue; // corrupt bag → skip the row, keep the report
      if (row.objectType === 'skill') skills.push(toSkillItem(row, bag));
      else if (row.objectType === 'hook') hooks.push(toHookItem(row, bag, findings));
      else if (row.objectType === 'mcp_server') mcpServers.push(toMcpItem(row, bag, overrides));
      else configFiles.push(toConfigFileItem(row, bag));
    }

    return {
      scannedAt: new Date(scan.started_at).toISOString(),
      skills,
      hooks,
      mcpServers,
      configFiles,
      topics: buildTopics(skills, hooks, mcpServers, configFiles, scan.attributes),
    };
  }

  // asset_id → trust for every stored override. The id space is opaque on
  // purpose — sample inventory_asset ids AND the content-addressed meta
  // inventory ids real scanned MCP servers use (see the mcp_trust_override
  // schema note); an override whose asset is gone simply never matches. A row
  // with an out-of-vocabulary trust value is ignored rather than guessed at.
  private trustOverrides(): Map<string, TrustLevel> {
    const rows = allRows<{ assetId: string; trust: string }>(
      this.db.prepare('SELECT asset_id AS assetId, trust FROM mcp_trust_override'),
    );
    const map = new Map<string, TrustLevel>();
    for (const row of rows) {
      if (row.trust === 'known-good' || row.trust === 'risky' || row.trust === 'unapproved') {
        map.set(row.assetId, row.trust);
      }
    }
    return map;
  }
}

function toSkillItem(row: InventoryReadRow, bag: Record<string, unknown>): SkillInventoryItem {
  const item: SkillInventoryItem = {
    id: row.id,
    name: row.title ?? '(unnamed)',
    source: str(bag.source) ?? 'unknown',
    scope: str(bag.scope) ?? 'unknown',
    // No catalog exists to compare the installed version against, so status
    // stays 'unknown' — never a guessed "up to date".
    status: 'unknown',
  };
  const description = str(bag.description);
  if (description !== undefined) item.description = description;
  const version = str(bag.version);
  if (version !== undefined) item.installedVersion = version;
  const updatedAt = str(bag.updated_at);
  if (updatedAt !== undefined) item.updatedAt = updatedAt;
  return item;
}

// Findings correlate to a hook by command (the finding's masked_match carries
// the offending command). If two hooks share a command, the warning applies to
// both — arguably correct: the risk is identical wherever that command runs.
function toHookItem(
  row: InventoryReadRow,
  bag: Record<string, unknown>,
  findings: FindingReadRow[],
): HookInventoryItem {
  const command = str(bag.command) ?? '';
  const matched = findings.filter((f) => f.maskedMatch === command);
  const item: HookInventoryItem = {
    id: row.id,
    event: str(bag.event) ?? 'unknown',
    command,
    scope: str(bag.scope) ?? 'unknown',
    // Highest-severity finding wins the badge (see HookInventoryItem): an
    // exfiltration-capable hook must never render as plain 'active'.
    status: matched.some((f) => f.ruleId === 'hook-external-egress')
      ? 'egress'
      : matched.some((f) => f.ruleId === 'hook-conflict')
        ? 'conflict'
        : matched.some((f) => f.ruleId === 'hook-unknown')
          ? 'unknown'
          : 'active',
    warnings: matched.map((f) => f.name),
  };
  const matcher = str(bag.matcher);
  if (matcher !== undefined) item.matcher = matcher;
  const pluginName = str(bag.plugin_name);
  if (pluginName !== undefined) item.pluginName = pluginName;
  return item;
}

// An MCP server's effective trust: the user's override when set, else
// 'unapproved' — review-required. A scan can't prove a server safe (there is
// no verification registry yet), so the default is the review queue, never a
// guessed 'known-good'. Derived here so every renderer agrees; never stored.
function toMcpItem(
  row: InventoryReadRow,
  bag: Record<string, unknown>,
  overrides: Map<string, TrustLevel>,
): McpInventoryItem {
  const item: McpInventoryItem = {
    id: row.id,
    name: row.title ?? '(unnamed)',
    scope: str(bag.scope) ?? 'unknown',
    transport: str(bag.transport) ?? 'unknown',
    trust: overrides.get(row.id) ?? 'unapproved',
  };
  const command = str(bag.command);
  if (command !== undefined) item.command = command;
  const url = str(bag.url);
  if (url !== undefined) item.url = url;
  if (Array.isArray(bag.env_keys)) {
    const envKeys = bag.env_keys.filter((k): k is string => typeof k === 'string');
    if (envKeys.length > 0) item.envKeys = envKeys;
  }
  const pluginName = str(bag.plugin_name);
  if (pluginName !== undefined) item.pluginName = pluginName;
  const marketplace = str(bag.marketplace);
  if (marketplace !== undefined) item.marketplace = marketplace;
  const project = str(bag.project);
  if (project !== undefined) item.project = project;
  return item;
}

// A config file's row: kind/detail/mtime straight off the bag. `untracked` is
// DERIVED from the Claude Code convention that the `local` scope file
// (settings.local.json) is the gitignored per-machine override.
function toConfigFileItem(
  row: InventoryReadRow,
  bag: Record<string, unknown>,
): ConfigFileInventoryItem {
  const scope = str(bag.scope) ?? 'unknown';
  const item: ConfigFileInventoryItem = {
    id: row.id,
    name: row.title ?? '(unnamed)',
    path: row.location ?? '',
    scope,
    kind: str(bag.kind) ?? 'Configuration file',
    untracked: scope === 'local',
  };
  const detail = str(bag.detail);
  if (detail !== undefined) item.detail = detail;
  if (typeof bag.entry_count === 'number') item.entryCount = bag.entry_count;
  const updatedAt = str(bag.updated_at);
  if (updatedAt !== undefined) item.updatedAt = updatedAt;
  return item;
}

function buildTopics(
  skills: SkillInventoryItem[],
  hooks: HookInventoryItem[],
  mcpServers: McpInventoryItem[],
  configFiles: ConfigFileInventoryItem[],
  scanAttributes: string | null,
): ConfigTopicStatus[] {
  const topics: ConfigTopicStatus[] = [];

  const updates = skills.filter((s) => s.status === 'update_available').length;
  const skillsTopic: ConfigTopicStatus = { topic: 'skills', count: skills.length };
  if (updates > 0) skillsTopic.attention = `${String(updates)} updates`;
  topics.push(skillsTopic);

  const egress = hooks.filter((h) => h.status === 'egress').length;
  const conflicts = hooks.filter((h) => h.status === 'conflict').length;
  const unknown = hooks.filter((h) => h.status === 'unknown').length;
  const parts: string[] = [];
  if (egress > 0) parts.push(`${String(egress)} egress`);
  if (unknown > 0) parts.push(`${String(unknown)} unknown`);
  if (conflicts > 0) parts.push(`${String(conflicts)} conflict${conflicts > 1 ? 's' : ''}`);
  const hooksTopic: ConfigTopicStatus = { topic: 'hooks', count: hooks.length };
  if (parts.length > 0) hooksTopic.attention = parts.join(' · ');
  topics.push(hooksTopic);

  // MCP topic: with 'unapproved' the review-required default, the attention
  // line IS the review queue.
  const unapproved = mcpServers.filter((s) => s.trust === 'unapproved').length;
  const mcpTopic: ConfigTopicStatus = { topic: 'mcp', count: mcpServers.length };
  if (unapproved > 0) mcpTopic.attention = `${String(unapproved)} unapproved`;
  topics.push(mcpTopic);

  // Config files: pure inventory for now (existence + shape) — the untracked
  // local override is the one attention-worthy convention.
  const untracked = configFiles.filter((f) => f.untracked).length;
  const filesTopic: ConfigTopicStatus = { topic: 'config_files', count: configFiles.length };
  if (untracked > 0) filesTopic.attention = `${String(untracked)} untracked`;
  topics.push(filesTopic);

  // Configuration topic = the scan itself: sources that failed to parse (from
  // the scan event's fail-open bookkeeping).
  const errors = countScanErrors(scanAttributes);
  const configTopic: ConfigTopicStatus = { topic: 'configuration', count: errors };
  if (errors > 0) configTopic.attention = `${String(errors)} sources failed to parse`;
  topics.push(configTopic);

  return topics;
}

function countScanErrors(attributes: string | null): number {
  const errors = parseJsonObject(attributes)?.errors;
  return typeof errors === 'number' ? errors : 0;
}

function parseBag(raw: string): Record<string, unknown> | undefined {
  return parseJsonObject(raw);
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

interface InventoryReadRow {
  id: string;
  objectType: 'skill' | 'hook' | 'mcp_server' | 'config_file';
  title: string | null;
  location: string | null;
  attributes: string;
}

interface FindingReadRow {
  maskedMatch: string;
  ruleId: string;
  name: string;
}
