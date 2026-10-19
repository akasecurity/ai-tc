import type {
  ConfigFileInventoryItem,
  Flag,
  HookInventoryItem,
  McpInventoryItem,
  SkillInventoryItem,
  TrustLevel,
} from '@akasecurity/schema';

// Projection of scanned config-inventory rows (skills, hooks, MCP servers,
// config files) onto the asset row the Inventory views render. Pure: no I/O and
// no `node:sqlite`, so it is also served from the `./sqlite-free` entry.
//
// Statuses are derived here, not stored: a hook's status comes from the posture
// findings passed in, an MCP server's trust from the overrides passed in
// (default `unapproved`, the review-required state).

export interface AssetRow {
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

export interface ConfigInventoryRow {
  id: string;
  objectType: 'skill' | 'hook' | 'mcp_server' | 'config_file';
  title: string | null;
  location: string | null;
}

export interface PostureFindingRow {
  maskedMatch: string;
  ruleId: string;
  name: string;
}

export interface ConfigAssetContext {
  findings?: readonly PostureFindingRow[];
  trustOverrides?: ReadonlyMap<string, TrustLevel>;
}

/**
 * The asset row for one scanned config item. `bag` is the item's attribute bag;
 * `context` supplies the posture findings and trust overrides the status fields
 * are derived from.
 */
export function configAssetRow(
  row: ConfigInventoryRow,
  bag: Record<string, unknown>,
  context: ConfigAssetContext = {},
): AssetRow {
  switch (row.objectType) {
    case 'skill':
      return skillAssetRow(toSkillItem(row, bag));
    case 'hook':
      return hookAssetRow(toHookItem(row, bag, context.findings ?? []));
    case 'mcp_server':
      return mcpAssetRow(toMcpItem(row, bag, context.trustOverrides ?? new Map()));
    case 'config_file':
      return configFileAssetRow(toConfigFileItem(row, bag));
  }
}

export function skillAssetRow(item: SkillInventoryItem): AssetRow {
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

export function hookAssetRow(item: HookInventoryItem): AssetRow {
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

export function mcpAssetRow(item: McpInventoryItem): AssetRow {
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

export function configFileAssetRow(item: ConfigFileInventoryItem): AssetRow {
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

export function toSkillItem(
  row: ConfigInventoryRow,
  bag: Record<string, unknown>,
): SkillInventoryItem {
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
export function toHookItem(
  row: ConfigInventoryRow,
  bag: Record<string, unknown>,
  findings: readonly PostureFindingRow[],
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
export function toMcpItem(
  row: ConfigInventoryRow,
  bag: Record<string, unknown>,
  overrides: ReadonlyMap<string, TrustLevel>,
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
export function toConfigFileItem(
  row: ConfigInventoryRow,
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

function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}
