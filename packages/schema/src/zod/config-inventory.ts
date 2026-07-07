// Configuration-inventory contracts — the Skills & Hooks surface of the [Meta]
// Data Model (design: config-inventory-skills-hooks.design.md). Skills and hooks
// are Inventory objects (`object_type` = 'skill' | 'hook', meta.ts); each scan is
// one `config_scan` audit event under the session root, and posture findings
// hang off that event.
//
// Layering: the scanner (@akasecurity/plugin-sdk) PRODUCES a ConfigScanResult; the
// posture rules (@akasecurity/detections) CONSUME it (pure, schema-typed only — this
// module is the shared vocabulary that keeps detections free of plugin-sdk); the
// gateway carries a ConfigScanRecord into @akasecurity/persistence.
//
// No `.meta({ id })` anywhere here: nothing is referenced by an API route,
// and an orphan id would leak into the OpenAPI client (the .meta id-leak gotcha
// in local.ts). Add ids only when ingest routes start referencing these shapes.
import { z } from 'zod';

import { ActionTaken, Span } from './finding.ts';
import type { TrustLevel } from './inventory.ts';
import {
  AuditEventInput,
  canonicalIdentity,
  InspectionDefinitionInput,
  InventoryInput,
} from './meta.ts';

// ── Scan entry shapes (scanner output / posture-rule input) ─────────────────

// Where a config artifact is registered. `plugin` scope carries the owning
// plugin's name separately (see configScopeKey). The same command at user scope
// and project scope is two registrations — two owners, two blast radii — so
// scope is part of hook identity.
export const ConfigScope = z.enum(['user', 'project', 'local', 'plugin']);
export type ConfigScope = z.infer<typeof ConfigScope>;

export const SkillScanEntry = z.object({
  name: z.string().min(1),
  // The identity source: a marketplace repo for plugin skills (e.g.
  // 'anthropics/skills'), 'local' for personal ~/.claude/skills, or
  // 'project:<repo-identity>' for checked-in project skills. The surrogate keeps
  // a personal skill named 'pdf' from colliding with the marketplace 'pdf'.
  source: z.string().min(1),
  scope: ConfigScope,
  pluginName: z.string().optional(),
  // Volatile — rides the attribute bag, never the identity hash.
  version: z.string().optional(),
  description: z.string().optional(),
  // Skill directory mtime (ISO) — the "updated Nd ago" freshness signal.
  updatedAt: z.iso.datetime().optional(),
  // Filesystem path — the promoted inventory `location` column.
  location: z.string().optional(),
});
export type SkillScanEntry = z.infer<typeof SkillScanEntry>;

export const HookScanEntry = z.object({
  // Hook event name (PreToolUse, PostToolUse, …). Open string, not an enum: the
  // set is harness-defined and grows without a schema change.
  event: z.string().min(1),
  // The tool matcher ('Bash', 'Edit|Write', …). Absent = matches all tools.
  matcher: z.string().optional(),
  command: z.string().min(1),
  timeout: z.number().optional(),
  scope: ConfigScope,
  pluginName: z.string().optional(),
  // The settings file / hooks.json the entry came from.
  location: z.string().optional(),
});
export type HookScanEntry = z.infer<typeof HookScanEntry>;

export const McpServerScanEntry = z.object({
  // The server's config key ("github", "filesystem", …) — identity, with the
  // qualified scope (see mcpServerIdentityKey).
  name: z.string().min(1),
  scope: ConfigScope,
  pluginName: z.string().optional(),
  // The owning plugin's marketplace — part of PLUGIN-scope identity: two
  // marketplaces can each ship a plugin named `guard`, and without this their
  // same-named servers would collapse to one row (the second silently dropped,
  // inheriting the first's trust).
  marketplace: z.string().optional(),
  // The repo identity (remote url, or the cwd for un-remoted repos) — part of
  // PROJECT/LOCAL-scope identity: a server named `github` in repo A and one in
  // repo B are different servers with different commands, and MUST NOT share a
  // row — a shared row would let a cloned repo's .mcp.json inherit the trust
  // the user granted elsewhere.
  project: z.string().optional(),
  // 'stdio' when the entry carries a command; otherwise the config's `type`
  // ('http' / 'sse' / …). Open string — the transport set is harness-defined.
  transport: z.string().min(1),
  // Volatile on purpose (unlike hook `command`): a changed command/url is drift
  // on a stable row — visible across config_scan snapshots and preserving the
  // user's trust decision — never a quiet new row. One of the two is present.
  // Secret-masked at collection time (the scanner runs the bundled detection
  // packs over both — tokens routinely ride command args and URLs).
  command: z.string().optional(),
  url: z.string().optional(),
  // Env var NAMES only, never values (the no-secrets rule).
  envKeys: z.array(z.string()).optional(),
  // The config file the entry came from.
  location: z.string().optional(),
});
export type McpServerScanEntry = z.infer<typeof McpServerScanEntry>;

export const ConfigFileScanEntry = z.object({
  // Basename (settings.json, CLAUDE.md) or dir name (commands/, agents/).
  name: z.string().min(1),
  // The absolute path — identity (with scope) and the promoted `location`.
  path: z.string().min(1),
  scope: ConfigScope,
  // Human label: "User settings", "Project memory", "Slash commands", …
  kind: z.string().min(1),
  // Derived SHAPE summary — top-level key names, entry counts, line counts.
  // Never file content or values (memory files can carry sensitive detail).
  detail: z.string().optional(),
  // Dir configs (commands/, agents/) and .mcp.json: how many entries.
  entryCount: z.number().optional(),
  // File mtime (ISO) — the freshness signal.
  updatedAt: z.iso.datetime().optional(),
});
export type ConfigFileScanEntry = z.infer<typeof ConfigFileScanEntry>;

// One config scan pass. `errors` is the fail-open bookkeeping: a malformed
// source file becomes an entry here (and a note in the scan event's attributes),
// never a throw out of the scanner.
export const ConfigScanResult = z.object({
  scannedAt: z.iso.datetime(),
  skills: z.array(SkillScanEntry),
  hooks: z.array(HookScanEntry),
  mcpServers: z.array(McpServerScanEntry),
  configFiles: z.array(ConfigFileScanEntry),
  errors: z.array(z.object({ source: z.string(), reason: z.string() })),
});
export type ConfigScanResult = z.infer<typeof ConfigScanResult>;

// ── Identity keys (what gets hashed into the content-addressed id) ──────────
// Hash only what makes the thing THE SAME THING. Skill version
// and hook timeout are volatile → bag. Hook command is identity on purpose (an
// edit = a new hook = the "unknown hook appeared" signal).

// 'plugin:aka' vs plain 'user'/'project'/'local' — folds the owning plugin into
// identity so two plugins registering the same command stay distinct rows.
export function configScopeKey(scope: ConfigScope, pluginName?: string): string {
  return scope === 'plugin' ? `plugin:${pluginName ?? ''}` : scope;
}

export function skillIdentityKey(
  entry: Pick<SkillScanEntry, 'source' | 'name' | 'pluginName'>,
): string {
  // Fold the owning plugin into identity — the skill analogue of configScopeKey
  // for hooks. Every plugin in a marketplace shares `source = <marketplace>`, so
  // without pluginName two different plugins shipping a same-named skill would
  // collapse to one row (the second silently dropped). Non-plugin skills
  // (personal / project / marketplace-root) carry no pluginName and keep the
  // 2-part key, so their content-addressed id is unchanged.
  return entry.pluginName
    ? canonicalIdentity([entry.source, entry.name, entry.pluginName])
    : canonicalIdentity([entry.source, entry.name]);
}

export function hookIdentityKey(
  entry: Pick<HookScanEntry, 'event' | 'matcher' | 'command' | 'scope' | 'pluginName'>,
): string {
  return canonicalIdentity([
    entry.event,
    entry.matcher ?? '',
    entry.command,
    configScopeKey(entry.scope, entry.pluginName),
  ]);
}

// name + QUALIFIED scope — command/url are deliberately NOT identity (the
// opposite trade to hooks): an MCP server carries a user trust decision
// (mcp_trust_override, keyed by this row's id), so a silently-changed endpoint
// must be drift on a stable row, never a quiet new row that resets trust.
//
// The qualifier is what keeps that trust decision from LEAKING across owners:
// - project/local servers fold the project surrogate in, so repo B's `github`
//   can never inherit the trust granted to repo A's `github` (a cloned repo's
//   .mcp.json would otherwise hijack it);
// - plugin servers fold marketplace + plugin in, so two marketplaces' `guard`
//   plugins keep distinct same-named servers;
// - user servers are machine-global by definition — bare scope.
export function mcpServerScopeKey(
  entry: Pick<McpServerScanEntry, 'scope' | 'pluginName' | 'marketplace' | 'project'>,
): string {
  // Flat `:`-joined, NOT a nested canonicalIdentity, on purpose: this string
  // doubles as the human-readable `scope` attribute on the row (see
  // configInventoryInputs), so nesting would both uglify that display and churn
  // every content-addressed id. The residual cost is a theoretical separator
  // collision (marketplace `a:b` + plugin `c` vs `a` + `b:c`), which needs a
  // literal `:` inside a marketplace/plugin directory name — effectively never.
  switch (entry.scope) {
    case 'plugin':
      return `plugin:${entry.marketplace ?? ''}:${entry.pluginName ?? ''}`;
    case 'project':
    case 'local':
      return `${entry.scope}:${entry.project ?? ''}`;
    default:
      return entry.scope;
  }
}

export function mcpServerIdentityKey(
  entry: Pick<McpServerScanEntry, 'name' | 'scope' | 'pluginName' | 'marketplace' | 'project'>,
): string {
  return canonicalIdentity([entry.name, mcpServerScopeKey(entry)]);
}

// path + scope: the file IS the thing; its contents (kind/detail/mtime) are
// mutable state on the row. Editing settings.json refreshes the bag — it never
// mints a new row. Scope disambiguates conceptually-same basenames at different
// levels (user vs project settings.json), though their paths already differ.
export function configFileIdentityKey(entry: Pick<ConfigFileScanEntry, 'path' | 'scope'>): string {
  return canonicalIdentity([entry.path, configScopeKey(entry.scope)]);
}

// ── Scan → inventory mapping (pure) ─────────────────────────────────────────
// Shared by the scanner (to build the upsert batch) and tests (to assert the
// batch), so the identity/bag contract can't drift between them. The bags are
// COMPLETE on every call — the inventory upsert is Type-1 wholesale replace
// (see SqliteInventoryRepository), so a partial bag would erase attributes.

export function configInventoryInputs(scan: ConfigScanResult): InventoryInput[] {
  const inputs: InventoryInput[] = [];
  for (const skill of scan.skills) {
    const attributes: SkillScanEntryBag = {
      source: skill.source,
      scope: configScopeKey(skill.scope, skill.pluginName),
    };
    if (skill.version !== undefined) attributes.version = skill.version;
    if (skill.description !== undefined) attributes.description = skill.description;
    if (skill.updatedAt !== undefined) attributes.updated_at = skill.updatedAt;
    if (skill.pluginName !== undefined) attributes.plugin_name = skill.pluginName;
    const input: InventoryInput = {
      objectType: 'skill',
      identityKey: skillIdentityKey(skill),
      title: skill.name,
      attributes,
    };
    if (skill.location !== undefined) input.location = skill.location;
    inputs.push(input);
  }
  for (const hook of scan.hooks) {
    const attributes: HookScanEntryBag = {
      event: hook.event,
      command: hook.command,
      scope: configScopeKey(hook.scope, hook.pluginName),
    };
    if (hook.matcher !== undefined) attributes.matcher = hook.matcher;
    if (hook.timeout !== undefined) attributes.timeout = hook.timeout;
    if (hook.pluginName !== undefined) attributes.plugin_name = hook.pluginName;
    const input: InventoryInput = {
      objectType: 'hook',
      identityKey: hookIdentityKey(hook),
      title: `${hook.event}: ${truncate(hook.command, 80)}`,
      attributes,
    };
    if (hook.location !== undefined) input.location = hook.location;
    inputs.push(input);
  }
  for (const server of scan.mcpServers) {
    const attributes: McpServerScanEntryBag = {
      // The QUALIFIED scope — the same string hashed into identity, so the
      // read surface can always show which owner a row belongs to.
      scope: mcpServerScopeKey(server),
      transport: server.transport,
    };
    if (server.command !== undefined) attributes.command = server.command;
    if (server.url !== undefined) attributes.url = server.url;
    if (server.envKeys !== undefined && server.envKeys.length > 0) {
      attributes.env_keys = server.envKeys;
    }
    if (server.pluginName !== undefined) attributes.plugin_name = server.pluginName;
    if (server.marketplace !== undefined) attributes.marketplace = server.marketplace;
    if (server.project !== undefined) attributes.project = server.project;
    const input: InventoryInput = {
      objectType: 'mcp_server',
      identityKey: mcpServerIdentityKey(server),
      title: server.name,
      attributes,
    };
    if (server.location !== undefined) input.location = server.location;
    inputs.push(input);
  }
  for (const file of scan.configFiles) {
    const attributes: ConfigFileScanEntryBag = {
      kind: file.kind,
      scope: configScopeKey(file.scope),
    };
    if (file.detail !== undefined) attributes.detail = file.detail;
    if (file.entryCount !== undefined) attributes.entry_count = file.entryCount;
    if (file.updatedAt !== undefined) attributes.updated_at = file.updatedAt;
    inputs.push({
      objectType: 'config_file',
      identityKey: configFileIdentityKey(file),
      title: file.name,
      location: file.path,
      attributes,
    });
  }
  return inputs;
}

// Snake_case bag keys per the canonical vocabulary (SkillAttributes /
// HookAttributes in meta.ts) — adapters must not drift to camelCase or the
// read surface's bag parsing silently loses fields.
interface SkillScanEntryBag extends Record<string, unknown> {
  source: string;
  scope: string;
  version?: string;
  description?: string;
  updated_at?: string;
  plugin_name?: string;
}

interface HookScanEntryBag extends Record<string, unknown> {
  event: string;
  command: string;
  scope: string;
  matcher?: string;
  timeout?: number;
  plugin_name?: string;
}

interface McpServerScanEntryBag extends Record<string, unknown> {
  scope: string;
  transport: string;
  command?: string;
  url?: string;
  env_keys?: string[];
  plugin_name?: string;
  marketplace?: string;
  project?: string;
}

interface ConfigFileScanEntryBag extends Record<string, unknown> {
  kind: string;
  scope: string;
  detail?: string;
  entry_count?: number;
  updated_at?: string;
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

// ── Gateway record (the one atomic write per scan) ──────────────────────────

// A posture-rule hit, referencing its definition by NATURAL key (ruleId +
// version) rather than by row id: the content-addressed inspectionDefinitionId
// is minted inside @akasecurity/persistence (the layer that owns the sha256 helper —
// same boundary rule as llmCallId), so the runtime never imports persistence to
// compute it. The writer resolves the key against the record's `definitions`,
// stamps the scan event's id as audit_event_id, and mints the finding row id.
export const ConfigPostureFindingInput = z.object({
  ruleId: z.string().min(1),
  version: z.string().min(1),
  span: Span,
  // For posture rules this is the offending COMMAND (config the user already
  // holds locally, not captured secret content) — it is also the correlation
  // key the read surface matches back to a hook row.
  maskedMatch: z.string(),
  actionTaken: ActionTaken,
  confidence: z.number().min(0).max(1),
});
export type ConfigPostureFindingInput = z.infer<typeof ConfigPostureFindingInput>;

// Everything one scan commits together: the inventory upserts, the config_scan
// audit event, and any posture definitions + findings that reference
// it. One gateway method / one SQLite transaction — a torn scan (rows without
// their scan event, findings without their definitions) never persists.
export const ConfigScanRecord = z.object({
  items: z.array(InventoryInput),
  scanEvent: AuditEventInput,
  definitions: z.array(InspectionDefinitionInput).optional(),
  findings: z.array(ConfigPostureFindingInput).optional(),
});
export type ConfigScanRecord = z.infer<typeof ConfigScanRecord>;

// ── Read DTOs (plain interfaces, NOT Zod) ───────────────────────────────────
// Same rule as the read-projection DTOs in local.ts: no Zod registration, no
// `.meta({ id })` — these are the shapes @akasecurity/persistence's read port returns
// and the (later) dashboard views render. Statuses are DERIVED at read time
// (open findings on the latest scan; catalog comparison) — never stored.

export interface SkillInventoryItem {
  // Content-addressed inventory row id — the stable handle a UI selects/links by.
  id: string;
  name: string;
  source: string;
  scope: string;
  description?: string;
  installedVersion?: string;
  // From a skills catalog; absent when there is no catalog to compare against.
  latestVersion?: string;
  updatedAt?: string;
  // 'unknown' = no catalog to compare against (permanent for local/project
  // skills, which have no published upstream).
  status: 'update_available' | 'up_to_date' | 'unknown';
}

export interface HookInventoryItem {
  // Content-addressed inventory row id — the stable handle a UI selects/links by.
  id: string;
  event: string;
  matcher?: string;
  command: string;
  scope: string;
  pluginName?: string;
  // Derived from the latest scan's open posture findings, highest severity
  // wins: 'egress' (external-egress hook — the badge a UI must not soften)
  // > 'conflict' > 'unknown' > 'active' (no open finding).
  status: 'active' | 'conflict' | 'unknown' | 'egress';
  // Rule titles of the open posture findings on this hook (the generic
  // per-rule text, e.g. "Overlapping hooks — run order is undefined" — not
  // yet contextualized with the other hook's name).
  warnings: string[];
}

export interface McpInventoryItem {
  // Content-addressed inventory row id — the stable handle a UI selects/links
  // by, and the mcp_trust_override key.
  id: string;
  name: string;
  // The QUALIFIED scope (same string identity hashes) — 'user',
  // 'project:<repo>', 'local:<repo>', 'plugin:<marketplace>:<plugin>'.
  scope: string;
  transport: string;
  command?: string;
  url?: string;
  envKeys?: string[];
  pluginName?: string;
  marketplace?: string;
  project?: string;
  // EFFECTIVE trust: the user's override when set, else 'unapproved' — a scan
  // can't prove a server safe (no verification registry yet), so unreviewed
  // means review-required, never a guessed 'known-good'. Derived at read time.
  trust: TrustLevel;
}

export interface ConfigFileInventoryItem {
  // Content-addressed inventory row id — the stable handle a UI selects/links by.
  id: string;
  name: string;
  path: string;
  scope: string;
  kind: string;
  detail?: string;
  entryCount?: number;
  updatedAt?: string;
  // settings.local.json is by Claude Code convention the gitignored local
  // override — surfaced so the page can flag it. Derived, never stored.
  untracked: boolean;
}

// The "Status by topic" rollup row.
export interface ConfigTopicStatus {
  topic: 'skills' | 'hooks' | 'mcp' | 'config_files' | 'configuration';
  count: number;
  attention?: string;
}

export interface ConfigInventoryReport {
  // started_at of the latest config_scan (ISO); null when no scan has run yet.
  scannedAt: string | null;
  skills: SkillInventoryItem[];
  hooks: HookInventoryItem[];
  mcpServers: McpInventoryItem[];
  configFiles: ConfigFileInventoryItem[];
  topics: ConfigTopicStatus[];
}
