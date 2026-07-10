import { readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';

import type {
  ConfigFileScanEntry,
  ConfigScanResult,
  ConfigScope,
  HookScanEntry,
  McpServerScanEntry,
  SkillScanEntry,
} from '@akasecurity/schema';
import { mcpServerIdentityKey, skillIdentityKey } from '@akasecurity/schema';

import { maskText } from './mask.ts';
import { resolveRepoIdentity } from './repo.ts';

/**
 * Inputs for one config-inventory scan. `homeDir` is injectable for tests;
 * production callers omit it (node:os homedir — the same environment door the
 * inventory resolver already uses via hostname(), NOT process.env).
 */
export interface ResolveConfigInventoryInput {
  cwd: string;
  homeDir?: string | undefined;
}

/**
 * Scan the machine's Claude Code configuration surface — registered hooks and
 * installed skills — into a {@link ConfigScanResult} (the meta-model config
 * inventory; design: config-inventory-skills-hooks.design.md).
 *
 * Sources, each parsed independently and fail-open (a malformed file becomes an
 * `errors` entry, never a throw — dropping one source must not lose the rest):
 *
 * - Hooks: `~/.claude/settings.json` (user), `<cwd>/.claude/settings.json`
 *   (project), `<cwd>/.claude/settings.local.json` (local), plus each installed
 *   plugin's `<installPath>/hooks/hooks.json` (scope `plugin`).
 * - MCP servers: `<cwd>/.mcp.json` (the shared project surface, scope
 *   `project`); `~/.claude.json` — the `claude mcp add` target — top-level
 *   `mcpServers` (scope `user`) and this project's `projects[cwd].mcpServers`
 *   (scope `local`, matched leniently: trailing slash + realpath); a
 *   `mcpServers` key in any of the three settings files (managed/enterprise
 *   deployments put servers there); each installed plugin's
 *   `<installPath>/.mcp.json` AND its manifest's `mcpServers` field (scope
 *   `plugin`). De-duplicated by inventory identity (name + qualified scope:
 *   project surrogate for project/local, marketplace+plugin for plugin), first
 *   hit wins — canonical sources are scanned before fallbacks so their
 *   command/url wins the bag. No secrets: env var NAMES only, commands/urls
 *   masked through the bundled detection packs, url userinfo/query values
 *   stripped structurally.
 * - Config files: existence + a derived SHAPE summary — never content. The
 *   three settings files (top-level key names), `~/.claude/CLAUDE.md` and
 *   `<cwd>/CLAUDE.md` memory (line counts), `<cwd>/.mcp.json` (server count),
 *   and the project's `.claude/commands/` + `.claude/agents/` dirs (entry
 *   counts). Absent files are a non-event.
 * - Skills: `~/.claude/skills/<name>/SKILL.md` (source 'local'), the project's
 *   `<cwd>/.claude/skills` and top-level `<cwd>/skills` (source
 *   `project:<repo-identity>`), each installed plugin's
 *   `<installPath>/skills/<name>/SKILL.md` (source = the plugin's marketplace),
 *   plus every known marketplace's skills (root + `plugins/*` + `external_plugins/*`)
 *   EXCEPT Anthropic's built-in `claude-plugins-official` catalog. Skills are
 *   de-duplicated by inventory identity (source + name), so distinct sources that
 *   share a name (personal `pdf` vs a marketplace `pdf`) stay separate.
 *
 * Installed plugins come from `~/.claude/plugins/installed_plugins.json`
 * (version 2: `plugins: { "<name>@<marketplace>": [{ installPath, version }] }`)
 * — the harness's own manifest, so attribution never guesses at directory
 * layouts. Read-only everywhere; env values are never captured (bag carries
 * key names and commands only, per the design's no-secrets rule).
 */
export function resolveConfigInventory(input: ResolveConfigInventoryInput): ConfigScanResult {
  const scan: ConfigScanResult = {
    scannedAt: new Date().toISOString(),
    skills: [],
    hooks: [],
    mcpServers: [],
    configFiles: [],
    errors: [],
  };
  try {
    const home = input.homeDir ?? homedir();
    const claudeDir = join(home, '.claude');

    // The repo identity — folded into project/local-scope identity for skills
    // (as the `project:` source surrogate) AND MCP servers (as the scope
    // qualifier), so same-named artifacts in different repos never share a row
    // (an MCP row carries a trust decision; sharing would let a cloned repo
    // inherit it).
    const repo = resolveRepoIdentity(input.cwd);
    const repoIdentity = repo?.url ?? input.cwd;
    const projectSource = `project:${repoIdentity}`;

    // Hooks + (managed-deployment) MCP servers from the three settings scopes.
    collectSettingsHooks(scan, join(claudeDir, 'settings.json'), 'user');
    collectSettingsHooks(scan, join(input.cwd, '.claude', 'settings.json'), 'project');
    collectSettingsHooks(scan, join(input.cwd, '.claude', 'settings.local.json'), 'local');

    // MCP servers. Canonical sources FIRST — dedup is first-hit-wins per
    // identity, so the canonical file's command/url wins the bag when a server
    // is registered in two places at the same scope: the shared project
    // .mcp.json, then ~/.claude.json (the `claude mcp add` target: top-level =
    // user scope, projects[cwd] = local scope), then the settings files above
    // (already parsed for hooks; managed deployments carry mcpServers there).
    // recordErrors: this collector is the project .mcp.json's ONLY parse, so a
    // malformed file must be noted here or it vanishes silently.
    const projectOrigin = { scope: 'project' as const, project: repoIdentity };
    collectMcpFile(scan, join(input.cwd, '.mcp.json'), projectOrigin, { recordErrors: true });
    collectUserClaudeJson(scan, join(home, '.claude.json'), input.cwd, repoIdentity);
    collectMcpFile(scan, join(claudeDir, 'settings.json'), { scope: 'user' });
    collectMcpFile(scan, join(input.cwd, '.claude', 'settings.json'), projectOrigin);
    collectMcpFile(scan, join(input.cwd, '.claude', 'settings.local.json'), {
      scope: 'local',
      project: repoIdentity,
    });

    // Configuration files: existence + shape summaries, never content.
    collectConfigFiles(scan, claudeDir, input.cwd);

    // Personal skills + project skills (the Claude Code `.claude/skills` convention).
    collectSkillsDir(scan, join(claudeDir, 'skills'), { source: 'local', scope: 'user' });
    collectSkillsDir(scan, join(input.cwd, '.claude', 'skills'), {
      source: projectSource,
      scope: 'project',
    });

    // Plugin-owned hooks + skills, attributed via the harness's install manifest.
    collectInstalledPlugins(scan, claudeDir);

    // Every known marketplace's skills EXCEPT Anthropic's built-in catalog — the
    // third-party surface the user pulled in (installPath scans can miss these:
    // a built installPath may carry only commands/ + hooks/, the skills living in
    // the marketplace clone).
    collectMarketplaceSkills(scan, claudeDir);

    // Project code skills: a repo can define skills at its top-level `skills/`
    // (not the `.claude/skills` convention) — e.g. this codebase. These carry the
    // `project:` source, so a repo that is ALSO a registered marketplace surfaces
    // its skills as two distinct rows (project code + marketplace checkout) — they
    // are genuinely two registrations with two identities, not one to collapse.
    collectSkillsDir(scan, join(input.cwd, 'skills'), { source: projectSource, scope: 'project' });

    // Collapse only skills that share an inventory identity (source + name); see
    // dedupeSkills. Distinct-source same-name skills are kept.
    scan.skills = dedupeSkills(scan.skills);
    // Same rule for MCP servers: one row per identity (name + qualified scope),
    // first hit winning — the same server reached via two files is one
    // registration; the same name at two scopes (or two projects, or two
    // marketplaces) is two.
    scan.mcpServers = dedupeMcpServers(scan.mcpServers);
  } catch (err) {
    // Fail-open belt-and-braces: even a scanner bug yields a (partial) result.
    scan.errors.push({ source: 'config-scan', reason: message(err) });
  }
  return scan;
}

// ── Hooks ────────────────────────────────────────────────────────────────────

// The Claude Code hooks shape shared by settings files and plugin hooks.json:
// { "hooks": { "<Event>": [ { "matcher"?, "hooks": [ { "type", "command", "timeout"? } ] } ] } }
function collectHooksObject(
  scan: ConfigScanResult,
  hooks: unknown,
  location: string,
  scope: ConfigScope,
  pluginName?: string,
): void {
  if (typeof hooks !== 'object' || hooks === null) return;
  for (const [event, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (typeof entry !== 'object' || entry === null) continue;
      const matcher = (entry as Record<string, unknown>).matcher;
      const inner = (entry as Record<string, unknown>).hooks;
      if (!Array.isArray(inner)) continue;
      for (const hook of inner) {
        if (typeof hook !== 'object' || hook === null) continue;
        const command = (hook as Record<string, unknown>).command;
        if (typeof command !== 'string' || command.length === 0) continue;
        const timeout = (hook as Record<string, unknown>).timeout;
        // Hook commands embed tokens too (`curl -H "Authorization: …"`) — same
        // no-secrets masking as MCP commands. maskText is deterministic, so the
        // command-is-identity property survives: the same masked command hashes
        // to the same row every scan.
        const item: HookScanEntry = { event, command: maskText(command), scope, location };
        if (typeof matcher === 'string') item.matcher = matcher;
        if (typeof timeout === 'number') item.timeout = timeout;
        if (pluginName !== undefined) item.pluginName = pluginName;
        scan.hooks.push(item);
      }
    }
  }
}

function collectSettingsHooks(scan: ConfigScanResult, path: string, scope: ConfigScope): void {
  const raw = readOptional(path);
  if (raw === undefined) return; // absent file = nothing registered, not an error
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return;
    collectHooksObject(scan, (parsed as Record<string, unknown>).hooks, path, scope);
  } catch (err) {
    scan.errors.push({ source: path, reason: parseErrorReason(err) });
  }
}

// ── MCP servers ──────────────────────────────────────────────────────────────

// Where an MCP entry came from — everything mcpServerScopeKey folds into
// identity beyond the name: the scope, the owning plugin + its marketplace
// (plugin scope), the project surrogate (project/local scopes).
interface McpOrigin {
  scope: ConfigScope;
  pluginName?: string;
  marketplace?: string;
  project?: string;
}

// The Claude Code mcpServers shape, shared by .mcp.json, ~/.claude.json, the
// settings files and plugin manifests:
// { "<name>": { command, args?, env?, … } | { type?, url, … } }.
// The no-secrets rule applies to every captured string: env VALUES are never
// read (names only), and the command/url — where tokens routinely ride as args
// (`--header "Authorization: Bearer …"`) or query strings — pass through the
// bundled detection packs (maskText, fail-secure) before entering the scan.
function collectMcpObject(
  scan: ConfigScanResult,
  servers: unknown,
  location: string,
  origin: McpOrigin,
): void {
  if (typeof servers !== 'object' || servers === null) return;
  for (const [name, entry] of Object.entries(servers)) {
    if (name.length === 0 || typeof entry !== 'object' || entry === null) continue;
    const rec = entry as Record<string, unknown>;
    const command = str(rec.command);
    const url = str(rec.url);
    if (command === undefined && url === undefined) continue; // not a server entry
    // stdio when a command is present (the config's default); a remote entry's
    // `type` ('http' / 'sse') when declared, else 'http'.
    const declared = str(rec.type);
    const transport = declared ?? (command !== undefined ? 'stdio' : 'http');
    const item: McpServerScanEntry = { name, scope: origin.scope, transport, location };
    if (command !== undefined) {
      // The full invocation (command + args) — display/drift state, not
      // identity. Number/boolean args (ports, flags) are kept as their string
      // form: dropping them would misrepresent the invocation and corrupt the
      // drift baseline. maskText is deterministic, so drift comparison over the
      // masked string still works.
      const args = Array.isArray(rec.args)
        ? rec.args
            .filter((a) => typeof a === 'string' || typeof a === 'number' || typeof a === 'boolean')
            .map(String)
        : [];
      item.command = maskText([command, ...args].join(' '));
    }
    // URLs carry credentials structurally (userinfo, query values) as well as
    // token-shaped substrings — sanitize the structure, then mask the rest.
    if (url !== undefined) item.url = maskText(sanitizeUrl(url));
    if (typeof rec.env === 'object' && rec.env !== null) {
      const envKeys = Object.keys(rec.env);
      if (envKeys.length > 0) item.envKeys = envKeys;
    }
    if (origin.pluginName !== undefined) item.pluginName = origin.pluginName;
    if (origin.marketplace !== undefined) item.marketplace = origin.marketplace;
    if (origin.project !== undefined) item.project = origin.project;
    scan.mcpServers.push(item);
  }
}

// Strip the credentials a URL can carry structurally: userinfo and query
// VALUES (param names stay — they are shape, not secret). Scheme/host/path
// stay: they are the identity a reviewer needs. Unparseable urls fall through
// untouched — the maskText pass still runs over them.
function sanitizeUrl(raw: string): string {
  try {
    const url = new URL(raw);
    url.username = '';
    url.password = '';
    for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, '***');
    return url.toString();
  } catch {
    return raw;
  }
}

// A JSON file carrying a top-level `mcpServers` key (.mcp.json, settings files,
// plugin .mcp.json). Parse failures on settings files are already recorded by
// collectSettingsHooks — recording them here too would double-count one broken
// file — so this collector stays silent on malformed JSON unless asked not to be.
function collectMcpFile(
  scan: ConfigScanResult,
  path: string,
  origin: McpOrigin,
  opts?: { recordErrors?: boolean },
): void {
  const raw = readOptional(path);
  if (raw === undefined) return;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return;
    collectMcpObject(scan, (parsed as Record<string, unknown>).mcpServers, path, origin);
  } catch (err) {
    if (opts?.recordErrors ?? false) {
      scan.errors.push({ source: path, reason: parseErrorReason(err) });
    }
  }
}

// ~/.claude.json — the `claude mcp add` target. Top-level `mcpServers` is the
// user scope; this project's `projects` entry is its local scope (the default
// `claude mcp add -s local` destination). Other projects' local servers are
// deliberately skipped: they are not part of THIS session's surface, and a
// machine-wide sweep would drag every repo the user ever opened into one scan.
function collectUserClaudeJson(
  scan: ConfigScanResult,
  path: string,
  cwd: string,
  repoIdentity: string,
): void {
  const raw = readOptional(path);
  if (raw === undefined) return;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return;
    const rec = parsed as Record<string, unknown>;
    collectMcpObject(scan, rec.mcpServers, path, { scope: 'user' });
    const projects = rec.projects;
    if (typeof projects === 'object' && projects !== null) {
      const project = projectEntryFor(projects as Record<string, unknown>, cwd);
      if (typeof project === 'object' && project !== null) {
        collectMcpObject(scan, (project as Record<string, unknown>).mcpServers, path, {
          scope: 'local',
          project: repoIdentity,
        });
      }
    }
  } catch (err) {
    scan.errors.push({ source: path, reason: parseErrorReason(err) });
  }
}

// ~/.claude.json keys `projects` by the exact cwd string Claude Code launched
// with. Match leniently on OUR side — trailing slashes and symlinked paths
// (macOS /tmp → /private/tmp) would otherwise silently drop every local-scope
// server for the session.
function projectEntryFor(projects: Record<string, unknown>, cwd: string): unknown {
  const candidates = new Set<string>([cwd]);
  const trimmed = cwd.replace(/\/+$/, '');
  if (trimmed.length > 0) candidates.add(trimmed);
  try {
    candidates.add(realpathSync(cwd));
  } catch {
    // unresolvable cwd → raw candidates only
  }
  for (const key of candidates) {
    const entry = projects[key];
    if (typeof entry === 'object' && entry !== null) return entry;
  }
  return undefined;
}

// A plugin manifest's `mcpServers` field: an inline servers object, or a
// relative path ("./mcp/servers.json") to a file carrying one. The manifest is
// the harness's own install contract, so entries here are running config even
// when no .mcp.json exists at the plugin root.
function collectPluginManifestMcp(
  scan: ConfigScanResult,
  installPath: string,
  origin: McpOrigin,
): void {
  const manifestPath = join(installPath, '.claude-plugin', 'plugin.json');
  const raw = readOptional(manifestPath);
  if (raw === undefined) return;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return;
    const declared = (parsed as Record<string, unknown>).mcpServers;
    if (typeof declared === 'string' && declared.length > 0) {
      collectMcpFile(scan, join(installPath, declared), origin, { recordErrors: true });
    } else {
      collectMcpObject(scan, declared, manifestPath, origin);
    }
  } catch (err) {
    scan.errors.push({ source: manifestPath, reason: parseErrorReason(err) });
  }
}

// ── Config files ─────────────────────────────────────────────────────────────
// Existence + a derived SHAPE summary per file — top-level key names, entry
// counts, line counts. Never file content or values: memory files in particular
// can carry sensitive project detail. An absent file is a non-event; a
// malformed one is still a row (existence is filesystem truth), just without a
// shape summary (parse errors on these files are recorded by the hook/MCP
// collectors that also read them, or don't matter for existence).

// The settings keys worth naming in the summary, with their display labels
// (the long tail of unknown keys is skipped, not guessed at).
const SETTINGS_KEY_LABELS: readonly [key: string, label: string][] = [
  ['permissions', 'Permissions'],
  ['model', 'model'],
  ['env', 'env'],
  ['hooks', 'hooks'],
  ['mcpServers', 'MCP servers'],
  ['statusLine', 'status line'],
];

function collectConfigFiles(scan: ConfigScanResult, claudeDir: string, cwd: string): void {
  settingsConfigFile(scan, join(claudeDir, 'settings.json'), 'user', 'User settings');
  settingsConfigFile(scan, join(cwd, '.claude', 'settings.json'), 'project', 'Project settings');
  settingsConfigFile(scan, join(cwd, '.claude', 'settings.local.json'), 'local', 'Local overrides');
  memoryConfigFile(scan, join(claudeDir, 'CLAUDE.md'), 'user', 'User memory');
  memoryConfigFile(scan, join(cwd, 'CLAUDE.md'), 'project', 'Project memory');
  mcpJsonConfigFile(scan, join(cwd, '.mcp.json'));
  dirConfigFile(scan, join(cwd, '.claude', 'commands'), 'Slash commands', 'command');
  dirConfigFile(scan, join(cwd, '.claude', 'agents'), 'Subagents', 'subagent');
}

// The row skeleton every source shares: basename, mtime, kind. Returns
// undefined when the path doesn't exist (a non-event, not an error).
function configFileEntry(
  path: string,
  scope: ConfigScope,
  kind: string,
): ConfigFileScanEntry | undefined {
  try {
    const stat = statSync(path);
    return { name: basename(path), path, scope, kind, updatedAt: stat.mtime.toISOString() };
  } catch {
    return undefined;
  }
}

function settingsConfigFile(
  scan: ConfigScanResult,
  path: string,
  scope: ConfigScope,
  kind: string,
): void {
  const entry = configFileEntry(path, scope, kind);
  if (!entry) return;
  const raw = readOptional(path);
  if (raw !== undefined) {
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed === 'object' && parsed !== null) {
        const labels = SETTINGS_KEY_LABELS.filter(([key]) => key in parsed).map(
          ([, label]) => label,
        );
        if (labels.length > 0) entry.detail = labels.join(', ');
      }
    } catch {
      // Malformed settings: the row still records existence; the parse error
      // is already an errors entry via collectSettingsHooks.
    }
  }
  scan.configFiles.push(entry);
}

function memoryConfigFile(
  scan: ConfigScanResult,
  path: string,
  scope: ConfigScope,
  kind: string,
): void {
  const entry = configFileEntry(path, scope, kind);
  if (!entry) return;
  const raw = readOptional(path);
  if (raw !== undefined) {
    // Line count only — memory content never leaves the machine's file. A
    // trailing newline terminates the last line rather than starting a new
    // one, and an empty file has zero lines, not one.
    const trimmed = raw.endsWith('\n') ? raw.slice(0, -1) : raw;
    const lines = trimmed === '' ? 0 : trimmed.split('\n').length;
    entry.detail = `${String(lines)} lines`;
  }
  scan.configFiles.push(entry);
}

function mcpJsonConfigFile(scan: ConfigScanResult, path: string): void {
  const entry = configFileEntry(path, 'project', 'MCP servers');
  if (!entry) return;
  const raw = readOptional(path);
  if (raw !== undefined) {
    try {
      const parsed: unknown = JSON.parse(raw);
      const servers = (parsed as Record<string, unknown> | null)?.mcpServers;
      if (typeof servers === 'object' && servers !== null) {
        // Count what the MCP scanner actually accepts (a command or url), so
        // this surface and the MCP asset list never disagree about the same
        // file — a disabled stub without either is not a server.
        const count = Object.values(servers).filter(
          (v) =>
            typeof v === 'object' &&
            v !== null &&
            (str((v as Record<string, unknown>).command) !== undefined ||
              str((v as Record<string, unknown>).url) !== undefined),
        ).length;
        entry.entryCount = count;
        entry.detail = `${String(count)} server${count === 1 ? '' : 's'}`;
      }
    } catch {
      // Recorded as an error by collectMcpFile — existence still rows here.
    }
  }
  scan.configFiles.push(entry);
}

// A directory config surface (commands/, agents/): the entry count is its
// shape. Both surfaces are defined by .md files, possibly nested in namespace
// subdirectories — so count .md files recursively, and never count what the
// harness doesn't load (.DS_Store, dotfiles, stray non-.md files).
function dirConfigFile(scan: ConfigScanResult, path: string, kind: string, noun: string): void {
  const entry = configFileEntry(path, 'project', kind);
  if (!entry) return;
  try {
    const count = countMarkdownFiles(path, 0);
    entry.entryCount = count;
    entry.detail = `${String(count)} ${noun}${count === 1 ? '' : 's'}`;
  } catch {
    // Unreadable dir: existence still rows, without a count.
  }
  scan.configFiles.push(entry);
}

function countMarkdownFiles(dir: string, depth: number): number {
  if (depth > 4) return 0; // defensive bound — config dirs are shallow
  let count = 0;
  for (const dirent of readdirSync(dir, { withFileTypes: true })) {
    if (dirent.name.startsWith('.')) continue;
    if (dirent.isDirectory()) count += countMarkdownFiles(join(dir, dirent.name), depth + 1);
    else if (dirent.name.endsWith('.md')) count += 1;
  }
  return count;
}

// ── Skills ───────────────────────────────────────────────────────────────────

interface SkillOrigin {
  source: string;
  scope: ConfigScope;
  pluginName?: string;
  // Plugin skills fall back to the plugin's install version when SKILL.md
  // frontmatter carries none.
  defaultVersion?: string;
}

function collectSkillsDir(scan: ConfigScanResult, dir: string, origin: SkillOrigin): void {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return; // no skills dir = nothing installed, not an error
  }
  for (const name of names) {
    const skillFile = join(dir, name, 'SKILL.md');
    try {
      const raw = readOptional(skillFile);
      if (raw === undefined) continue; // stray file/dir without a SKILL.md
      const front = parseFrontmatter(raw);
      const entry: SkillScanEntry = {
        name: front.name ?? name,
        source: origin.source,
        scope: origin.scope,
        location: join(dir, name),
        updatedAt: statSync(skillFile).mtime.toISOString(),
      };
      const version = front.version ?? origin.defaultVersion;
      if (version !== undefined) entry.version = version;
      if (front.description !== undefined) entry.description = front.description;
      if (origin.pluginName !== undefined) entry.pluginName = origin.pluginName;
      scan.skills.push(entry);
    } catch (err) {
      scan.errors.push({ source: skillFile, reason: message(err) });
    }
  }
}

// Lenient SKILL.md frontmatter: a leading `---` block of `key: value` lines.
// Skills without frontmatter (heading-only SKILL.md) fall back to the dir name.
// `description` fidelity is best-effort: only the single line after
// `description:` is captured, so YAML block scalars / multi-line values come
// out truncated. Identity rests on `name` (dir-name fallback), not description.
function parseFrontmatter(raw: string): { name?: string; description?: string; version?: string } {
  const out: { name?: string; description?: string; version?: string } = {};
  const lines = raw.split('\n');
  if (lines[0]?.trim() !== '---') return out;
  for (const line of lines.slice(1)) {
    if (line.trim() === '---') break;
    const sep = line.indexOf(':');
    if (sep === -1) continue;
    const key = line.slice(0, sep).trim();
    const value = line
      .slice(sep + 1)
      .trim()
      .replace(/^['"]|['"]$/g, '');
    if (value === '') continue;
    if (key === 'name') out.name = value;
    else if (key === 'description') out.description = value;
    else if (key === 'version') out.version = value;
  }
  return out;
}

// ── Installed plugins ────────────────────────────────────────────────────────

function collectInstalledPlugins(scan: ConfigScanResult, claudeDir: string): void {
  const manifestPath = join(claudeDir, 'plugins', 'installed_plugins.json');
  const raw = readOptional(manifestPath);
  if (raw === undefined) return;
  let plugins: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(raw);
    const p = (parsed as Record<string, unknown> | null)?.plugins;
    if (typeof p !== 'object' || p === null) return;
    plugins = p as Record<string, unknown>;
  } catch (err) {
    scan.errors.push({ source: manifestPath, reason: parseErrorReason(err) });
    return;
  }

  for (const [key, installs] of Object.entries(plugins)) {
    if (!Array.isArray(installs)) continue;
    // "name@marketplace" — the marketplace is the skill source (the publisher).
    const at = key.indexOf('@');
    const pluginName = at === -1 ? key : key.slice(0, at);
    const marketplace = at === -1 ? key : key.slice(at + 1);
    const seen = new Set<string>();
    for (const install of installs) {
      if (typeof install !== 'object' || install === null) continue;
      const installPath = (install as Record<string, unknown>).installPath;
      if (typeof installPath !== 'string' || seen.has(installPath)) continue;
      seen.add(installPath);
      const version = (install as Record<string, unknown>).version;

      const hooksPath = join(installPath, 'hooks', 'hooks.json');
      const hooksRaw = readOptional(hooksPath);
      if (hooksRaw !== undefined) {
        try {
          const parsed: unknown = JSON.parse(hooksRaw);
          if (typeof parsed === 'object' && parsed !== null) {
            collectHooksObject(
              scan,
              (parsed as Record<string, unknown>).hooks,
              hooksPath,
              'plugin',
              pluginName,
            );
          }
        } catch (err) {
          scan.errors.push({ source: hooksPath, reason: parseErrorReason(err) });
        }
      }

      const origin: SkillOrigin = { source: marketplace, scope: 'plugin', pluginName };
      if (typeof version === 'string') origin.defaultVersion = version;
      collectSkillsDir(scan, join(installPath, 'skills'), origin);

      // A plugin can ship MCP servers via its own .mcp.json OR declare them in
      // its manifest (plugin.json `mcpServers`: inline object or a relative
      // path). Both are this plugin's ONLY parse of those files, so record
      // errors. Marketplace rides the origin — it is part of plugin-scope
      // identity (two marketplaces' same-named plugins stay distinct).
      const mcpOrigin: McpOrigin = { scope: 'plugin', pluginName, marketplace };
      collectMcpFile(scan, join(installPath, '.mcp.json'), mcpOrigin, { recordErrors: true });
      collectPluginManifestMcp(scan, installPath, mcpOrigin);
    }
  }
}

// ── Marketplace skills (all except Anthropic's own) ────────────────────────────────

// Skills that ship inside a marketplace checkout. Every known marketplace is
// walked EXCEPT Anthropic's built-in `claude-plugins-official` (the tool's own
// bundled catalog, not the user's config): marketplace-root `skills/` plus every
// plugin's `plugins/<p>/skills` and `external_plugins/<p>/skills`. Not scoped to
// enabled plugins — the user asked to see the third-party surface they pulled in.
function collectMarketplaceSkills(scan: ConfigScanResult, claudeDir: string): void {
  for (const mp of readMarketplaces(join(claudeDir, 'plugins', 'known_marketplaces.json'))) {
    if (isClaudeOfficialMarketplace(mp.name, mp.repo)) continue;
    // Marketplace-root skills (repo-level skills shipped in the checkout).
    collectSkillsDir(scan, join(mp.installLocation, 'skills'), {
      source: mp.name,
      scope: 'plugin',
    });
    // Each plugin's own skills, in the standard or external layout.
    collectPluginSkillDirs(scan, join(mp.installLocation, 'plugins'), mp.name);
    collectPluginSkillDirs(scan, join(mp.installLocation, 'external_plugins'), mp.name);
  }
}

// Scan every `<pluginsDir>/<plugin>/skills` — attribute each to its plugin, with
// the source staying the marketplace (the publisher).
function collectPluginSkillDirs(
  scan: ConfigScanResult,
  pluginsDir: string,
  marketplace: string,
): void {
  let plugins: string[];
  try {
    plugins = readdirSync(pluginsDir);
  } catch {
    return; // this marketplace doesn't use this layout
  }
  for (const plugin of plugins) {
    collectSkillsDir(scan, join(pluginsDir, plugin, 'skills'), {
      source: marketplace,
      scope: 'plugin',
      pluginName: plugin,
    });
  }
}

interface KnownMarketplace {
  name: string;
  installLocation: string;
  repo: string | undefined;
}

// `known_marketplaces.json`: { "<name>": { installLocation, source: { repo } } }.
function readMarketplaces(manifestPath: string): KnownMarketplace[] {
  const raw = readOptional(manifestPath);
  if (raw === undefined) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null) return [];
    const out: KnownMarketplace[] = [];
    for (const [name, entry] of Object.entries(parsed as Record<string, unknown>)) {
      const rec = entry as Record<string, unknown> | null;
      const loc = rec?.installLocation;
      if (typeof loc !== 'string' || loc.length === 0) continue;
      const source = rec?.source as Record<string, unknown> | undefined;
      const repo = typeof source?.repo === 'string' ? source.repo : undefined;
      out.push({ name, installLocation: loc, repo });
    }
    return out;
  } catch {
    return []; // malformed manifest → no marketplace skills
  }
}

// Claude Code's built-in plugin catalog — excluded from the inventory (it's the
// tool's own BUNDLED skills, not the user's config). Matched by the canonical
// marketplace name, or its canonical repo (case-insensitively) so a locally
// renamed clone of the same catalog is still caught. Deliberately NOT a broad
// `anthropics/*` org match: a marketplace the user opted into (e.g. the public
// `anthropics/skills` collection) IS third-party config we must surface — org-wide
// exclusion would silently under-report it, against this scanner's whole intent.
function isClaudeOfficialMarketplace(name: string, repo: string | undefined): boolean {
  return (
    name === 'claude-plugins-official' ||
    repo?.toLowerCase() === 'anthropics/claude-plugins-official'
  );
}

// Collapse skills that share an INVENTORY IDENTITY (source + name + owning plugin —
// the exact key @akasecurity/persistence content-addresses on via skillIdentityKey) to
// one entry. A skill can surface from several roots with the same identity (the
// same plugin dir reached by both installed_plugins and its marketplace clone);
// those are one row. Anything with a distinct identity stays separate — a personal
// `pdf` vs a marketplace `pdf`, two marketplaces that each ship `audit`, or two
// different plugins in ONE marketplace that each ship `audit` — so the inventory
// never under-reports the surface. First hit per identity wins.
function dedupeSkills(skills: SkillScanEntry[]): SkillScanEntry[] {
  const seen = new Set<string>();
  const out: SkillScanEntry[] = [];
  for (const skill of skills) {
    const key = skillIdentityKey(skill);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(skill);
  }
  return out;
}

// One row per MCP inventory identity (name + scope), first hit winning — the
// scan order in resolveConfigInventory puts the canonical source first.
function dedupeMcpServers(servers: McpServerScanEntry[]): McpServerScanEntry[] {
  const seen = new Set<string>();
  const out: McpServerScanEntry[] = [];
  for (const server of servers) {
    const key = mcpServerIdentityKey(server);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(server);
  }
  return out;
}

// ── Small helpers ────────────────────────────────────────────────────────────

// undefined = file absent/unreadable (a non-event for optional config files).
function readOptional(path: string): string | undefined {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return undefined;
  }
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// V8 JSON.parse SyntaxErrors quote a source excerpt (`…"API_KEY": sk-l"…`), so
// err.message can embed the very secret a malformed config file was holding —
// and scan errors are persisted onto the config_scan audit event. Keep only the
// position bookkeeping, never the excerpt. Non-parse errors (fs errors carry
// paths, not content) keep their message.
function parseErrorReason(err: unknown): string {
  if (err instanceof SyntaxError) {
    const position = /at position \d+(?: \(line \d+ column \d+\))?/.exec(err.message)?.[0];
    return position ? `invalid JSON ${position}` : 'invalid JSON';
  }
  return message(err);
}

// undefined for anything but a non-empty string (lenient config field access).
function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}
