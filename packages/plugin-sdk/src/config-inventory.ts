import { readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type {
  ConfigScanResult,
  ConfigScope,
  HookScanEntry,
  SkillScanEntry,
} from '@akasecurity/schema';
import { skillIdentityKey } from '@akasecurity/schema';

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
    // Populated by the MCP collectors (next PR in the stack) — the widened
    // contract lands first so every consumer moves in one mechanical sweep.
    mcpServers: [],
    errors: [],
  };
  try {
    const home = input.homeDir ?? homedir();
    const claudeDir = join(home, '.claude');

    // Hooks from the three settings scopes.
    collectSettingsHooks(scan, join(claudeDir, 'settings.json'), 'user');
    collectSettingsHooks(scan, join(input.cwd, '.claude', 'settings.json'), 'project');
    collectSettingsHooks(scan, join(input.cwd, '.claude', 'settings.local.json'), 'local');

    // Personal skills + project skills (the Claude Code `.claude/skills` convention).
    collectSkillsDir(scan, join(claudeDir, 'skills'), { source: 'local', scope: 'user' });
    const repo = resolveRepoIdentity(input.cwd);
    const projectSource = `project:${repo?.url ?? input.cwd}`;
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
        const item: HookScanEntry = { event, command, scope, location };
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
    scan.errors.push({ source: path, reason: message(err) });
  }
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
    scan.errors.push({ source: manifestPath, reason: message(err) });
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
          scan.errors.push({ source: hooksPath, reason: message(err) });
        }
      }

      const origin: SkillOrigin = { source: marketplace, scope: 'plugin', pluginName };
      if (typeof version === 'string') origin.defaultVersion = version;
      collectSkillsDir(scan, join(installPath, 'skills'), origin);
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
