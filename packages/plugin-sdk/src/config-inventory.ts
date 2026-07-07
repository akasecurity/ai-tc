import { readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type {
  ConfigScanResult,
  ConfigScope,
  HookScanEntry,
  SkillScanEntry,
} from '@akasecurity/schema';

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
 * - Skills: `~/.claude/skills/<name>/SKILL.md` (source 'local'),
 *   `<cwd>/.claude/skills/<name>/SKILL.md` (source `project:<repo-identity>` —
 *   the surrogate keeps a project `pdf` from colliding with a marketplace
 *   `pdf`), plus each installed plugin's `<installPath>/skills/<name>/SKILL.md`
 *   (source = the plugin's marketplace).
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
    errors: [],
  };
  try {
    const home = input.homeDir ?? homedir();
    const claudeDir = join(home, '.claude');

    // Hooks from the three settings scopes.
    collectSettingsHooks(scan, join(claudeDir, 'settings.json'), 'user');
    collectSettingsHooks(scan, join(input.cwd, '.claude', 'settings.json'), 'project');
    collectSettingsHooks(scan, join(input.cwd, '.claude', 'settings.local.json'), 'local');

    // Personal + project skills.
    collectSkillsDir(scan, join(claudeDir, 'skills'), { source: 'local', scope: 'user' });
    const repo = resolveRepoIdentity(input.cwd);
    collectSkillsDir(scan, join(input.cwd, '.claude', 'skills'), {
      source: `project:${repo?.url ?? input.cwd}`,
      scope: 'project',
    });

    // Plugin-owned hooks + skills, attributed via the harness's install manifest.
    collectInstalledPlugins(scan, claudeDir);
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
