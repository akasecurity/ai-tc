import { closeSync, fstatSync, openSync, readFileSync, readSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { normalizeAccountEmail } from '@akasecurity/schema';

import type { AccountPlanState } from './account-check.ts';
import type { ClaudeAccountEnv } from './account-env.ts';
import {
  CLAUDE_BASE_URL_ENV,
  CLAUDE_CREDENTIAL_ENV,
  CLAUDE_PROVIDER_FLAG_ENV,
  isNonDefaultBaseUrl,
  isPresent,
  isTruthyFlag,
} from './account-env.ts';

export const CLAUDE_CONFIG_MAX_BYTES = 4 * 1024 * 1024;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const COMPANY_CLAUDE_PLANS: ReadonlySet<string> = new Set(['claude_team', 'claude_enterprise']);

/** The parts of Claude Code's login file the account check reads. */
export interface ClaudeLogin {
  readonly hasOauthAccount: boolean;
  /** `oauthAccount.organizationUuid`, lower-cased, when it is a UUID. */
  readonly org: string | undefined;
  /** `oauthAccount.emailAddress`, normalised. */
  readonly email: string | undefined;
  readonly planState: AccountPlanState;
  readonly primaryApiKey: boolean;
  readonly hasSlots: boolean;
  /** The org of the `clientDataCacheSlots` entry with the newest `at`, lower-cased. */
  readonly newestSlotOrg: string | undefined;
}

export type ClaudeLoginRead =
  | {
      readonly status: 'ok';
      readonly login: ClaudeLogin;
      readonly mtimeMs: number;
      readonly size: number;
    }
  | { readonly status: 'absent' }
  | { readonly status: 'unreadable' };

/** Where to look instead of the real home and the system managed-settings file. */
export interface ClaudeLoginPaths {
  readonly home?: string | undefined;
  readonly managedSettings?: string | undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNotFound(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

function closeQuietly(fd: number): void {
  try {
    closeSync(fd);
  } catch {
    // already closed
  }
}

/** `claude_team` and `claude_enterprise` are company plans; absent or null is not shown. */
export function claudePlanState(organizationType: unknown): AccountPlanState {
  if (organizationType === undefined || organizationType === null) return 'absent';
  return typeof organizationType === 'string' && COMPANY_CLAUDE_PLANS.has(organizationType)
    ? 'company'
    : 'other';
}

/** `<CLAUDE_CONFIG_DIR>/.claude.json` when the override is set, else `~/.claude.json`. */
export function claudeConfigPath(
  env: Pick<ClaudeAccountEnv, 'configDir'>,
  home: string = homedir(),
): string {
  return join(env.configDir ?? home, '.claude.json');
}

export function claudeManagedSettingsPath(platform: NodeJS.Platform = process.platform): string {
  if (platform === 'darwin') return '/Library/Application Support/ClaudeCode/managed-settings.json';
  if (platform === 'win32') return 'C:\\Program Files\\ClaudeCode\\managed-settings.json';
  return '/etc/claude-code/managed-settings.json';
}

/** The user, project, local and managed settings layers, in that order. */
export function claudeSettingsPaths(
  env: Pick<ClaudeAccountEnv, 'configDir'>,
  cwd: string,
  paths: ClaudeLoginPaths = {},
): readonly string[] {
  const userDir = env.configDir ?? join(paths.home ?? homedir(), '.claude');
  return [
    join(userDir, 'settings.json'),
    join(cwd, '.claude', 'settings.json'),
    join(cwd, '.claude', 'settings.local.json'),
    paths.managedSettings ?? claudeManagedSettingsPath(),
  ];
}

function settingsLayerVetoes(path: string): boolean {
  let text: string;
  try {
    const stat = statSync(path);
    if (!stat.isFile()) return false;
    if (stat.size > CLAUDE_CONFIG_MAX_BYTES) return true;
    text = readFileSync(path, 'utf8');
  } catch (error) {
    return !isNotFound(error);
  }
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return true;
  }
  if (!isRecord(root)) return true;
  if (root.apiKeyHelper !== undefined && root.apiKeyHelper !== null) return true;
  const env = root.env;
  if (!isRecord(env)) return false;
  return (
    CLAUDE_CREDENTIAL_ENV.some((name) => isPresent(env[name])) ||
    CLAUDE_PROVIDER_FLAG_ENV.some((name) => isTruthyFlag(env[name])) ||
    isNonDefaultBaseUrl(env[CLAUDE_BASE_URL_ENV])
  );
}

/**
 * True when any settings layer sets an API key helper or an env block that
 * bills elsewhere. A layer that exists but cannot be read or parsed counts.
 */
export function claudeSettingsVeto(paths: readonly string[]): boolean {
  return paths.some(settingsLayerVetoes);
}

function newestSlot(slots: unknown): { hasSlots: boolean; newestSlotOrg: string | undefined } {
  if (!isRecord(slots)) return { hasSlots: false, newestSlotOrg: undefined };
  let newest: { at: number; org: unknown } | undefined;
  for (const slot of Object.values(slots)) {
    if (!isRecord(slot) || typeof slot.at !== 'number' || !Number.isFinite(slot.at)) continue;
    if (newest === undefined || slot.at > newest.at) newest = { at: slot.at, org: slot.org };
  }
  if (newest === undefined) return { hasSlots: false, newestSlotOrg: undefined };
  return {
    hasSlots: true,
    newestSlotOrg: typeof newest.org === 'string' ? newest.org.toLowerCase() : undefined,
  };
}

function parseClaudeConfig(text: string): ClaudeLogin | undefined {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!isRecord(root)) return undefined;
  const oauth = root.oauthAccount;
  const account = isRecord(oauth) ? oauth : undefined;
  const rawOrg = account?.organizationUuid;
  const org = typeof rawOrg === 'string' ? rawOrg.toLowerCase() : undefined;
  const rawEmail = account?.emailAddress;
  return {
    hasOauthAccount: account !== undefined,
    org: org !== undefined && UUID.test(org) ? org : undefined,
    email: typeof rawEmail === 'string' ? normalizeAccountEmail(rawEmail) : undefined,
    planState: claudePlanState(account?.organizationType),
    primaryApiKey: root.primaryApiKey !== undefined && root.primaryApiKey !== null,
    ...newestSlot(root.clientDataCacheSlots),
  };
}

let memo: { path: string; mtimeMs: number; size: number; read: ClaudeLoginRead } | undefined;

/**
 * Claude Code's login file, read whole up to the cap. A good read is memoised
 * on (mtime, size); an absent or unreadable one never is.
 */
export function readClaudeLogin(path: string): ClaudeLoginRead {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch (error) {
    return isNotFound(error) ? { status: 'absent' } : { status: 'unreadable' };
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > CLAUDE_CONFIG_MAX_BYTES) return { status: 'unreadable' };
    if (memo?.path === path && memo.mtimeMs === stat.mtimeMs && memo.size === stat.size)
      return memo.read;
    const buffer = Buffer.alloc(stat.size);
    let filled = 0;
    while (filled < stat.size) {
      const chunk = readSync(fd, buffer, filled, stat.size - filled, filled);
      if (chunk === 0) break;
      filled += chunk;
    }
    if (filled !== stat.size) return { status: 'unreadable' };
    const login = parseClaudeConfig(buffer.toString('utf8'));
    if (login === undefined) return { status: 'unreadable' };
    const read: ClaudeLoginRead = { status: 'ok', login, mtimeMs: stat.mtimeMs, size: stat.size };
    memo = { path, mtimeMs: stat.mtimeMs, size: stat.size, read };
    return read;
  } catch {
    return { status: 'unreadable' };
  } finally {
    closeQuietly(fd);
  }
}
