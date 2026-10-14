import type { Stats } from 'node:fs';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { join } from 'node:path';

import type { AccountPlanState } from './account-check.ts';
import { emailMatchesAttached } from './account-check.ts';

// Codex's login file, read in memory for three things only: whether its email
// is the attached user's, its plan's state, and its account id. Secrets are
// dropped while the file is parsed, the id_token's header and signature are
// never decoded, and no error is logged or passed on, since a JSON parse error
// quotes part of its input.

export const CODEX_AUTH_MAX_BYTES = 64 * 1024;
export const CODEX_ID_TOKEN_MAX_CHARS = 16 * 1024;
export const CODEX_ID_TOKEN_PAYLOAD_MAX_BYTES = 8 * 1024;

/** The id_token claim namespaces Codex reads the plan, the account and the profile email from. */
export const AUTH_CLAIMS = 'https://api.openai.com/auth';
export const PROFILE_CLAIMS = 'https://api.openai.com/profile';

/** Fields the parse drops, so no reference to their values survives it. */
export const CODEX_DROPPED_FIELDS = ['access_token', 'refresh_token'] as const;

/** Fields the parse turns into presence booleans; each marks a login that is not a ChatGPT one. */
export const CODEX_PRESENCE_FIELDS = [
  'OPENAI_API_KEY',
  'personal_access_token',
  'agent_identity',
  'bedrock_api_key',
  'bedrock_access_keys',
] as const;

/** The workspace plans Codex knows, with the two aliases it reads as enterprise and edu. */
export const COMPANY_CHATGPT_PLANS: ReadonlySet<string> = new Set([
  'team',
  'business',
  'enterprise',
  'hc',
  'edu',
  'education',
  'ent26',
  'enterprise_cbp_usage_based',
  'self_serve_business_prolite',
  'self_serve_business_usage_based',
  'edu_plus',
  'edu_pro',
]);

const DROPPED: ReadonlySet<string> = new Set(CODEX_DROPPED_FIELDS);
const PRESENCE: ReadonlySet<string> = new Set(CODEX_PRESENCE_FIELDS);
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NOFOLLOW = (constants as { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0;

export interface CodexLogin {
  /** The login's account id, lower-cased. */
  readonly accountId: string;
  readonly emailMatchesAttached: boolean;
  readonly planState: AccountPlanState;
  /** The file's device, inode, size, mtime and ctime as read, joined into one string. */
  readonly fingerprint: string;
}

export type CodexLoginRead =
  | { readonly status: 'ok'; readonly login: CodexLogin }
  | { readonly status: 'absent' | 'mode' | 'malformed' };

const ABSENT: CodexLoginRead = { status: 'absent' };
const MODE: CodexLoginRead = { status: 'mode' };
const MALFORMED: CodexLoginRead = { status: 'malformed' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNotFound(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === 'ENOENT';
}

const pick = (record: Readonly<Record<string, unknown>>, field: string): unknown => record[field];

/** A plan in the company set, no plan claim, or anything else, a non-string claim included. */
export function chatgptPlanState(plan: unknown): AccountPlanState {
  if (plan === undefined) return 'absent';
  return typeof plan === 'string' && COMPANY_CHATGPT_PLANS.has(plan) ? 'company' : 'other';
}

export function codexAuthPath(codexHome: string): string {
  return join(codexHome, 'auth.json');
}

function fingerprintOf(stat: Stats): string {
  return [stat.dev, stat.ino, stat.size, stat.mtimeMs, stat.ctimeMs].map(String).join(':');
}

/** The login file's fingerprint from `lstat` alone, or 'absent' when there is no file. */
export function codexAuthFingerprint(codexHome: string): string {
  try {
    return fingerprintOf(lstatSync(codexAuthPath(codexHome)));
  } catch {
    return 'absent';
  }
}

function reviveAuth(field: string, value: unknown): unknown {
  if (DROPPED.has(field)) return undefined;
  if (PRESENCE.has(field)) return value !== null;
  return value;
}

function readBounded(fd: number): string | undefined {
  const buffer = Buffer.alloc(CODEX_AUTH_MAX_BYTES + 1);
  try {
    let filled = 0;
    while (filled < buffer.length) {
      const chunk = readSync(fd, buffer, filled, buffer.length - filled, filled);
      if (chunk === 0) break;
      filled += chunk;
    }
    if (filled > CODEX_AUTH_MAX_BYTES) return undefined;
    return new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, filled));
  } catch {
    return undefined;
  } finally {
    buffer.fill(0);
  }
}

function idTokenClaims(jwtText: string): Record<string, unknown> | undefined {
  const segments = jwtText.split('.');
  if (segments.length !== 3 || segments.some((segment) => segment === '')) return undefined;
  const payload = segments[1];
  if (payload === undefined || !BASE64URL.test(payload) || payload.length % 4 === 1)
    return undefined;
  const bytes = Buffer.from(payload, 'base64url');
  let decoded: string;
  try {
    if (bytes.length > CODEX_ID_TOKEN_PAYLOAD_MAX_BYTES) return undefined;
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  } finally {
    bytes.fill(0);
  }
  let claims: unknown;
  try {
    claims = JSON.parse(decoded);
  } catch {
    return undefined;
  }
  return isRecord(claims) ? claims : undefined;
}

function parseAuth(
  content: string,
  attachedUserDigest: string | undefined,
  fingerprint: string,
): CodexLoginRead {
  let root: unknown;
  try {
    root = JSON.parse(content, reviveAuth);
  } catch {
    return MALFORMED;
  }
  if (!isRecord(root)) return MALFORMED;
  const parsed = root;
  const mode = pick(parsed, 'auth_mode');
  const otherLogin = CODEX_PRESENCE_FIELDS.some((field) => pick(parsed, field) === true);
  const chatgpt = mode === 'chatgpt' || ((mode === undefined || mode === null) && !otherLogin);
  if (!chatgpt) return MODE;
  const saved = pick(parsed, 'tokens');
  if (!isRecord(saved)) return MALFORMED;
  const savedAccount = pick(saved, 'account_id');
  const jwtText = pick(saved, 'id_token');
  if (typeof savedAccount !== 'string' || typeof jwtText !== 'string') return MALFORMED;
  if (jwtText.length > CODEX_ID_TOKEN_MAX_CHARS) return MALFORMED;
  const claims = idTokenClaims(jwtText);
  if (claims === undefined) return MALFORMED;
  const authClaims = pick(claims, AUTH_CLAIMS);
  const auth = isRecord(authClaims) ? authClaims : {};
  const accountClaim = pick(auth, 'chatgpt_account_id');
  if (
    typeof accountClaim !== 'string' ||
    accountClaim !== savedAccount ||
    !UUID.test(accountClaim)
  ) {
    return MALFORMED;
  }
  if (pick(claims, 'email_verified') === false) return MALFORMED;
  const topEmail = pick(claims, 'email');
  if (topEmail !== undefined && typeof topEmail !== 'string') return MALFORMED;
  const profile = pick(claims, PROFILE_CLAIMS);
  const profileEmail = isRecord(profile) ? pick(profile, 'email') : undefined;
  const email =
    typeof topEmail === 'string'
      ? topEmail
      : typeof profileEmail === 'string'
        ? profileEmail
        : undefined;
  return {
    status: 'ok',
    login: {
      accountId: accountClaim.toLowerCase(),
      emailMatchesAttached:
        attachedUserDigest !== undefined && emailMatchesAttached(email, attachedUserDigest),
      planState: chatgptPlanState(pick(auth, 'chatgpt_plan_type')),
      fingerprint,
    },
  };
}

/**
 * Codex's login, with the reason it is not a usable ChatGPT one: no file,
 * another login mode, or anything malformed (a symlink, a loose mode, a
 * foreign owner, an oversized, torn or non-UTF-8 file, or a bad id_token).
 * Windows has no uid and no meaningful mode bits, so there only the symlink
 * refusal applies; `platform` is the running one except in tests.
 */
export function inspectCodexLogin(
  codexHome: string,
  attachedUserDigest: string | undefined,
  platform: NodeJS.Platform = process.platform,
): CodexLoginRead {
  const path = codexAuthPath(codexHome);
  let fd: number;
  try {
    if (platform === 'win32' && lstatSync(path).isSymbolicLink()) return MALFORMED;
    fd = openSync(path, constants.O_RDONLY | NOFOLLOW);
  } catch (error) {
    return isNotFound(error) ? ABSENT : MALFORMED;
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size > CODEX_AUTH_MAX_BYTES) return MALFORMED;
    if (platform !== 'win32' && (stat.uid !== process.getuid?.() || (stat.mode & 0o022) !== 0)) {
      return MALFORMED;
    }
    const content = readBounded(fd);
    if (content === undefined) return MALFORMED;
    return parseAuth(content, attachedUserDigest, fingerprintOf(stat));
  } catch {
    return MALFORMED;
  } finally {
    try {
      closeSync(fd);
    } catch {
      // already closed
    }
  }
}

/** The login when it is a usable ChatGPT one, else undefined. */
export function readCodexLogin(
  codexHome: string,
  attachedUserDigest: string | undefined,
): CodexLogin | undefined {
  const read = inspectCodexLogin(codexHome, attachedUserDigest);
  return read.status === 'ok' ? read.login : undefined;
}
