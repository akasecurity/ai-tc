import { normalizeAccountEmail } from '@akasecurity/schema';

import { DEFAULT_ANTHROPIC_HOST } from '../provider-env.ts';

// The one module under src/account that reads process.env, for the Claude Code
// account check. Values stay in the returned object, in memory; a credential
// variable is read for non-empty presence only.

/** Variables whose non-empty value bills a Claude Code session to a key or token. */
export const CLAUDE_CREDENTIAL_ENV = [
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_AUTH_TOKEN',
  'CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR',
  'ANTHROPIC_UNIX_SOCKET',
] as const;

/** Flags that route Claude Code to a provider other than its claude.ai login. */
export const CLAUDE_PROVIDER_FLAG_ENV = [
  'CLAUDE_CODE_USE_BEDROCK',
  'CLAUDE_CODE_USE_VERTEX',
  'CLAUDE_CODE_USE_FOUNDRY',
  'CLAUDE_CODE_USE_ANTHROPIC_AWS',
  'CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD',
  'CLAUDE_CODE_USE_MANTLE',
] as const;

export const CLAUDE_BASE_URL_ENV = 'ANTHROPIC_BASE_URL';

/** Every variable readClaudeAccountEnv reads. */
export const CLAUDE_ACCOUNT_ENV_NAMES = [
  ...CLAUDE_CREDENTIAL_ENV,
  ...CLAUDE_PROVIDER_FLAG_ENV,
  CLAUDE_BASE_URL_ENV,
  'CLAUDE_CODE_ORGANIZATION_UUID',
  'CLAUDE_CODE_USER_EMAIL',
  'CLAUDE_CONFIG_DIR',
  'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB',
] as const;

/** A set, non-empty string. */
export function isPresent(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

/** The host's flag reading: only 1, true, yes and on turn a flag on. */
export function isTruthyFlag(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const flag = value.trim().toLowerCase();
  return flag === '1' || flag === 'true' || flag === 'yes' || flag === 'on';
}

/**
 * True when a base URL sends requests anywhere but the default API: not https,
 * another host or port, credentials, a path, a query or a fragment. An unset
 * or empty value, and the default URL itself, are not.
 */
export function isNonDefaultBaseUrl(value: unknown): boolean {
  if (!isPresent(value)) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return true;
  }
  return (
    url.protocol !== 'https:' ||
    url.host !== DEFAULT_ANTHROPIC_HOST ||
    url.username !== '' ||
    url.password !== '' ||
    url.pathname !== '/' ||
    url.search !== '' ||
    url.hash !== ''
  );
}

/** What the Claude Code account check reads from the environment. */
export interface ClaudeAccountEnv {
  readonly configDir: string | undefined;
  readonly orgPresent: boolean;
  /** The trimmed, lower-cased organization id the desktop host passes. */
  readonly org: string | undefined;
  readonly emailPresent: boolean;
  /** The desktop host's login email, normalised; undefined when it does not normalise. */
  readonly email: string | undefined;
  readonly credentialEnv: boolean;
  readonly providerFlag: boolean;
  readonly baseUrlVeto: boolean;
  readonly envScrub: boolean;
}

// A read that throws answers a veto, so nothing counts as work.
const UNREADABLE_CLAUDE_ENV: ClaudeAccountEnv = {
  configDir: undefined,
  orgPresent: false,
  org: undefined,
  emailPresent: false,
  email: undefined,
  credentialEnv: true,
  providerFlag: false,
  baseUrlVeto: false,
  envScrub: true,
};

export function readClaudeAccountEnv(): ClaudeAccountEnv {
  try {
    const env = process.env;
    const configDir = env.CLAUDE_CONFIG_DIR;
    const org = env.CLAUDE_CODE_ORGANIZATION_UUID;
    const email = env.CLAUDE_CODE_USER_EMAIL;
    return {
      configDir: isPresent(configDir) ? configDir : undefined,
      orgPresent: isPresent(org),
      org: isPresent(org) ? org.trim().toLowerCase() : undefined,
      emailPresent: isPresent(email),
      email: isPresent(email) ? normalizeAccountEmail(email) : undefined,
      credentialEnv: CLAUDE_CREDENTIAL_ENV.some((name) => isPresent(env[name])),
      providerFlag: CLAUDE_PROVIDER_FLAG_ENV.some((name) => isTruthyFlag(env[name])),
      baseUrlVeto: isNonDefaultBaseUrl(env[CLAUDE_BASE_URL_ENV]),
      envScrub: isTruthyFlag(env.CLAUDE_CODE_SUBPROCESS_ENV_SCRUB),
    };
  } catch {
    return UNREADABLE_CLAUDE_ENV;
  }
}
