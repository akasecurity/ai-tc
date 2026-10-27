// The environment variables the hook client forwards to the hook server. Plain
// data with no imports, because the build reads it before anything is bundled:
// the client script is generated from it. A test holds it equal to the lists
// the account checks read (request-env.test.ts).

/** Set only while the host serves a Remote Control connection (see remote-session.ts). */
export const REMOTE_CONTROL_ENV = 'CLAUDE_CODE_BRIDGE_SESSION_ID';

/** Forwarded with their value. */
export const VALUE_ENV: readonly string[] = [
  'ANTHROPIC_BASE_URL',
  'CLAUDE_CODE_USE_BEDROCK',
  'CLAUDE_CODE_USE_VERTEX',
  'CLAUDE_CODE_USE_FOUNDRY',
  'CLAUDE_CODE_USE_ANTHROPIC_AWS',
  'CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD',
  'CLAUDE_CODE_USE_MANTLE',
  'CLAUDE_CODE_ORGANIZATION_UUID',
  'CLAUDE_CODE_USER_EMAIL',
  'CLAUDE_CONFIG_DIR',
  'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB',
  REMOTE_CONTROL_ENV,
];

/** Credentials: the hook tests them for presence only, so only a marker is forwarded. */
export const PRESENCE_ONLY_ENV: readonly string[] = [
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_AUTH_TOKEN',
  'CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR',
  'ANTHROPIC_UNIX_SOCKET',
];

/** Every forwarded variable. */
export const FORWARDED_ENV: readonly string[] = [...VALUE_ENV, ...PRESENCE_ONLY_ENV];
