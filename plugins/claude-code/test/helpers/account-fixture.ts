// A personal device for the account tests. A temp home holds AKA's settings, a
// credential and its attached-identity record, a migrated store, Claude Code's
// login file, two checkouts and the session transcripts. The hooks open the
// gateway the plugin's own factory builds, over the suite's recording transport.
import { randomUUID } from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  forgetWorkAccounts,
  readAttachedIdentity,
  readControlPlaneCredential,
  sessionAccountsDir,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import {
  createPolicyStore,
  HISTORY_SYNC_MARKER_NAME,
  HISTORY_SYNC_THROTTLE_MS,
  SYNC_MARKER_NAME,
  SYNC_THROTTLE_MS,
} from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { loadConfig, throttled } from '@akasecurity/plugin-sdk';
import { appendObservation } from '@akasecurity/plugin-sdk/account';
import { defaultWorkspaceSettings } from '@akasecurity/schema';
import { vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { Sent } from './recording-client.ts';
import { migratedStore } from './store-templates.ts';

export const ENDPOINT = 'https://plane.example.test';
export const TENANT = 'Example Org';
export const USER_EMAIL = 'dev@example.com';
export const OTHER_EMAIL = 'colleague@example.com';
export const OTHER_TEST_KEY = 'not-a-real-key-either';
export const WORK_KEY = 'github.com/example-org/work';
export const PERSONAL_KEY = 'github.com/example-dev/notes';
const TEST_KEY = 'not-a-real-key';
const ATTACHED_AT = '2026-01-15T09:00:00.000Z';
const WORK_ORIGIN = 'https://github.com/example-org/work.git';
const PERSONAL_ORIGIN = 'https://github.com/example-dev/notes.git';
const CLAUDE_VERSION = '2.1.300';

// The variables the Claude Code readers consult. Each is blanked so the host
// running this suite (a terminal inside Claude Code, say) cannot veto a login
// or disagree with the login file.
const CLAUDE_ENV = [
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_AUTH_TOKEN',
  'ANTHROPIC_BASE_URL',
  'ANTHROPIC_UNIX_SOCKET',
  'CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR',
  'CLAUDE_CODE_OAUTH_TOKEN',
  'CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR',
  'CLAUDE_CODE_USE_BEDROCK',
  'CLAUDE_CODE_USE_VERTEX',
  'CLAUDE_CODE_USE_FOUNDRY',
  'CLAUDE_CODE_USE_ANTHROPIC_AWS',
  'CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD',
  'CLAUDE_CODE_USE_MANTLE',
  'CLAUDE_CODE_ORGANIZATION_UUID',
  'CLAUDE_CODE_USER_EMAIL',
  'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB',
] as const;

/** One row of the local store's audit_events, as the assertions read it. */
export interface StoredRow {
  id: string;
  eventType: string;
  scopeKey: string | null;
}

export interface AttachOptions {
  readonly mode?: 'scoped' | 'machine';
  /** Repository keys enrolled; WORK_KEY when omitted. */
  readonly enrolled?: readonly string[];
  /** Account keys enrolled by hand, each marked for coding agents. */
  readonly manual?: readonly string[];
  readonly userEmail?: string;
  readonly apiKey?: string;
  readonly workSubscriptions?: 'off' | undefined;
  /** What a redact resolves to on a field that cannot be rewritten; the default (`warn`) when omitted. */
  readonly redactFallback?: 'block';
  /** False: no attached-identity record yet, as when the background sync has not asked. */
  readonly identity?: boolean;
}

export interface LoginOptions {
  readonly org: string;
  readonly email?: string;
  /** `claude_team` when omitted; null writes no organizationType at all. */
  readonly organizationType?: string | null;
  /** The Claude config dir the login file is written to; the home when omitted. */
  readonly configDir?: string;
}

/** One session's transcript, written line by line as the host writes it. */
export interface Transcript {
  readonly sessionId: string;
  readonly path: string;
  /** A user prompt; returns its uuid. */
  prompt(at: string, cwd?: string): string;
  /** The host's per-request copy of the session's organization. */
  org(organizationUuid: string, at: string): void;
  /** An assistant reply to the last prompt; returns its uuid. */
  reply(at: string, cwd?: string): string;
}

export interface Device {
  readonly root: string;
  /** The user's home: HOME, `.claude.json` and the transcripts live under it. */
  readonly home: string;
  /** `~/.aka` */
  readonly base: string;
  readonly dataDir: string;
  readonly workOrg: string;
  readonly personalOrg: string;
  /** A checkout of the enrolled repository. */
  readonly work: string;
  /** A checkout of a repository nobody enrolled. */
  readonly personal: string;
  /** What the suite's recording transport was handed. */
  readonly sent: Sent;
  config(): PluginConfig;
  attach(options?: AttachOptions): void;
  /** Writes the attached-identity record the background sync writes for the last attach. */
  writeIdentity(): void;
  login(options: LoginOptions): void;
  /** Writes a login file that does not parse. */
  unreadableLogin(): void;
  transcript(sessionId: string): Transcript;
  /** The `startup` boundary a session start records, and nothing else. */
  boundary(t: Transcript): void;
  optOut(): void;
  optIn(): void;
  /** Caches an organization policy that prohibits `models`, as the policy pull does. */
  prohibit(models: readonly string[]): Promise<void>;
  learnedKeys(): string[];
  sessionState(sessionId: string): { log: string; scanCache: boolean };
  storedRows(): StoredRow[];
  dispose(): void;
}

/** Whether `key` is an agent key for the Claude organization `org`. */
export function isAgentKeyFor(key: unknown, org: string): boolean {
  return typeof key === 'string' && key.startsWith('agent:') && key.endsWith(`:claude:${org}`);
}

function checkout(root: string, name: string, origin: string): string {
  const dir = join(root, name);
  mkdirSync(join(dir, '.git'), { recursive: true });
  writeFileSync(
    join(dir, '.git', 'config'),
    `[core]\n\tbare = false\n[remote "origin"]\n\turl = ${origin}\n`,
  );
  return dir;
}

/** A fresh device whose attached gateway sends to `sent`, the suite's recording transport. */
export function device(sent: Sent): Device {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'aka-account-')));
  const home = join(root, 'home');
  const base = join(home, '.aka');
  const dataDir = dataDirOf(base);
  const settingsDir = settingsDirOf(base);
  mkdirSync(home, { recursive: true });
  migratedStore.seed(dataDir);
  vi.stubEnv('HOME', home);
  vi.stubEnv('USERPROFILE', home);
  vi.stubEnv('CLAUDE_CONFIG_DIR', home);
  for (const name of CLAUDE_ENV) vi.stubEnv(name, '');
  sent.captures.length = 0;
  sent.audit.length = 0;
  sent.inventory.length = 0;
  let lastAttach: AttachOptions = {};

  const writeSettings = (options: AttachOptions): void => {
    const entries = [
      ...(options.enrolled ?? [WORK_KEY]).map((identity) => ({
        kind: 'repo',
        identity,
        enrolledAt: ATTACHED_AT,
      })),
      ...(options.manual ?? []).map((identity) => ({
        kind: 'account',
        identity,
        enrolledAt: ATTACHED_AT,
        codingAgents: true,
      })),
    ];
    const settings = {
      ...defaultWorkspaceSettings(),
      ...(options.redactFallback === undefined ? {} : { redactFallback: options.redactFallback }),
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: ATTACHED_AT },
      attachmentScope: {
        endpoint: ENDPOINT,
        tenantName: TENANT,
        userEmail: options.userEmail ?? USER_EMAIL,
        entries,
        ...(options.workSubscriptions === undefined
          ? {}
          : { workSubscriptions: options.workSubscriptions }),
      },
    };
    mkdirSync(settingsDir, { recursive: true });
    writeFileSync(join(settingsDir, 'settings.json'), JSON.stringify(settings), { mode: 0o600 });
  };

  const writeIdentity = (): void => {
    writeAttachedIdentity(dataDir, {
      endpoint: ENDPOINT,
      apiKey: lastAttach.apiKey ?? TEST_KEY,
      tenantName: TENANT,
      userEmail: lastAttach.userEmail ?? USER_EMAIL,
      source: 'whoami',
    });
  };

  const credentialOf = () => {
    const credential = readControlPlaneCredential(settingsDir, {
      endpoint: ENDPOINT,
      attachedAt: ATTACHED_AT,
    });
    if (credential === null) throw new Error('the fixture holds no usable credential');
    return credential;
  };

  return {
    root,
    home,
    base,
    dataDir,
    workOrg: randomUUID(),
    personalOrg: randomUUID(),
    work: checkout(root, 'work', WORK_ORIGIN),
    personal: checkout(root, 'notes', PERSONAL_ORIGIN),
    sent,
    config: () => loadConfig(),
    attach(options = {}) {
      lastAttach = options;
      const apiKey = options.apiKey ?? TEST_KEY;
      writeControlPlaneCredential(
        settingsDir,
        options.mode === 'machine'
          ? { specVersion: 1, endpoint: ENDPOINT, apiKey, mintedAt: ATTACHED_AT }
          : { specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey, mintedAt: ATTACHED_AT },
      );
      writeSettings(options);
      if (options.mode !== 'machine' && options.identity !== false) {
        writeAttachedIdentity(dataDir, {
          endpoint: ENDPOINT,
          apiKey,
          tenantName: TENANT,
          userEmail: options.userEmail ?? USER_EMAIL,
        });
      }
      // Throttle markers stamped now, so a session start spawns no sync child.
      throttled(dataDir, SYNC_MARKER_NAME, SYNC_THROTTLE_MS);
      throttled(dataDir, HISTORY_SYNC_MARKER_NAME, HISTORY_SYNC_THROTTLE_MS);
    },
    writeIdentity,
    login(options) {
      const organizationType =
        options.organizationType === undefined ? 'claude_team' : options.organizationType;
      const configDir = options.configDir ?? home;
      mkdirSync(configDir, { recursive: true });
      writeFileSync(
        join(configDir, '.claude.json'),
        JSON.stringify({
          oauthAccount: {
            organizationUuid: options.org,
            emailAddress: options.email ?? USER_EMAIL,
            ...(organizationType === null ? {} : { organizationType }),
          },
        }),
      );
    },
    unreadableLogin() {
      writeFileSync(join(home, '.claude.json'), '{"oauthAccount":');
    },
    transcript(sessionId) {
      const dir = join(home, '.claude', 'projects', 'example');
      mkdirSync(dir, { recursive: true });
      const path = join(dir, `${sessionId}.jsonl`);
      writeFileSync(path, '');
      let lastPrompt: { uuid: string; promptId: string } | undefined;
      const line = (record: Record<string, unknown>): void => {
        appendFileSync(path, `${JSON.stringify(record)}\n`);
      };
      const personal = join(root, 'notes');
      return {
        sessionId,
        path,
        prompt(at, cwd = personal) {
          lastPrompt = { uuid: randomUUID(), promptId: randomUUID() };
          line({
            type: 'user',
            sessionId,
            uuid: lastPrompt.uuid,
            promptId: lastPrompt.promptId,
            timestamp: at,
            cwd,
            message: { role: 'user', content: 'a prompt' },
          });
          return lastPrompt.uuid;
        },
        org(organizationUuid, at) {
          line({
            type: 'attachment',
            sessionId,
            uuid: randomUUID(),
            timestamp: at,
            attachment: { type: 'credential_org', organizationUuid },
          });
        },
        reply(at, cwd = personal) {
          const uuid = randomUUID();
          line({
            type: 'assistant',
            sessionId,
            uuid,
            parentUuid: lastPrompt?.uuid,
            timestamp: at,
            cwd,
            version: CLAUDE_VERSION,
            gitBranch: 'main',
            entrypoint: 'cli',
            message: {
              id: `msg_${uuid}`,
              model: 'claude-sonnet-4-5-20250929',
              content: [{ type: 'text', text: 'done' }],
              usage: { input_tokens: 12, output_tokens: 7 },
            },
          });
          return uuid;
        },
      };
    },
    boundary(t) {
      appendObservation(sessionAccountsDir(dataDir), t.sessionId, { t: Date.now(), b: 'startup' });
    },
    optOut() {
      writeSettings({ ...lastAttach, workSubscriptions: 'off' });
      forgetWorkAccounts(dataDir, { endpoint: ENDPOINT, credential: credentialOf() });
    },
    optIn() {
      writeSettings({ ...lastAttach, workSubscriptions: undefined });
    },
    prohibit(models) {
      return createPolicyStore(dataDir).write({
        version: 'test',
        policies: [],
        customKeywords: [],
        prohibitedModels: [...models],
        fetchedAt: new Date().toISOString(),
      });
    },
    learnedKeys: () => (readAttachedIdentity(dataDir)?.workAccounts ?? []).map((e) => e.identity),
    sessionState(sessionId) {
      const dir = sessionAccountsDir(dataDir);
      const log = join(dir, `${sessionId}.log`);
      return {
        log: existsSync(log) ? readFileSync(log, 'utf8') : '',
        scanCache: existsSync(join(dir, `${sessionId}.scan.json`)),
      };
    },
    storedRows() {
      const db = new DatabaseSync(dbPathOf(base), { readOnly: true });
      try {
        return db
          .prepare(
            `SELECT id, event_type AS eventType, scope_key AS scopeKey
               FROM audit_events ORDER BY started_at, id`,
          )
          .all() as unknown as StoredRow[];
      } finally {
        db.close();
      }
    },
    dispose() {
      vi.unstubAllEnvs();
      removeTree(root);
    },
  };
}
