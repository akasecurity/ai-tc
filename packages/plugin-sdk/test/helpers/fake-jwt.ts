import { randomBytes, randomUUID } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { attachedUserDigestOf, sessionAccountsDir } from '@akasecurity/persistence';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { AccountContext } from '../../src/account/account-check.ts';
import {
  AUTH_CLAIMS,
  CODEX_DROPPED_FIELDS,
  CODEX_PRESENCE_FIELDS,
  PROFILE_CLAIMS,
} from '../../src/account/codex-login.ts';
import type { ContextOptions } from './transcript-builder.ts';
import { fixtureEmail, T0 } from './transcript-builder.ts';

// Codex login and rollout fixtures. A token is three base64url segments
// assembled at run time from the claims a case names: nothing token-shaped is
// committed, and no signature is made or checked.

const b64url = (text: string): string => Buffer.from(text, 'utf8').toString('base64url');

export interface FakeJwt {
  readonly header: string;
  readonly payload: string;
  readonly signature: string;
  readonly token: string;
}

export function fakeJwt(claims: Readonly<Record<string, unknown>>): FakeJwt {
  const header = b64url(JSON.stringify({ alg: 'none', typ: 'JWT', kid: randomUUID() }));
  const payload = b64url(JSON.stringify(claims));
  const signature = b64url(`sig-${randomUUID()}`);
  return { header, payload, signature, token: `${header}.${payload}.${signature}` };
}

/** The same claims with the payload in the standard base64 alphabet, so it carries a plus or a slash. */
export function standardAlphabetJwt(claims: Readonly<Record<string, unknown>>): string {
  for (let pad = 1; pad < 64; pad += 1) {
    const payload = Buffer.from(JSON.stringify({ ...claims, pad: '?>'.repeat(pad) }), 'utf8')
      .toString('base64')
      .replace(/=+$/, '');
    if (/[+/]/.test(payload)) return `${b64url('{}')}.${payload}.${b64url('sig')}`;
  }
  throw new Error('no standard-alphabet payload found');
}

export interface SessionMetaOptions {
  readonly sessionId: string;
  readonly creatorAccountId?: unknown;
  /** null leaves the provider out. */
  readonly modelProvider?: string | null;
  readonly originator?: string;
  readonly baseInstructionsBytes?: number;
  /** Name the session by `id` alone, leaving `session_id` out. */
  readonly idOnly?: boolean;
}

/** A rollout's first line, in the shape Codex writes for each new thread. */
export function sessionMetaLine(options: SessionMetaOptions): string {
  const at = new Date(T0).toISOString();
  const payload: Record<string, unknown> = {
    ...(options.idOnly === true ? {} : { session_id: options.sessionId }),
    id: options.idOnly === true ? options.sessionId : randomUUID(),
    timestamp: at,
    cwd: join(tmpdir(), 'codex-project'),
    originator: options.originator ?? 'codex_cli_rs',
    cli_version: '0.160.0',
    creator_user_id: `user-${randomUUID()}`,
    ...(options.creatorAccountId === undefined
      ? {}
      : { creator_account_id: options.creatorAccountId }),
    ...(options.modelProvider === null
      ? {}
      : { model_provider: options.modelProvider ?? 'openai' }),
    base_instructions: { text: 'x'.repeat(options.baseInstructionsBytes ?? 256) },
  };
  return JSON.stringify({ timestamp: at, type: 'session_meta', payload });
}

export interface CodexLoginFixture {
  readonly accountId?: string;
  /** The account claim, when it should differ from the account id. */
  readonly claimAccountId?: unknown;
  readonly email?: unknown;
  readonly profileEmail?: unknown;
  readonly emailVerified?: boolean;
  /** The plan claim; undefined leaves it out. */
  readonly plan?: unknown;
  /** The login mode field; null leaves it out. */
  readonly authMode?: string | null;
  /** The API-key field's value; absent writes null. */
  readonly apiKey?: string | null;
  readonly extra?: Readonly<Record<string, unknown>>;
  /** A token written in place of the one built from the claims. */
  readonly idToken?: string;
}

export interface CodexLoginWritten {
  readonly accountId: string;
  /** The two opaque values written in the fields a reader must never keep. */
  readonly secrets: readonly [string, string];
  readonly jwt: FakeJwt;
  readonly path: string;
}

/** The id_token claims, in the namespaces Codex reads them from. */
export function codexClaims(
  fixture: CodexLoginFixture & { readonly accountId: string },
): Record<string, unknown> {
  const auth: Record<string, unknown> = {
    chatgpt_account_id:
      fixture.claimAccountId === undefined ? fixture.accountId : fixture.claimAccountId,
  };
  if (fixture.plan !== undefined) auth.chatgpt_plan_type = fixture.plan;
  return {
    ...(fixture.email === undefined ? {} : { email: fixture.email }),
    ...(fixture.emailVerified === undefined ? {} : { email_verified: fixture.emailVerified }),
    ...(fixture.profileEmail === undefined
      ? {}
      : { [PROFILE_CLAIMS]: { email: fixture.profileEmail } }),
    [AUTH_CLAIMS]: auth,
  };
}

const opaque = (label: string): string => [label, randomUUID()].join('-');
let writes = 0;

/** Write the login file owner-only, with a fresh mtime so every write changes its fingerprint. */
export function writeCodexAuth(
  codexHome: string,
  fixture: CodexLoginFixture = {},
): CodexLoginWritten {
  const accountId = fixture.accountId ?? randomUUID();
  const jwt = fakeJwt(codexClaims({ ...fixture, accountId }));
  const [firstHidden, secondHidden] = CODEX_DROPPED_FIELDS;
  const [apiKeyField] = CODEX_PRESENCE_FIELDS;
  const secrets = [opaque('fixture-first'), opaque('fixture-second')] as const;
  const body: Record<string, unknown> = {
    ...(fixture.authMode === null ? {} : { auth_mode: fixture.authMode ?? 'chatgpt' }),
    [apiKeyField]: fixture.apiKey ?? null,
    tokens: {
      id_token: fixture.idToken ?? jwt.token,
      [firstHidden]: secrets[0],
      [secondHidden]: secrets[1],
      account_id: accountId,
    },
    last_refresh: new Date(T0).toISOString(),
    ...fixture.extra,
  };
  mkdirSync(codexHome, { recursive: true, mode: 0o700 });
  const path = join(codexHome, 'auth.json');
  writeFileSync(path, JSON.stringify(body, null, 2), { mode: 0o600 });
  chmodSync(path, 0o600);
  writes += 1;
  const stamp = new Date(T0 + writes * 1_000);
  utimesSync(path, stamp, stamp);
  return { accountId, secrets, jwt, path };
}

export interface CodexMachine {
  readonly root: string;
  readonly home: string;
  readonly codexHome: string;
  readonly dataDir: string;
  readonly stateDir: string;
  readonly rollout: string;
  readonly sessionId: string;
  readonly accountId: string;
  readonly email: string;
  readonly bindingHash: string;
  writeAuth(fixture?: CodexLoginFixture): CodexLoginWritten;
  writeHead(options?: Partial<SessionMetaOptions>): void;
  context(options?: ContextOptions): AccountContext;
  dispose(): void;
}

/** A home with its Codex directory, a rollout path for one thread and an AKA data dir, under one temp root. */
export function codexMachine(): CodexMachine {
  const root = mkdtempSync(join(tmpdir(), 'aka-codex-account-'));
  const home = join(root, 'home');
  const codexHome = join(home, '.codex');
  const dataDir = join(root, 'aka');
  for (const dir of [home, dataDir]) mkdirSync(dir, { recursive: true });
  const sessionId = randomUUID();
  const accountId = randomUUID();
  const email = fixtureEmail(`dev-${randomBytes(3).toString('hex')}`);
  const bindingHash = randomBytes(8).toString('hex');
  const rollout = join(codexHome, 'sessions', '2026', '01', '05', `rollout-${sessionId}.jsonl`);
  return {
    root,
    home,
    codexHome,
    dataDir,
    stateDir: sessionAccountsDir(dataDir),
    rollout,
    sessionId,
    accountId,
    email,
    bindingHash,
    writeAuth: (fixture = {}) =>
      writeCodexAuth(codexHome, { accountId, email, plan: 'team', ...fixture }),
    writeHead: (options = {}) => {
      mkdirSync(dirname(rollout), { recursive: true });
      writeFileSync(
        rollout,
        `${sessionMetaLine({ sessionId, creatorAccountId: accountId, ...options })}\n`,
      );
    },
    context: (options = {}) => {
      const digest = attachedUserDigestOf(options.email ?? email);
      if (digest === undefined) throw new Error('the fixture address does not normalise');
      return {
        bindingHash: options.bindingHash ?? bindingHash,
        attachedUserDigest: digest,
        workSubscriptionsOn: options.on ?? true,
        learned: (options.learned ?? []).map((identity) => ({
          kind: 'account' as const,
          identity,
          label: 'ChatGPT work account',
          enrolledAt: new Date(T0).toISOString(),
        })),
        manual: [...(options.manual ?? [])],
        inScope: options.inScope ?? (() => false),
      };
    },
    dispose: () => {
      removeTree(root);
    },
  };
}

/** The fixture address builder, re-exported so a Codex case needs one helper import. */
export { fixtureEmail };
