import { randomUUID } from 'node:crypto';
import type * as Fs from 'node:fs';
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  CODEX_ACCOUNT_ENV_NAMES,
  CODEX_CREDENTIAL_ENV,
  readCodexAccountEnv,
  resolveCodexHome,
} from '../../src/account/account-env.ts';
import { readCodexHead } from '../../src/account/codex-head.ts';
import type { CodexLogin } from '../../src/account/codex-login.ts';
import {
  CODEX_AUTH_MAX_BYTES,
  CODEX_DROPPED_FIELDS,
  CODEX_PRESENCE_FIELDS,
  codexAuthFingerprint,
  COMPANY_CHATGPT_PLANS,
  inspectCodexLogin,
  readCodexLogin,
} from '../../src/account/codex-login.ts';
import type { CodexMachine } from '../helpers/fake-jwt.ts';
import { codexClaims, codexMachine, fakeJwt, standardAlphabetJwt } from '../helpers/fake-jwt.ts';
import { fixtureEmail, otherHost } from '../helpers/transcript-builder.ts';

const opened = vi.hoisted(() => ({ paths: [] as string[] }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof Fs>();
  return {
    ...actual,
    openSync: (...args: Parameters<typeof actual.openSync>) => {
      opened.paths.push(String(args[0]));
      return actual.openSync(...args);
    },
  };
});

const COMPANY = [
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
];

let machine: CodexMachine;

beforeEach(() => {
  for (const name of CODEX_ACCOUNT_ENV_NAMES) vi.stubEnv(name, undefined);
  machine = codexMachine();
  opened.paths.length = 0;
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  machine.dispose();
});

const digest = (): string => machine.context().attachedUserDigest;
const inspect = () => inspectCodexLogin(machine.codexHome, digest());

function login(): CodexLogin {
  const read = inspect();
  if (read.status !== 'ok') throw new Error(`expected a login, got ${read.status}`);
  return read.login;
}

const fingerprint = (): string => codexAuthFingerprint(machine.codexHome);

const validClaims = (): Record<string, unknown> =>
  codexClaims({ accountId: machine.accountId, email: machine.email, plan: 'team' });

describe('inspectCodexLogin', () => {
  it('reads the account, the email match, the plan state and the fingerprint, and nothing else', () => {
    machine.writeAuth({ accountId: machine.accountId.toUpperCase() });
    const read = login();
    expect(read).toEqual({
      accountId: machine.accountId,
      emailMatchesAttached: true,
      planState: 'company',
      fingerprint: fingerprint(),
    });
    expect(Object.keys(read).sort()).toEqual([
      'accountId',
      'emailMatchesAttached',
      'fingerprint',
      'planState',
    ]);
  });

  it('names exactly the company plan set', () => {
    expect([...COMPANY_CHATGPT_PLANS].sort()).toEqual([...COMPANY].sort());
  });

  it.each(COMPANY)('reads plan %s as a company plan', (plan) => {
    machine.writeAuth({ plan });
    expect(login().planState).toBe('company');
  });

  it.each([
    'enterprise_cbp_automation',
    'free',
    'go',
    'plus',
    'pro',
    'prolite',
    'promax',
    'Team',
    'ENTERPRISE',
    'a_plan_not_known_yet',
    7,
    null,
    true,
  ])('reads plan %j as other', (plan) => {
    machine.writeAuth({ plan });
    expect(login().planState).toBe('other');
  });

  it('reads a login with no plan claim as absent', () => {
    machine.writeAuth({ plan: undefined });
    expect(login().planState).toBe('absent');
  });

  it('accepts the email from the profile claim alone', () => {
    machine.writeAuth({ email: undefined, profileEmail: machine.email });
    expect(login().emailMatchesAttached).toBe(true);
  });

  it('matches an email that differs only in case', () => {
    machine.writeAuth({ email: machine.email.toUpperCase() });
    expect(login().emailMatchesAttached).toBe(true);
  });

  it.each([
    ['another address', () => fixtureEmail('someone-else')],
    ['a non-ASCII address', () => fixtureEmail('dév')],
  ])('does not match %s', (_, email) => {
    machine.writeAuth({ email: email() });
    expect(login().emailMatchesAttached).toBe(false);
  });

  it('refuses a top-level email that is not a string, and an unverified email', () => {
    machine.writeAuth({ email: 42 });
    expect(inspect()).toEqual({ status: 'malformed' });
    machine.writeAuth({ emailVerified: false });
    expect(inspect()).toEqual({ status: 'malformed' });
  });

  it.each([['chatgpt'], [null]] as const)('reads login mode %j as a ChatGPT login', (authMode) => {
    machine.writeAuth({ authMode });
    expect(inspect().status).toBe('ok');
  });

  it.each(['apikey', 'chatgptAuthTokens', 'personal_access_token', 'agent_identity', 'bedrock'])(
    'refuses login mode %s',
    (authMode) => {
      machine.writeAuth({ authMode });
      expect(inspect()).toEqual({ status: 'mode' });
    },
  );

  it('refuses an absent mode beside an API key or another login kind, following Codex order', () => {
    machine.writeAuth({ authMode: null, apiKey: randomUUID() });
    expect(inspect()).toEqual({ status: 'mode' });
    for (const field of CODEX_PRESENCE_FIELDS.slice(1)) {
      machine.writeAuth({ authMode: null, extra: { [field]: { id: randomUUID() } } });
      expect(inspect(), field).toEqual({ status: 'mode' });
    }
  });

  it('refuses an account claim that differs from tokens.account_id', () => {
    machine.writeAuth({ claimAccountId: randomUUID() });
    expect(inspect()).toEqual({ status: 'malformed' });
  });

  it('refuses an account id that is not UUID-shaped, and a file with no account id', () => {
    machine.writeAuth({ accountId: ['acct', randomUUID()].join('-') });
    expect(inspect()).toEqual({ status: 'malformed' });
    machine.writeAuth({ extra: { tokens: { id_token: fakeJwt(validClaims()).token } } });
    expect(inspect()).toEqual({ status: 'malformed' });
  });

  it.each([2, 4])('refuses a jwt of %i segments, and one with an empty segment', (count) => {
    const jwt = fakeJwt(validClaims());
    const parts = [jwt.header, jwt.payload, jwt.signature, jwt.signature].slice(0, count);
    machine.writeAuth({ idToken: parts.join('.') });
    expect(inspect()).toEqual({ status: 'malformed' });
    machine.writeAuth({ idToken: [jwt.header, '', jwt.signature].join('.') });
    expect(inspect()).toEqual({ status: 'malformed' });
  });

  it('refuses a padded payload and one in the standard base64 alphabet', () => {
    const jwt = fakeJwt(validClaims());
    machine.writeAuth({ idToken: [jwt.header, `${jwt.payload}==`, jwt.signature].join('.') });
    expect(inspect()).toEqual({ status: 'malformed' });
    machine.writeAuth({ idToken: standardAlphabetJwt(validClaims()) });
    expect(inspect()).toEqual({ status: 'malformed' });
  });

  it('refuses a payload that is not UTF-8, not an object or over 8 KiB, and a jwt over 16 KiB', () => {
    const jwt = fakeJwt({});
    for (const bytes of [
      Buffer.from([0xff, 0xfe, 0xfd]),
      Buffer.from('[1,2]'),
      Buffer.from(JSON.stringify({ pad: 'x'.repeat(9 * 1024) })),
    ]) {
      machine.writeAuth({
        idToken: [jwt.header, bytes.toString('base64url'), jwt.signature].join('.'),
      });
      expect(inspect()).toEqual({ status: 'malformed' });
    }
    machine.writeAuth({ idToken: [jwt.header, 'A'.repeat(17 * 1024), jwt.signature].join('.') });
    expect(inspect()).toEqual({ status: 'malformed' });
  });

  it('answers absent for a missing file, malformed for a torn, oversized or non-UTF-8 one', () => {
    expect(inspect()).toEqual({ status: 'absent' });
    const path = join(machine.codexHome, 'auth.json');
    mkdirSync(machine.codexHome, { recursive: true });
    for (const content of [
      '{"auth_mode": "chatgpt", "tokens": {',
      JSON.stringify({ pad: 'x'.repeat(CODEX_AUTH_MAX_BYTES) }),
      Buffer.from([0x7b, 0xff, 0x7d]),
    ]) {
      writeFileSync(path, content, { mode: 0o600 });
      expect(inspect()).toEqual({ status: 'malformed' });
    }
  });

  it.skipIf(process.platform === 'win32')(
    'refuses a symlink, a group-writable file and one another user owns',
    () => {
      const written = machine.writeAuth();
      const target = join(machine.root, 'elsewhere.json');
      writeFileSync(target, readFileSync(written.path), { mode: 0o600 });
      rmSync(written.path);
      symlinkSync(target, written.path);
      expect(inspect()).toEqual({ status: 'malformed' });
      rmSync(written.path);
      const again = machine.writeAuth();
      chmodSync(again.path, 0o620);
      expect(inspect()).toEqual({ status: 'malformed' });
      chmodSync(again.path, 0o600);
      expect(inspect().status).toBe('ok');
      const self = process.getuid?.() ?? 0;
      vi.spyOn(process as { getuid: () => number }, 'getuid').mockReturnValue(self + 1);
      expect(inspect()).toEqual({ status: 'malformed' });
    },
  );

  it('on win32 skips the owner and mode checks, and still refuses a symlink', () => {
    const written = machine.writeAuth();
    const onWindows = () => inspectCodexLogin(machine.codexHome, digest(), 'win32');
    chmodSync(written.path, 0o666);
    expect(onWindows().status).toBe('ok');
    if (process.platform !== 'win32') {
      expect(inspect()).toEqual({ status: 'malformed' });
      const self = process.getuid?.() ?? 0;
      vi.spyOn(process as { getuid: () => number }, 'getuid').mockReturnValue(self + 1);
      expect(onWindows().status).toBe('ok');
      vi.restoreAllMocks();
      const target = join(machine.root, 'elsewhere.json');
      writeFileSync(target, readFileSync(written.path), { mode: 0o600 });
      rmSync(written.path);
      symlinkSync(target, written.path);
      expect(onWindows()).toEqual({ status: 'malformed' });
    }
  });
});

describe('the Codex environment', () => {
  it.each(CODEX_CREDENTIAL_ENV)(
    'reads a non-empty %s as a credential and keeps no value',
    (name) => {
      const value = randomUUID();
      vi.stubEnv(name, value);
      const env = readCodexAccountEnv();
      expect(env.credentialEnv).toBe(true);
      expect(JSON.stringify(env)).not.toContain(value);
    },
  );

  it('reads a gateway base URL as a gateway, and the default API as none', () => {
    vi.stubEnv('OPENAI_BASE_URL', ['https:', '', otherHost(), 'v1'].join('/'));
    expect(readCodexAccountEnv().gateway).toBe(true);
    vi.stubEnv('OPENAI_BASE_URL', 'https://api.openai.com');
    expect(readCodexAccountEnv().gateway).toBe(false);
  });

  it('resolves the home override when it is a directory, and the default when unset or empty', () => {
    const relocated = join(machine.root, 'codex-home');
    if (process.platform === 'win32') expect(relocated).toMatch(/^[A-Za-z]:\\/);
    mkdirSync(relocated);
    vi.stubEnv('CODEX_HOME', relocated);
    expect(resolveCodexHome(readCodexAccountEnv(), machine.home)).toBe(realpathSync(relocated));
    vi.stubEnv('CODEX_HOME', join(machine.root, 'missing'));
    expect(resolveCodexHome(readCodexAccountEnv(), machine.home)).toBeUndefined();
    const file = join(machine.root, 'a-file');
    writeFileSync(file, '');
    vi.stubEnv('CODEX_HOME', file);
    expect(resolveCodexHome(readCodexAccountEnv(), machine.home)).toBeUndefined();
    vi.stubEnv('CODEX_HOME', '');
    expect(resolveCodexHome(readCodexAccountEnv(), machine.home)).toBe(machine.codexHome);
  });
});

describe('the login file fingerprint', () => {
  it('is stable until the file changes, and absent with the file gone', () => {
    const written = machine.writeAuth();
    const first = fingerprint();
    expect(first).toMatch(/^\d+:\d+:\d+:[\d.]+:[\d.]+$/);
    expect(fingerprint()).toBe(first);
    machine.writeAuth();
    expect(fingerprint()).not.toBe(first);
    rmSync(written.path);
    expect(fingerprint()).toBe('absent');
  });
});

describe('no token is kept', () => {
  it('a fake access token is never retained', () => {
    const written = machine.writeAuth();
    const parse = vi.spyOn(JSON, 'parse');
    const read = readCodexLogin(machine.codexHome, digest());
    const results = JSON.stringify(parse.mock.results.map((result) => result.value as unknown));
    parse.mockRestore();
    for (const hidden of written.secrets) {
      expect(results).not.toContain(hidden);
      expect(JSON.stringify(read)).not.toContain(hidden);
    }
    expect(read?.accountId).toBe(machine.accountId);
  });

  it('a malformed file returns undefined with nothing thrown or logged', () => {
    mkdirSync(machine.codexHome, { recursive: true });
    const hidden = ['fixture', randomUUID()].join('-');
    const torn = JSON.stringify({ tokens: { [CODEX_DROPPED_FIELDS[1]]: hidden } }).slice(0, -2);
    writeFileSync(join(machine.codexHome, 'auth.json'), torn, { mode: 0o600 });
    const spies = [
      vi.spyOn(console, 'error'),
      vi.spyOn(console, 'warn'),
      vi.spyOn(console, 'log'),
      vi.spyOn(console, 'info'),
      vi.spyOn(console, 'debug'),
      vi.spyOn(process.stderr, 'write'),
    ];
    let read: unknown = 'not called';
    expect(() => {
      read = readCodexLogin(machine.codexHome, digest());
    }).not.toThrow();
    expect(read).toBeUndefined();
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });

  it('header and signature are never decoded', () => {
    const written = machine.writeAuth();
    const from = vi.spyOn(Buffer, 'from');
    readCodexLogin(machine.codexHome, digest());
    const decoded = from.mock.calls
      .map((call) => call as unknown[])
      .filter((call) => call[1] === 'base64url' || call[1] === 'base64')
      .map((call) => call[0]);
    from.mockRestore();
    expect(decoded).toEqual([written.jwt.payload]);
  });

  it('only auth.json and the transcript are opened, and no child_process or network module is imported', () => {
    machine.writeAuth();
    machine.writeHead();
    opened.paths.length = 0;
    readCodexHead(machine.rollout);
    readCodexLogin(machine.codexHome, digest());
    expect([...new Set(opened.paths)].sort()).toEqual(
      [join(machine.codexHome, 'auth.json'), machine.rollout].sort(),
    );
    const banned = /from '(?:node:)?(?:child_process|net|http|https|http2|tls|dgram)'/;
    for (const file of ['account-env.ts', 'codex-head.ts', 'codex-login.ts', 'codex-validate.ts']) {
      const source = readFileSync(new URL(`../../src/account/${file}`, import.meta.url), 'utf8');
      expect(source, file).not.toMatch(banned);
    }
  });
});
