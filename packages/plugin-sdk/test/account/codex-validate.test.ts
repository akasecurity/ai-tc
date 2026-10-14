import { randomBytes, randomUUID } from 'node:crypto';
import type * as Fs from 'node:fs';
import { readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { AccountContext } from '../../src/account/account-check.ts';
import type { CodexAccountEnv } from '../../src/account/account-env.ts';
import { CODEX_ACCOUNT_ENV_NAMES } from '../../src/account/account-env.ts';
import { readCodexHead } from '../../src/account/codex-head.ts';
import { codexAuthFingerprint, inspectCodexLogin } from '../../src/account/codex-login.ts';
import type {
  CodexAccountCheck,
  CodexHookResult,
  CodexSessionSource,
} from '../../src/account/codex-validate.ts';
import {
  codexHookAccount,
  codexSessionAccount,
  codexThreadState,
  startCodexSession,
} from '../../src/account/codex-validate.ts';
import {
  appendObservation,
  classifyObservation,
  readObservations,
  sessionAccountHash,
} from '../../src/account/observation-log.ts';
import type { CodexLoginFixture, CodexMachine, SessionMetaOptions } from '../helpers/fake-jwt.ts';
import { codexMachine } from '../helpers/fake-jwt.ts';
import { fixtureEmail, T0 } from '../helpers/transcript-builder.ts';

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
  machine.dispose();
});

const workKey = (): string => `chatgpt:${machine.accountId}`;
const authOpens = (): number => opened.paths.filter((path) => path.endsWith('auth.json')).length;
const headOpens = (): number => opened.paths.filter((path) => path === machine.rollout).length;
const lines = () =>
  readObservations(machine.stateDir, machine.sessionId).entries.map((entry) =>
    classifyObservation(entry.observation),
  );
const stateBytes = (): string =>
  readdirSync(machine.stateDir)
    .map((name) => readFileSync(join(machine.stateDir, name), 'utf8'))
    .join('\n');

function sessionCheck(
  options: {
    readonly source?: Exclude<CodexSessionSource, 'compact'>;
    readonly env?: Partial<CodexAccountEnv>;
    readonly ctx?: AccountContext;
    readonly head?: Partial<SessionMetaOptions>;
    readonly auth?: CodexLoginFixture;
  } = {},
): CodexAccountCheck {
  machine.writeHead(options.head);
  machine.writeAuth(options.auth);
  const ctx = options.ctx ?? machine.context();
  return codexSessionAccount({
    source: options.source ?? 'startup',
    sessionId: machine.sessionId,
    env: { codexHome: undefined, credentialEnv: false, gateway: false, ...options.env },
    head: readCodexHead(machine.rollout),
    login: inspectCodexLogin(machine.codexHome, ctx.attachedUserDigest),
    ctx,
  });
}

// `null` is a machine with no bound identity record. An explicit `undefined`
// would take the default context instead.
function start(
  source: CodexSessionSource,
  ctx: AccountContext | null = machine.context(),
  final = false,
) {
  return startCodexSession({
    dataDir: machine.dataDir,
    sessionId: machine.sessionId,
    ctx: ctx ?? undefined,
    transcriptPath: machine.rollout,
    home: machine.home,
    now: () => T0,
    source,
    final,
  });
}

function later(ctx: AccountContext = machine.context(), at = T0 + 60_000): CodexHookResult {
  return codexHookAccount({
    dataDir: machine.dataDir,
    sessionId: machine.sessionId,
    ctx,
    transcriptPath: machine.rollout,
    home: machine.home,
    now: () => at,
  });
}

/** A thread that started validated, as a caller that then learned its key sees it. */
function workThread(): AccountContext {
  machine.writeHead();
  machine.writeAuth();
  expect(start('startup').check).toMatchObject({ key: workKey(), basis: 'validated' });
  return machine.context({ learned: [workKey()] });
}

describe('codexSessionAccount', () => {
  it('validates a ChatGPT workspace login on a fresh openai thread', () => {
    expect(sessionCheck()).toEqual({
      key: workKey(),
      basis: 'validated',
      authFingerprint: codexAuthFingerprint(machine.codexHome),
    });
  });

  it.each(COMPANY)('a workspace SKU validates: %s', (plan) => {
    expect(sessionCheck({ auth: { plan } })).toMatchObject({ basis: 'validated' });
  });

  it('refuses a resumed thread', () => {
    expect(sessionCheck({ source: 'resume' })).toEqual({ none: 'resumed' });
  });

  it.each([['credentialEnv'], ['gateway']] as const)('vetoes %s', (name) => {
    expect(sessionCheck({ env: { [name]: true } })).toEqual({ none: 'veto' });
  });

  it.each(['azure', 'ollama', null] as const)('refuses provider %j', (provider) => {
    expect(sessionCheck({ head: { modelProvider: provider } })).toEqual({ none: 'provider' });
  });

  it('refuses a head of another session, and one with no or a non-UUID account', () => {
    expect(sessionCheck({ head: { sessionId: randomUUID() } })).toEqual({
      none: 'no-session-account',
    });
    expect(sessionCheck({ head: { creatorAccountId: 'not-a-uuid' } })).toEqual({
      none: 'no-session-account',
    });
  });

  it('refuses another login mode and a malformed login, and answers absent with no file', () => {
    expect(sessionCheck({ auth: { authMode: 'apikey' } })).toEqual({ none: 'mode' });
    expect(sessionCheck({ auth: { claimAccountId: randomUUID() } })).toEqual({ none: 'malformed' });
    machine.writeHead();
    rmSync(join(machine.codexHome, 'auth.json'));
    const ctx = machine.context();
    expect(
      codexSessionAccount({
        source: 'startup',
        sessionId: machine.sessionId,
        env: { codexHome: undefined, credentialEnv: false, gateway: false },
        head: readCodexHead(machine.rollout),
        login: inspectCodexLogin(machine.codexHome, ctx.attachedUserDigest),
        ctx,
      }),
    ).toEqual({ none: 'absent' });
  });

  it('refuses a login whose account did not create the thread', () => {
    expect(sessionCheck({ head: { creatorAccountId: randomUUID() } })).toEqual({
      none: 'account-mismatch',
    });
  });

  it.each(['plus', 'pro', 'free', 'enterprise_cbp_automation', 'Team'])(
    'refuses plan %s on the automatic path',
    (plan) => {
      expect(sessionCheck({ auth: { plan } })).toEqual({ none: 'plan' });
    },
  );

  it('refuses a login with no plan claim on the automatic path', () => {
    expect(sessionCheck({ auth: { plan: undefined } })).toEqual({ none: 'plan' });
  });

  it('refuses another email', () => {
    expect(sessionCheck({ auth: { email: fixtureEmail('someone-else') } })).toEqual({
      none: 'email',
    });
  });

  it('a remembered org accepts a login with no plan claim', () => {
    expect(
      sessionCheck({ ctx: machine.context({ learned: [workKey()] }), auth: { plan: undefined } }),
    ).toMatchObject({
      key: workKey(),
      basis: 'remembered',
    });
  });

  it.each(['enterprise_cbp_automation', 'pro'])(
    'a remembered org refuses a service account or personal plan: %s',
    (plan) => {
      expect(
        sessionCheck({ ctx: machine.context({ learned: [workKey()] }), auth: { plan } }),
      ).toEqual({ none: 'plan' });
    },
  );

  it('a remembered org refuses another email', () => {
    const ctx = machine.context({ learned: [workKey()] });
    expect(sessionCheck({ ctx, auth: { email: fixtureEmail('someone-else') } })).toEqual({
      none: 'email',
    });
  });

  it('a manual entry skips email and plan, and still validates while opted out', () => {
    const ctx = machine.context({ on: false, manual: [workKey()] });
    expect(
      sessionCheck({ ctx, auth: { email: fixtureEmail('colleague'), plan: 'plus' } }),
    ).toMatchObject({
      key: workKey(),
      basis: 'manual',
    });
  });

  it('answers opted-out for an automatic login while opted out', () => {
    expect(sessionCheck({ ctx: machine.context({ on: false }) })).toEqual({ none: 'opted-out' });
  });

  it('a ninth org never forwards', () => {
    const learned = Array.from({ length: 8 }, () => `chatgpt:${randomUUID()}`);
    expect(sessionCheck({ ctx: machine.context({ learned }) })).toEqual({ none: 'cap-reached' });
    expect(start('startup', machine.context({ learned }))).toMatchObject({
      check: { none: 'cap-reached' },
      mayAdmit: false,
    });
    expect(lines().map((line) => (line.kind === 'start' ? line.s : line.kind))).toEqual(['none']);
  });
});

describe('startCodexSession', () => {
  it("writes the start line with the key's hash and the fingerprint", () => {
    machine.writeHead();
    machine.writeAuth();
    const result = start('startup');
    expect(result).toMatchObject({
      check: { key: workKey(), basis: 'validated' },
      mayAdmit: true,
      pending: false,
    });
    expect(lines()).toEqual([
      {
        kind: 'start',
        t: T0,
        bd: machine.bindingHash,
        start: 'startup',
        s: sessionAccountHash(workKey()),
        fp: codexAuthFingerprint(machine.codexHome),
      },
    ]);
  });

  it('a personal or mismatched login persists nothing', () => {
    machine.writeHead();
    machine.writeAuth({ plan: 'plus' });
    expect(start('startup').check).toEqual({ none: 'plan' });
    machine.writeHead({ creatorAccountId: randomUUID() });
    expect(start('clear').check).toEqual({ none: 'account-mismatch' });
    expect(lines().map((line) => (line.kind === 'start' ? line.s : line.kind))).toEqual([
      'none',
      'none',
    ]);
    const bytes = stateBytes();
    for (const needle of [
      machine.accountId,
      machine.accountId.replaceAll('-', ''),
      sessionAccountHash(workKey()),
      machine.email,
      'plus',
    ]) {
      expect(bytes).not.toContain(needle);
    }
  });

  it('writes the sticky resume line, and every later hook stays on the repository rule', () => {
    machine.writeHead();
    machine.writeAuth();
    expect(start('resume')).toMatchObject({ check: { none: 'resumed' }, pending: false });
    expect(later().check).toEqual({ none: 'resumed' });
    expect(authOpens()).toBe(0);
  });

  it('a resume while opted out still ends the thread, and opting back in does not revive it', () => {
    machine.writeHead();
    machine.writeAuth();
    expect(start('startup').mayAdmit).toBe(true);
    const optedOut = machine.context({ on: false });
    const resumed = start('resume', optedOut);
    expect(later(machine.context())).toMatchObject({ check: { none: 'resumed' }, mayAdmit: false });
    expect(lines().at(-1)).toMatchObject({ kind: 'start', start: 'resume', s: 'none' });
    expect(resumed).toMatchObject({ check: { none: 'resumed' }, mayAdmit: false });
    expect(later(optedOut).check).toEqual({ none: 'opted-out' });
  });

  it('keeps the earlier decision on compact', () => {
    const ctx = workThread();
    expect(start('compact', ctx).check).toMatchObject({ key: workKey(), basis: 'remembered' });
    expect(lines()).toHaveLength(1);
  });

  it('writes nothing while the gate is closed', () => {
    machine.writeHead();
    machine.writeAuth();
    expect(start('startup', null).check).toEqual({ none: 'attached-user-unknown' });
    expect(start('startup', machine.context({ on: false })).check).toEqual({ none: 'opted-out' });
    expect(lines()).toEqual([]);
    expect(authOpens()).toBe(0);
  });

  it('reports a head not on disk yet as pending, and writes none on the final attempt', () => {
    machine.writeAuth();
    expect(start('startup')).toMatchObject({
      check: { none: 'no-session-account' },
      pending: true,
    });
    expect(lines()).toEqual([]);
    expect(start('startup', machine.context(), true)).toMatchObject({ pending: false });
    expect(lines().map((line) => (line.kind === 'start' ? line.s : line.kind))).toEqual(['none']);
  });
});

describe('a start line written while the head was pending', () => {
  it('reads as pending until a later start line resolves it, and a hook reads no login meanwhile', () => {
    const bd = machine.bindingHash;
    const pending = { t: T0, bd, start: 'startup', s: 'pending', fp: 'absent' } as const;
    expect(codexThreadState([pending], bd)).toEqual({ kind: 'pending' });
    const resolved = {
      t: T0 + 1,
      bd,
      start: 'startup',
      s: sessionAccountHash(workKey()),
      fp: '1:2:3:4:5',
    } as const;
    expect(codexThreadState([pending, resolved], bd)).toEqual({
      kind: 'started',
      startHash: sessionAccountHash(workKey()),
      baselineFp: '1:2:3:4:5',
    });
    expect(
      codexThreadState([pending, { t: T0 + 1, bd, start: 'startup', s: 'none', fp: 'absent' }], bd),
    ).toEqual({
      kind: 'none',
    });
    machine.writeAuth();
    expect(appendObservation(machine.stateDir, machine.sessionId, pending)).toBe(true);
    expect(later().check).toEqual({ none: 'no-session-account' });
    expect(authOpens()).toBe(0);
  });
});

describe('a login file change mid-thread', () => {
  it('reads auth.json once at start and never again while it is unchanged', () => {
    const ctx = workThread();
    expect(later(ctx).check).toMatchObject({ key: workKey(), basis: 'remembered' });
    expect(later(ctx, T0 + 120_000).check).toMatchObject({ key: workKey(), basis: 'remembered' });
    expect(authOpens()).toBe(1);
  });

  const scenarios: readonly (readonly [
    string,
    (m: CodexMachine) => void,
    CodexAccountCheck | 'keeps',
  ])[] = [
    ['a refresh', (m) => m.writeAuth(), 'keeps'],
    [
      'account switched mid-thread',
      (m) => m.writeAuth({ accountId: randomUUID() }),
      { none: 'auth-changed' },
    ],
    ['a personal plan', (m) => m.writeAuth({ plan: 'plus' }), { none: 'auth-changed' }],
    [
      'another email',
      (m) => m.writeAuth({ email: fixtureEmail('someone-else') }),
      { none: 'auth-changed' },
    ],
    ['another login mode', (m) => m.writeAuth({ authMode: 'apikey' }), { none: 'auth-changed' }],
    [
      'a removed file',
      (m) => {
        rmSync(join(m.codexHome, 'auth.json'));
      },
      { none: 'auth-changed' },
    ],
    [
      'a torn read',
      (m) => {
        writeFileSync(join(m.codexHome, 'auth.json'), '{"auth_mode": "chatgpt", "tok', {
          mode: 0o600,
        });
      },
      { none: 'auth-changed' },
    ],
  ];

  it.each(scenarios)(
    'a refresh keeps the account; a switch, a personal plan or a torn read ends the thread; nothing new persists: %s',
    (_, rewrite, expected) => {
      const ctx = workThread();
      const before = stateBytes();
      rewrite(machine);
      const result = later(ctx);
      if (expected === 'keeps') {
        expect(result.check).toMatchObject({ key: workKey(), basis: 'remembered' });
        expect(lines().at(-1)).toMatchObject({
          kind: 'baseline',
          s: sessionAccountHash(workKey()),
        });
        expect(later(ctx, T0 + 120_000).check).toMatchObject({ key: workKey() });
      } else {
        expect(result.check).toEqual(expected);
        expect(lines().at(-1)).toMatchObject({ kind: 'sticky', bd: machine.bindingHash });
        expect(later(ctx, T0 + 120_000).check).toEqual({ none: 'auth-changed' });
        const added = stateBytes().slice(before.length);
        expect(added).not.toContain('chatgpt');
        expect(added).not.toContain(machine.email);
      }
      expect(authOpens()).toBe(2);
    },
  );

  it('a remembered key whose refreshed login shows no plan keeps forwarding', () => {
    const ctx = workThread();
    machine.writeAuth({ plan: undefined });
    expect(later(ctx).check).toMatchObject({ key: workKey(), basis: 'remembered' });
    expect(lines().at(-1)).toMatchObject({ kind: 'baseline' });
  });

  it('a manual key is re-checked for login mode and account only', () => {
    machine.writeHead();
    machine.writeAuth();
    const ctx = machine.context({ on: false, manual: [workKey()] });
    expect(start('startup', ctx).check).toMatchObject({ basis: 'manual' });
    machine.writeAuth({ plan: 'plus', email: fixtureEmail('colleague') });
    expect(later(ctx).check).toMatchObject({ key: workKey(), basis: 'manual' });
    machine.writeAuth({ authMode: 'apikey' });
    expect(later(ctx, T0 + 120_000).check).toEqual({ none: 'auth-changed' });
  });

  it('one re-read per change, never one per hook', () => {
    const ctx = workThread();
    machine.writeAuth();
    for (let i = 1; i <= 4; i += 1) later(ctx, T0 + i * 60_000);
    expect(authOpens()).toBe(2);
  });

  it('a sticky none from any parallel hook ends the thread, whatever line follows it', () => {
    const ctx = workThread();
    appendObservation(machine.stateDir, machine.sessionId, {
      t: T0 + 1,
      bd: machine.bindingHash,
      s: 'none',
    });
    appendObservation(machine.stateDir, machine.sessionId, {
      t: T0 + 2,
      bd: machine.bindingHash,
      s: sessionAccountHash(workKey()),
      fp: codexAuthFingerprint(machine.codexHome),
    });
    expect(later(ctx).check).toEqual({ none: 'auth-changed' });
  });

  it('ignores the lines of another binding', () => {
    const ctx = workThread();
    const other = machine.context({
      bindingHash: randomBytes(8).toString('hex'),
      learned: [workKey()],
    });
    expect(later(other).check).toEqual({ none: 'no-session-account' });
    expect(later(ctx).check).toMatchObject({ key: workKey() });
  });
});

describe('the lock-timeout retry', () => {
  it('validates again a key whose learning timed out, and lets the caller admit it', () => {
    machine.writeHead();
    machine.writeAuth();
    expect(start('startup').mayAdmit).toBe(true);
    expect(later()).toMatchObject({
      check: { key: workKey(), basis: 'validated' },
      mayAdmit: true,
    });
    expect(authOpens()).toBe(2);
  });

  it('never fires for a thread started on a manual key, nor while opted out', () => {
    machine.writeHead();
    machine.writeAuth();
    const manual = machine.context({ manual: [workKey()] });
    expect(start('startup', manual).check).toMatchObject({ basis: 'manual' });
    expect(later(manual).check).toMatchObject({ basis: 'manual' });
    const optedOut = machine.context({ on: false, manual: [`chatgpt:${randomUUID()}`] });
    expect(later(optedOut).check).toEqual({ none: 'opted-out' });
    expect(authOpens()).toBe(1);
  });

  it('stops re-reading after the learned-account cap refuses the thread', () => {
    machine.writeHead();
    machine.writeAuth();
    expect(start('startup').mayAdmit).toBe(true);
    const learned = Array.from({ length: 8 }, () => `chatgpt:${randomUUID()}`);
    const capped = machine.context({ learned });
    for (let i = 1; i <= 3; i += 1) {
      expect(later(capped, T0 + i * 60_000)).toMatchObject({
        check: { none: 'cap-reached' },
        mayAdmit: false,
      });
    }
    expect([authOpens(), headOpens()]).toEqual([1, 1]);
    expect(later(machine.context(), T0 + 240_000)).toMatchObject({
      check: { key: workKey(), basis: 'validated' },
      mayAdmit: true,
    });
    expect([authOpens(), headOpens()]).toEqual([2, 2]);
  });
});
