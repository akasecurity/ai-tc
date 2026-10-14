import { randomBytes, randomUUID } from 'node:crypto';
import type * as Fs from 'node:fs';
import { statSync, utimesSync } from 'node:fs';
import { join } from 'node:path';

import type { AttachedIdentity, AttachmentScope } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { AccountContext } from '../../src/account/account-check.ts';
import { accountContextFor, accountContextOf } from '../../src/account/account-check.ts';
import {
  CLAUDE_ACCOUNT_ENV_NAMES,
  CLAUDE_CREDENTIAL_ENV,
  CLAUDE_PROVIDER_FLAG_ENV,
} from '../../src/account/account-env.ts';
import { readScanCache, writeScanCache } from '../../src/account/claude-session.ts';
import type { ClaudeHookResult, ClaudeSessionSource } from '../../src/account/claude-validate.ts';
import {
  checkClaudeHook,
  claudeLoginCheck,
  startClaudeSession,
} from '../../src/account/claude-validate.ts';
import {
  appendObservation,
  classifyObservation,
  latestBoundary,
  readObservations,
} from '../../src/account/observation-log.ts';
import type { ClaudeMachine, SettingsLayer } from '../helpers/transcript-builder.ts';
import {
  appendLines,
  assistantLine,
  claudeMachine,
  credentialOrgLine,
  fixtureEmail,
  otherHost,
  SECOND,
  T0,
  userPromptLine,
  workConfig,
  writeLines,
} from '../helpers/transcript-builder.ts';

const reads = vi.hoisted(() => ({ paths: [] as string[] }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof Fs>();
  const track =
    <A extends unknown[], R>(fn: (...args: A) => R) =>
    (...args: A): R => {
      reads.paths.push(String(args[0]));
      return fn(...args);
    };
  return {
    ...actual,
    openSync: track(actual.openSync),
    readFileSync: track(actual.readFileSync),
    statSync: track(actual.statSync),
  };
});

const LAYERS: readonly SettingsLayer[] = ['user', 'project', 'local', 'managed'];

let machine: ClaudeMachine;
let sid: string;
let org: string;

beforeEach(() => {
  for (const name of CLAUDE_ACCOUNT_ENV_NAMES) vi.stubEnv(name, undefined);
  machine = claudeMachine();
  sid = machine.sessionId;
  org = randomUUID();
  appendObservation(machine.stateDir, sid, { t: T0, b: 'startup' });
  reads.paths.length = 0;
});

afterEach(() => {
  vi.unstubAllEnvs();
  machine.dispose();
});

const key = (): string => `claude:${org}`;
const validated = (): { key: string; basis: 'validated' } => ({ key: key(), basis: 'validated' });

// `null` is a machine with no bound identity record. An explicit `undefined`
// would take the default context instead.
function hook(
  ctx: AccountContext | null = machine.context(),
  at = T0 + 10 * SECOND,
): ClaudeHookResult {
  return checkClaudeHook({
    dataDir: machine.dataDir,
    sessionId: sid,
    transcriptPath: machine.transcript,
    cwd: machine.cwd,
    ctx: ctx ?? undefined,
    paths: machine.paths,
    now: () => at,
  });
}

function start(source: ClaudeSessionSource, ctx: AccountContext | null = machine.context()) {
  return startClaudeSession({
    dataDir: machine.dataDir,
    sessionId: sid,
    transcriptPath: machine.transcript,
    cwd: machine.cwd,
    ctx: ctx ?? undefined,
    paths: machine.paths,
    now: () => T0 + 60 * SECOND,
    source,
  });
}

function workLogin(
  account: Record<string, unknown> = {},
  extra: Record<string, unknown> = {},
): void {
  machine.writeConfig(workConfig(org, machine.email, account, extra));
}

/** A session whose first reply ran under `sessionOrg`: a prompt, its credential_org, the reply. */
function repliedUnder(sessionOrg: string = org): void {
  writeLines(machine.transcript, [
    userPromptLine(sid, 'hello', T0 + SECOND),
    credentialOrgLine(sid, sessionOrg, T0 + 2 * SECOND),
    assistantLine(sid, T0 + 3 * SECOND),
  ]);
}

function lastLogLine(): ReturnType<typeof classifyObservation> | undefined {
  const last = readObservations(machine.stateDir, sid).entries.at(-1);
  return last === undefined ? undefined : classifyObservation(last.observation);
}

function identityFor(workAccounts: AttachedIdentity['workAccounts'] = []): AttachedIdentity {
  return {
    specVersion: 1,
    endpoint: `https://${otherHost()}`,
    credentialDigest: randomBytes(32).toString('hex'),
    attachedUserDigest: machine.context().attachedUserDigest,
    scopeTag: randomBytes(8).toString('hex'),
    source: 'attach',
    checkedAt: new Date(T0).toISOString(),
    workAccounts,
  };
}

describe('the automatic path', () => {
  it('keeps turn 1 local, and attributes the first reply', () => {
    workLogin();
    writeLines(machine.transcript, [userPromptLine(sid, 'hello', T0 + SECOND)]);
    expect(hook().check).toEqual({ none: 'no-session-account' });
    appendLines(machine.transcript, [
      credentialOrgLine(sid, org, T0 + 2 * SECOND),
      assistantLine(sid, T0 + 3 * SECOND),
    ]);
    expect(hook()).toEqual({ check: validated(), mayAdmit: true, threw: false });
  });

  it('attributes none to a stale config with no credential_org', () => {
    workLogin();
    writeLines(machine.transcript, [
      userPromptLine(sid, 'hello', T0 + SECOND),
      assistantLine(sid, T0 + 3 * SECOND),
    ]);
    expect(hook()).toEqual({
      check: { none: 'no-session-account' },
      mayAdmit: false,
      threw: false,
    });
  });

  it.each(['claude_team', 'claude_enterprise'])('validates %s', (type) => {
    workLogin({ organizationType: type });
    repliedUnder();
    expect(hook().check).toEqual(validated());
  });

  it.each([
    ['claude_max', 'plan'],
    ['claude_pro', 'plan'],
    [undefined, 'plan-unconfirmed'],
  ] as const)('refuses organizationType %j with %s', (type, reason) => {
    workLogin({ organizationType: type });
    repliedUnder();
    expect(hook().check).toEqual({ none: reason });
  });

  it('refuses a plan whose newest cache slot names another org', () => {
    workLogin(
      {},
      {
        clientDataCacheSlots: {
          a: { data: null, at: T0, org },
          b: { data: null, at: T0 + 1, org: randomUUID() },
        },
      },
    );
    repliedUnder();
    expect(hook().check).toEqual({ none: 'plan-stale' });
  });

  it('accepts a login with no cache slots at all', () => {
    workLogin({}, { clientDataCacheSlots: undefined });
    repliedUnder();
    expect(hook().check).toEqual(validated());
  });

  it('validates an email that differs only in case, and refuses another email', () => {
    machine.writeConfig(workConfig(org, machine.email.toUpperCase()));
    repliedUnder();
    expect(hook().check).toEqual(validated());
    machine.writeConfig(workConfig(org, fixtureEmail('someone-else')));
    expect(hook(machine.context(), T0 + 11 * SECOND).check).toEqual({ none: 'email' });
  });

  it('a ninth org never forwards: eight learned orgs refuse another, with nothing to admit', () => {
    workLogin();
    repliedUnder();
    const learned = Array.from({ length: 8 }, () => `claude:${randomUUID()}`);
    expect(hook(machine.context({ learned }))).toEqual({
      check: { none: 'cap-reached' },
      mayAdmit: false,
      threw: false,
    });
  });

  it('ends attribution when a different org appears under the same boundary', () => {
    workLogin();
    repliedUnder();
    expect(hook().check).toEqual(validated());
    appendLines(machine.transcript, [credentialOrgLine(sid, randomUUID(), T0 + 4 * SECOND)]);
    expect(hook(machine.context(), T0 + 11 * SECOND).check).toEqual({ none: 'org-changed' });
  });

  it('records a work view for the login it checked', () => {
    workLogin();
    repliedUnder();
    hook();
    expect(lastLogLine()).toMatchObject({ kind: 'view', k: 'w', bd: machine.bindingHash });
  });
});

describe('anything that bills the session elsewhere vetoes it', () => {
  beforeEach(() => {
    workLogin();
    repliedUnder();
  });

  it.each(CLAUDE_CREDENTIAL_ENV)('vetoes a non-empty %s and records the veto', (name) => {
    vi.stubEnv(name, randomUUID());
    expect(hook().check).toEqual({ none: 'veto' });
    expect(lastLogLine()).toMatchObject({ kind: 'view', k: 'v' });
  });

  it.each(CLAUDE_PROVIDER_FLAG_ENV)('vetoes a truthy %s, and not an empty one', (name) => {
    vi.stubEnv(name, '');
    expect(hook().check).toEqual(validated());
    vi.stubEnv(name, 'true');
    expect(hook(machine.context(), T0 + 11 * SECOND).check).toEqual({ none: 'veto' });
  });

  it('vetoes a primaryApiKey in the login file', () => {
    workLogin({}, { primaryApiKey: randomUUID() });
    expect(hook().check).toEqual({ none: 'veto' });
  });

  it.each(LAYERS)('vetoes an apiKeyHelper in the %s settings layer', (layer) => {
    machine.writeSettings(layer, { apiKeyHelper: '/usr/local/bin/key-helper' });
    expect(hook().check).toEqual({ none: 'veto' });
  });

  it('vetoes a base URL that is not the default, and not the default the desktop host sets', () => {
    vi.stubEnv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com');
    expect(hook().check).toEqual(validated());
    vi.stubEnv('ANTHROPIC_BASE_URL', `https://${otherHost()}`);
    expect(hook(machine.context(), T0 + 11 * SECOND).check).toEqual({ none: 'veto' });
  });
});

describe('the env can confirm or veto the login file', () => {
  beforeEach(() => {
    workLogin();
    repliedUnder();
  });

  it('validates when the env names the same org and email', () => {
    vi.stubEnv('CLAUDE_CODE_ORGANIZATION_UUID', org.toUpperCase());
    vi.stubEnv('CLAUDE_CODE_USER_EMAIL', machine.email);
    expect(hook().check).toEqual(validated());
  });

  it('refuses an env org that differs from the file', () => {
    vi.stubEnv('CLAUDE_CODE_ORGANIZATION_UUID', randomUUID());
    expect(hook().check).toEqual({ none: 'env-mismatch' });
  });

  it('refuses an env email that differs from the file', () => {
    vi.stubEnv('CLAUDE_CODE_USER_EMAIL', fixtureEmail('someone-else'));
    expect(hook().check).toEqual({ none: 'env-mismatch' });
  });
});

describe('the gate', () => {
  it('answers attached-user-unknown with no record, and reads nothing', () => {
    workLogin();
    repliedUnder();
    reads.paths.length = 0;
    expect(hook(null).check).toEqual({ none: 'attached-user-unknown' });
    expect(reads.paths).toEqual([]);
  });

  it('an existing attachment validates: a scope record with no workSubscriptions field is on', () => {
    workLogin();
    repliedUnder();
    const scope: AttachmentScope = { endpoint: `https://${otherHost()}`, entries: [] };
    const ctx = accountContextFor({
      identity: identityFor(),
      scope,
      bindingHash: machine.bindingHash,
      inScope: () => false,
    });
    expect(ctx?.workSubscriptionsOn).toBe(true);
    expect(hook(ctx).check).toEqual(validated());
  });

  it('opted out: answers opted-out and reads no login file and no transcript', () => {
    workLogin();
    repliedUnder();
    reads.paths.length = 0;
    expect(hook(machine.context({ on: false })).check).toEqual({ none: 'opted-out' });
    expect(reads.paths).toEqual([]);
  });

  it("manual entries are the user's own enrollment: one validates while opted out, email and plan unchecked", () => {
    machine.writeConfig(
      workConfig(org, fixtureEmail('colleague'), { organizationType: 'claude_max' }),
    );
    repliedUnder();
    expect(hook(machine.context({ on: false, manual: [key()] })).check).toEqual({
      key: key(),
      basis: 'manual',
    });
  });
});

describe('a remembered org', () => {
  const remembered = (): AccountContext => machine.context({ learned: [key()] });

  beforeEach(() => {
    repliedUnder();
  });

  it('forwards with no plan shown', () => {
    workLogin({ organizationType: undefined });
    expect(hook(remembered()).check).toEqual({ key: key(), basis: 'remembered' });
  });

  it.each(['claude_max', 'claude_pro', 'claude_unknown_tier'])(
    'a remembered org refuses a non-company plan: %s',
    (type) => {
      workLogin({ organizationType: type });
      expect(hook(remembered()).check).toEqual({ none: 'plan' });
    },
  );

  it('refuses another email', () => {
    machine.writeConfig(workConfig(org, fixtureEmail('someone-else')));
    expect(hook(remembered()).check).toEqual({ none: 'email' });
  });
});

describe('the verdict memo', () => {
  // A key in scope but not learned: a full run answers `validated` and may
  // admit it, a memo hit answers `remembered` and may not. So each case below
  // tells the two apart by what the second hook returns.
  const scoped = (): AccountContext => machine.context({ inScope: (k) => k === key() });
  const configPath = (): string => join(machine.home, '.claude.json');
  const pinConfigTime = (ms: number): void => {
    utimesSync(configPath(), new Date(ms), new Date(ms));
  };
  const fullRunValidated = (): ClaudeHookResult => ({
    check: validated(),
    mayAdmit: true,
    threw: false,
  });
  const loginChanged = { check: { none: 'login-changed' }, mayAdmit: false, threw: false } as const;

  beforeEach(() => {
    workLogin();
    repliedUnder();
    pinConfigTime(T0);
  });

  it('a memo hit forwards a key already in scope, and never admits', () => {
    expect(hook(scoped())).toEqual(fullRunValidated());
    expect(hook(scoped(), T0 + 11 * SECOND)).toEqual({
      check: { key: key(), basis: 'remembered' },
      mayAdmit: false,
      threw: false,
    });
  });

  it('runs in full when the login file changes size under the same mtime', () => {
    expect(hook(scoped())).toEqual(fullRunValidated());
    const size = statSync(configPath()).size;
    machine.writeConfig(workConfig(randomUUID(), machine.email, {}, { note: 'padding' }));
    pinConfigTime(T0);
    expect(statSync(configPath()).size).not.toBe(size);
    expect(hook(scoped(), T0 + 11 * SECOND)).toEqual(loginChanged);
  });

  it('runs in full when the login file changes mtime at the same size', () => {
    expect(hook(scoped())).toEqual(fullRunValidated());
    const size = statSync(configPath()).size;
    machine.writeConfig(workConfig(randomUUID(), machine.email));
    pinConfigTime(T0 + 60 * SECOND);
    expect(statSync(configPath()).size).toBe(size);
    expect(hook(scoped(), T0 + 11 * SECOND)).toEqual(loginChanged);
  });

  it('runs in full when the env now agrees with the login file', () => {
    expect(hook(scoped())).toEqual(fullRunValidated());
    vi.stubEnv('CLAUDE_CODE_USER_EMAIL', machine.email);
    expect(hook(scoped(), T0 + 11 * SECOND)).toEqual(fullRunValidated());
  });

  it('runs in full when the anchor line moves', () => {
    expect(hook(scoped())).toEqual(fullRunValidated());
    writeLines(machine.transcript, [
      userPromptLine(sid, 'hello again, with a longer first prompt than before', T0 + SECOND),
      credentialOrgLine(sid, org, T0 + 2 * SECOND),
      assistantLine(sid, T0 + 3 * SECOND),
    ]);
    expect(hook(scoped(), T0 + 11 * SECOND)).toEqual(fullRunValidated());
  });

  it('runs in full when the transcript now names another org on the same line', () => {
    const anywhere = machine.context({ inScope: () => true });
    expect(hook(anywhere)).toEqual(fullRunValidated());
    repliedUnder(randomUUID());
    expect(hook(anywhere, T0 + 11 * SECOND)).toEqual(loginChanged);
  });

  it('a memo or observation from another binding is ignored', () => {
    expect(hook().check).toEqual(validated());
    const other = machine.context({
      bindingHash: randomBytes(8).toString('hex'),
      inScope: () => true,
    });
    expect(hook(other, T0 + 11 * SECOND)).toEqual({
      check: validated(),
      mayAdmit: true,
      threw: false,
    });
  });

  it('reports a throw as a fail-open none', () => {
    hook();
    const throwing = machine.context({
      inScope: () => {
        throw new Error('scope unavailable');
      },
    });
    expect(hook(throwing, T0 + 11 * SECOND)).toEqual({
      check: { none: 'unreadable' },
      mayAdmit: false,
      threw: true,
    });
  });
});

describe('startClaudeSession', () => {
  beforeEach(() => {
    workLogin();
    repliedUnder();
  });

  it('inherits on resume when the login still names the session org and nothing vetoes', () => {
    expect(start('resume')).toEqual({ inherited: true, threw: false });
    expect(lastLogLine()).toMatchObject({ kind: 'inherit', bd: machine.bindingHash });
    expect(hook(machine.context(), T0 + 61 * SECOND).check).toEqual(validated());
  });

  it('refuses inheritance with a veto', () => {
    vi.stubEnv('ANTHROPIC_API_KEY', randomUUID());
    expect(start('resume').inherited).toBe(false);
  });

  it('refuses inheritance while the subprocess env scrub is on', () => {
    vi.stubEnv('CLAUDE_CODE_SUBPROCESS_ENV_SCRUB', '1');
    expect(start('resume').inherited).toBe(false);
    vi.stubEnv('CLAUDE_CODE_SUBPROCESS_ENV_SCRUB', '');
    expect(hook(machine.context(), T0 + 61 * SECOND).check).toEqual({ none: 'no-session-account' });
  });

  it('refuses inheritance when the login now names another org', () => {
    machine.writeConfig(workConfig(randomUUID(), machine.email));
    expect(start('resume').inherited).toBe(false);
  });

  it('writes a boundary even with no bound record, and nothing on compact', () => {
    const before = readObservations(machine.stateDir, sid).entries.length;
    expect(start('compact')).toEqual({ inherited: false, threw: false });
    expect(readObservations(machine.stateDir, sid).entries).toHaveLength(before);
    expect(start('clear', null)).toEqual({ inherited: false, threw: false });
    expect(lastLogLine()).toMatchObject({ kind: 'boundary', b: 'clear' });
  });
});

describe('a session whose log outgrew the tail window', () => {
  /** A resumed session that inherited its org, then 1,600 views that push the boundary out of the tail. */
  function outgrownResume(): void {
    workLogin();
    repliedUnder();
    expect(start('resume')).toEqual({ inherited: true, threw: false });
    expect(hook(machine.context(), T0 + 61 * SECOND).check).toEqual(validated());
    for (let i = 0; i < 1600; i += 1) {
      appendObservation(machine.stateDir, sid, {
        t: T0 + 62 * SECOND + i,
        bd: machine.bindingHash,
        k: 'n',
      });
    }
  }

  it('keeps its boundary from the scan cache, and inherits only under the binding that wrote it', () => {
    outgrownResume();
    expect(hook(machine.context(), T0 + 70 * SECOND).check).toEqual(validated());
    const rebound = machine.context({ bindingHash: randomBytes(8).toString('hex') });
    expect(hook(rebound, T0 + 71 * SECOND).check).toEqual({ none: 'no-session-account' });
  });

  it('takes the boundary from the scan cache, not from a read of the whole log', () => {
    outgrownResume();
    const whole = readObservations(machine.stateDir, sid).entries.map((entry) => entry.observation);
    expect(latestBoundary(whole, machine.bindingHash)).toMatchObject({
      kind: 'resume',
      inherited: true,
    });
    const cache = readScanCache(machine.stateDir, sid);
    if (cache === undefined) throw new Error('the earlier hook left no scan cache');
    writeScanCache(machine.stateDir, sid, {
      ...cache,
      inherited: false,
      anchorAt: undefined,
      memo: undefined,
    });
    expect(hook(machine.context(), T0 + 70 * SECOND).check).toEqual({ none: 'no-session-account' });
  });
});

describe('accountContextFor', () => {
  const at = new Date(T0).toISOString();

  it('is undefined without a bound identity record', () => {
    expect(
      accountContextFor({
        identity: undefined,
        scope: undefined,
        bindingHash: machine.bindingHash,
        inScope: () => false,
      }),
    ).toBeUndefined();
  });

  it('reads an absent workSubscriptions as on and any present value as off', () => {
    const scope: AttachmentScope = { endpoint: `https://${otherHost()}`, entries: [] };
    const input = {
      identity: identityFor(),
      bindingHash: machine.bindingHash,
      inScope: () => false,
    };
    expect(accountContextFor({ ...input, scope })?.workSubscriptionsOn).toBe(true);
    expect(
      accountContextFor({ ...input, scope: { ...scope, workSubscriptions: 'off' } })
        ?.workSubscriptionsOn,
    ).toBe(false);
  });

  it('takes manual keys only from account entries marked for coding agents, learned keys from the record', () => {
    const [marked, webOnly, learned] = [
      `claude:${randomUUID()}`,
      `claude:${randomUUID()}`,
      `claude:${randomUUID()}`,
    ];
    const scope: AttachmentScope = {
      endpoint: `https://${otherHost()}`,
      entries: [
        { kind: 'account', identity: marked, enrolledAt: at, codingAgents: true },
        { kind: 'account', identity: webOnly, enrolledAt: at },
        { kind: 'repo', identity: 'github.com/acme/app', enrolledAt: at },
      ],
    };
    const ctx = accountContextFor({
      identity: identityFor([
        { kind: 'account', identity: learned, label: 'Claude work account', enrolledAt: at },
      ]),
      scope,
      bindingHash: machine.bindingHash,
      inScope: () => false,
    });
    expect(ctx?.manual).toEqual([marked]);
    expect(ctx?.learned.map((entry) => entry.identity)).toEqual([learned]);
  });

  it("builds the context from the gateway's capability, an account in scope when it stamps", () => {
    const inScopeKey = `claude:${randomUUID()}`;
    const fromScope = accountContextOf({
      bindingHash: machine.bindingHash,
      context: {
        attachedUserDigest: machine.context().attachedUserDigest,
        workSubscriptionsOn: true,
        learned: [],
        manual: [inScopeKey],
      },
      stamp: (_repoKey, accountKey) =>
        accountKey === inScopeKey ? `agent:tag:${accountKey}` : undefined,
    });
    expect(fromScope).toMatchObject({ bindingHash: machine.bindingHash, manual: [inScopeKey] });
    expect(fromScope.inScope(inScopeKey)).toBe(true);
    expect(fromScope.inScope(`claude:${randomUUID()}`)).toBe(false);
  });
});

describe('claudeLoginCheck', () => {
  it('reports the login key and plan from the login file alone, with no record', () => {
    workLogin();
    repliedUnder();
    reads.paths.length = 0;
    expect(claudeLoginCheck({ ctx: undefined, cwd: machine.cwd, paths: machine.paths })).toEqual({
      key: key(),
      planState: 'company',
      found: true,
      check: { none: 'attached-user-unknown' },
    });
    expect(reads.paths).not.toContain(machine.transcript);
  });

  it("reports a personal plan's key and reason, for the user's own terminal", () => {
    workLogin({ organizationType: 'claude_max' });
    expect(
      claudeLoginCheck({ ctx: machine.context(), cwd: machine.cwd, paths: machine.paths }),
    ).toMatchObject({
      key: key(),
      planState: 'other',
      check: { none: 'plan' },
    });
  });
});
