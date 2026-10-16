import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, utimesSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { handleSessionStart } from '@akasecurity/plugin-runtime';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as Remote from '../../../../packages/remote/src/index.ts';
import { recordSessionStartAccount } from '../../src/hooks/account-stamp.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type { SessionStartDeps } from '../../src/hooks/session-start-run.ts';
import { runSessionStart } from '../../src/hooks/session-start-run.ts';
import type { Device, Transcript } from '../helpers/account-fixture.ts';
import { device, isAgentKeyFor, PERSONAL_KEY, WORK_KEY } from '../helpers/account-fixture.ts';
import type { Sent } from '../helpers/recording-client.ts';

// The hooks open the gateway the plugin's factory builds; only its transport is
// replaced, by one that records what it is handed and sends nothing.
const sent = vi.hoisted((): Sent => ({ captures: [], audit: [], inventory: [] }));
vi.mock('../../../../packages/remote/src/index.ts', async (importOriginal) => {
  const { recordingClient } = await import('../helpers/recording-client.ts');
  return {
    ...(await importOriginal<typeof Remote>()),
    createRemoteClient: () => recordingClient(sent),
  };
});

let dev: Device;
beforeEach(() => {
  dev = device(sent);
});
afterEach(() => {
  dev.dispose();
});

/** An instant `n` seconds after now, plus one, so it follows a boundary just recorded. */
const later = (n: number): string => new Date(Date.now() + (n + 1) * 1_000).toISOString();

// A resumed session's first run took place an hour ago: its boundary is
// stamped then and its transcript lines follow it, so all of them precede the
// resume, which runs now.
const AN_HOUR_AGO = Date.now() - 60 * 60 * 1_000;
const earlier = (n: number): string => new Date(AN_HOUR_AGO + n * 1_000).toISOString();
const firstRun = { now: () => AN_HOUR_AGO };

function payload(t: Transcript, source: string): Record<string, unknown> {
  return {
    session_id: t.sessionId,
    transcript_path: t.path,
    cwd: dev.personal,
    hook_event_name: 'SessionStart',
    source,
  };
}

function deps(overrides: Partial<SessionStartDeps> = {}): SessionStartDeps {
  return {
    version: '0.0.0-test',
    harnessInterface: undefined,
    handleSessionStart,
    triggerReconcile: () => undefined,
    emit: () => Promise.resolve(),
    ...overrides,
  };
}

async function write(t: Transcript, name: string): Promise<void> {
  await runPreToolUse(
    {
      session_id: t.sessionId,
      transcript_path: t.path,
      cwd: dev.personal,
      hook_event_name: 'PreToolUse',
      tool_name: 'Write',
      tool_input: { file_path: join(dev.personal, name), content: 'hello' },
    },
    () => Promise.resolve(),
    { mode: 'hook' },
  );
}

const captureKeys = (): (string | null)[] =>
  dev
    .storedRows()
    .filter((row) => row.eventType === 'code_change')
    .map((row) => row.scopeKey);

const lines = (sessionId: string): string[] =>
  dev.sessionState(sessionId).log.trim().split('\n').filter(Boolean);

describe('SessionStart records the session before the session start runs', () => {
  beforeEach(() => {
    dev.attach();
  });

  it('a resume killed inside the session start still has its boundary', async () => {
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    await expect(
      runSessionStart(
        payload(t, 'resume'),
        deps({ handleSessionStart: () => Promise.reject(new Error('stopped')) }),
      ),
    ).rejects.toThrow('stopped');
    expect(dev.sessionState(t.sessionId).log).toMatch(/"b":"resume"/);
  });

  it('resume under the same id after a veto anchors to the org the resumed session uses', async () => {
    // The first run: a personal login, then an API key in the environment.
    dev.login({ org: dev.personalOrg, organizationType: 'claude_pro' });
    const t = dev.transcript(randomUUID());
    await runSessionStart(payload(t, 'startup'), deps(firstRun));
    t.prompt(earlier(1));
    t.org(dev.personalOrg, earlier(2));
    t.reply(earlier(3));
    vi.stubEnv('ANTHROPIC_API_KEY', 'present-for-this-case');
    await write(t, 'first.md');
    // The resume, under the same id: the API key gone, the login the work subscription.
    vi.stubEnv('ANTHROPIC_API_KEY', '');
    dev.login({ org: dev.workOrg });
    const seenBySessionStart: string[] = [];
    await runSessionStart(
      payload(t, 'resume'),
      deps({
        handleSessionStart: (input, config) => {
          seenBySessionStart.push(dev.sessionState(t.sessionId).log);
          return handleSessionStart(input, config);
        },
      }),
    );
    expect(seenBySessionStart[0]).toMatch(/"b":"resume"/);
    t.prompt(later(4));
    t.org(dev.workOrg, later(5));
    t.reply(later(6));
    await write(t, 'second.md');
    const [first, second] = captureKeys();
    expect(first).toBe(PERSONAL_KEY);
    expect(isAgentKeyFor(second, dev.workOrg)).toBe(true);
  });

  it('inherits the org a resumed session ran under when the login still names it', async () => {
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    await runSessionStart(payload(t, 'startup'), deps(firstRun));
    t.prompt(earlier(1));
    t.org(dev.workOrg, earlier(2));
    t.reply(earlier(3));
    await runSessionStart(payload(t, 'resume'), deps());
    expect(dev.sessionState(t.sessionId).log).toMatch(/"inh":true/);
    // The host has written no org line since the resume: the inherited org anchors.
    await write(t, 'after-resume.md');
    expect(isAgentKeyFor(captureKeys()[0], dev.workOrg)).toBe(true);
  });

  it.each([
    ['an API key in the environment', 'ANTHROPIC_API_KEY', 'present-for-this-case'],
    ['the subprocess env scrub on', 'CLAUDE_CODE_SUBPROCESS_ENV_SCRUB', '1'],
  ])('does not inherit with %s', async (_label, name, value) => {
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    await runSessionStart(payload(t, 'startup'), deps(firstRun));
    t.prompt(earlier(1));
    t.org(dev.workOrg, earlier(2));
    t.reply(earlier(3));
    vi.stubEnv(name, value);
    await runSessionStart(payload(t, 'resume'), deps());
    expect(dev.sessionState(t.sessionId).log).toMatch(/"b":"resume"/);
    expect(dev.sessionState(t.sessionId).log).not.toMatch(/"inh":true/);
  });

  it('records no boundary for a compaction', async () => {
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    await runSessionStart(payload(t, 'startup'), deps());
    await runSessionStart(payload(t, 'compact'), deps());
    expect(lines(t.sessionId).filter((line) => line.includes('"b":'))).toHaveLength(1);
  });
});

describe('recordSessionStartAccount', () => {
  const start = (t: Transcript) =>
    recordSessionStartAccount({
      config: dev.config(),
      sessionId: t.sessionId,
      transcriptPath: t.path,
      cwd: dev.personal,
      source: 'startup',
    });

  it.each([
    ['a work', 'claude_team', 'validated', undefined, false],
    ['a personal', 'claude_pro', undefined, 'plan', false],
    ['a plan-less', null, undefined, 'plan-unconfirmed', true],
  ] as const)('reports %s login', (_label, organizationType, basis, none, undetermined) => {
    dev.attach();
    dev.login({ org: dev.workOrg, organizationType });
    const t = dev.transcript(randomUUID());
    expect(start(t)).toEqual({
      view: basis === undefined ? { none } : { key: `claude:${dev.workOrg}`, basis },
      basis,
      undetermined,
    });
    // The view is in the session's log: a hash for a work login, never a reason.
    expect(lines(t.sessionId)[1]).toMatch(basis === undefined ? /"k":"n"/ : /"k":"w"/);
  });

  it('reports a login file that does not parse as one that cannot be told yet', () => {
    dev.attach();
    dev.unreadableLogin();
    const account = start(dev.transcript(randomUUID()));
    expect(account.view).toEqual({ none: 'unreadable' });
    expect(account.undetermined).toBe(true);
  });

  it('records the boundary but reads no login while work subscriptions are off', () => {
    dev.attach({ workSubscriptions: 'off' });
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    expect(start(t).view).toBeUndefined();
    expect(lines(t.sessionId)).toEqual([expect.stringMatching(/"b":"startup"/)]);
  });

  it('records nothing on a machine-wide attachment', () => {
    dev.attach({ mode: 'machine' });
    dev.login({ org: dev.workOrg });
    expect(start(dev.transcript(randomUUID()))).toEqual({
      view: undefined,
      basis: undefined,
      undetermined: false,
    });
    expect(existsSync(join(dev.dataDir, 'session-accounts'))).toBe(false);
  });

  /** A session state file last written thirty-one days ago. */
  function staleState(): string {
    const dir = join(dev.dataDir, 'session-accounts');
    mkdirSync(dir, { recursive: true });
    const old = join(dir, 'an-old-session.log');
    writeFileSync(old, '');
    const longAgo = new Date(Date.now() - 31 * 24 * 60 * 60 * 1_000);
    utimesSync(old, longAgo, longAgo);
    return old;
  }

  it('prunes session state last written more than thirty days ago', () => {
    dev.attach();
    dev.login({ org: dev.workOrg });
    const old = staleState();
    const t = dev.transcript(randomUUID());
    start(t);
    expect(existsSync(old)).toBe(false);
    expect(lines(t.sessionId).length).toBeGreaterThan(0);
  });

  it.each<[string, () => void]>([
    [
      'a machine-wide attachment',
      () => {
        dev.attach({ mode: 'machine' });
      },
    ],
    ['no attachment', () => undefined],
  ])('prunes session state last written more than thirty days ago with %s', (_what, setUp) => {
    setUp();
    const old = staleState();
    start(dev.transcript(randomUUID()));
    expect(existsSync(old)).toBe(false);
  });
});

describe('the session root at session start', () => {
  const rootOf = (t: Transcript) =>
    dev.storedRows().find((row) => row.eventType === 'session' && row.id === t.sessionId);
  const sentRoots = () => dev.sent.audit.filter((event) => event.eventType === 'session');

  it("a personal session's root is written at session start with its repository key", async () => {
    dev.attach();
    dev.login({ org: dev.workOrg, organizationType: 'claude_pro' });
    const t = dev.transcript(randomUUID());
    await runSessionStart(payload(t, 'startup'), deps());
    expect(rootOf(t)).toMatchObject({ scopeKey: PERSONAL_KEY });
  });

  it.each([
    ['a work login', 'claude_team'],
    ['a login whose plan the config does not show', null],
  ] as const)(
    '%s leaves the root to the reconcile, as a local stub',
    async (_label, organizationType) => {
      dev.attach();
      dev.login({ org: dev.workOrg, organizationType });
      const t = dev.transcript(randomUUID());
      await runSessionStart(payload(t, 'startup'), deps());
      expect(rootOf(t)).toMatchObject({ scopeKey: null });
      expect(sentRoots()).toEqual([]);
    },
  );

  it('a login file that does not parse leaves the root to the reconcile', async () => {
    dev.attach();
    dev.unreadableLogin();
    const t = dev.transcript(randomUUID());
    await runSessionStart(payload(t, 'startup'), deps());
    expect(rootOf(t)).toMatchObject({ scopeKey: null });
  });

  it('a work session rooted in an enrolled repository writes its root at session start with its repository key', async () => {
    dev.attach();
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    await runSessionStart({ ...payload(t, 'startup'), cwd: dev.work }, deps());
    expect(rootOf(t)).toMatchObject({ scopeKey: WORK_KEY });
    expect(sentRoots()).toHaveLength(1);
  });

  it('a machine-wide attachment writes its root at session start', async () => {
    dev.attach({ mode: 'machine' });
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    await runSessionStart(payload(t, 'startup'), deps());
    expect(rootOf(t)).toMatchObject({ scopeKey: PERSONAL_KEY });
  });

  it('an opted-out session writes its root at session start', async () => {
    dev.attach({ workSubscriptions: 'off' });
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    await runSessionStart(payload(t, 'startup'), deps());
    expect(rootOf(t)).toMatchObject({ scopeKey: PERSONAL_KEY });
  });

  // The basis the session start is handed is the one the login view reached,
  // and only a work login reaches one.
  it.each([
    [
      'a work login',
      () => {
        dev.attach();
        dev.login({ org: dev.workOrg });
      },
      'validated',
    ],
    [
      'a work login on an account enrolled by hand',
      () => {
        dev.attach({ manual: [`claude:${dev.workOrg}`] });
        dev.login({ org: dev.workOrg });
      },
      'manual',
    ],
    [
      'a work login on a remembered account',
      async () => {
        dev.attach();
        dev.login({ org: dev.workOrg });
        const learning = dev.transcript(randomUUID());
        await runSessionStart(payload(learning, 'startup'), deps(firstRun));
        learning.prompt(earlier(1));
        learning.org(dev.workOrg, earlier(2));
        learning.reply(earlier(3));
        await write(learning, 'learn.md');
        dev.login({ org: dev.workOrg, organizationType: null });
      },
      'remembered',
    ],
    [
      'a personal login',
      () => {
        dev.attach();
        dev.login({ org: dev.workOrg, organizationType: 'claude_pro' });
      },
      undefined,
    ],
    [
      'a login whose plan the config does not show',
      () => {
        dev.attach();
        dev.login({ org: dev.workOrg, organizationType: null });
      },
      undefined,
    ],
    [
      'a login file that does not parse',
      () => {
        dev.attach();
        dev.unreadableLogin();
      },
      undefined,
    ],
    [
      'an opted-out attachment',
      () => {
        dev.attach({ workSubscriptions: 'off' });
        dev.login({ org: dev.workOrg });
      },
      undefined,
    ],
    [
      'a machine-wide attachment',
      () => {
        dev.attach({ mode: 'machine' });
        dev.login({ org: dev.workOrg });
      },
      undefined,
    ],
  ] as const)('the basis handed to the session start for %s', async (_label, setUp, basis) => {
    await setUp();
    const handed: Parameters<SessionStartDeps['handleSessionStart']>[0][] = [];
    await runSessionStart(
      payload(dev.transcript(randomUUID()), 'startup'),
      deps({
        handleSessionStart: (input, config) => {
          handed.push(input);
          return handleSessionStart(input, config);
        },
      }),
    );
    expect(handed).toHaveLength(1);
    expect(handed[0]?.accountBasis).toBe(basis);
  });
});

describe('the forwarding line at session start', () => {
  async function shownAtSessionStart(): Promise<string> {
    const shown: string[] = [];
    await runSessionStart(
      payload(dev.transcript(randomUUID()), 'startup'),
      deps({
        emit: (output) => {
          if ('systemMessage' in output) shown.push(output.systemMessage);
          return Promise.resolve();
        },
      }),
    );
    return shown.join('\n');
  }

  const UNDETERMINED_TAIL = 'otherwise it stays local, apart from work in an enrolled repository.';

  it('forwards only if the first reply shows an account enrolled by hand, with no stop command, when work subscriptions are off and the login file does not parse', async () => {
    dev.attach({ workSubscriptions: 'off', manual: [`claude:${dev.workOrg}`] });
    dev.unreadableLogin();
    const line = await shownAtSessionStart();
    expect(line.includes('only if its first reply shows an account enrolled by hand;')).toBe(true);
    expect(line.includes(UNDETERMINED_TAIL)).toBe(true);
    expect(line.includes('work subscription')).toBe(false);
    expect(line.includes('once Claude confirms')).toBe(false);
    expect(line.includes('--work-subscriptions')).toBe(false);
    expect(line.includes('aka unenroll')).toBe(false);
  });

  it('names the account enrolled by hand, not a work subscription, for a login on one while work subscriptions are on', async () => {
    dev.attach({ manual: [`claude:${dev.workOrg}`] });
    dev.login({ org: dev.workOrg });
    const line = await shownAtSessionStart();
    expect(line.includes('signed in to an account you enrolled by hand')).toBe(true);
    expect(line.includes('work subscription')).toBe(false);
    expect(line.includes('--work-subscriptions')).toBe(false);
    expect(line.includes('aka unenroll --account')).toBe(true);
  });

  it('forwards only if the first reply shows a work subscription or an account enrolled by hand, with no stop command, when work subscriptions are on and the login file does not parse', async () => {
    dev.attach({ manual: [`claude:${dev.workOrg}`] });
    dev.unreadableLogin();
    const line = await shownAtSessionStart();
    expect(
      line.includes(
        'only if its first reply shows a work subscription or an account enrolled by hand;',
      ),
    ).toBe(true);
    expect(line.includes(UNDETERMINED_TAIL)).toBe(true);
    expect(line.includes('once Claude confirms')).toBe(false);
    expect(line.includes('--work-subscriptions')).toBe(false);
    expect(line.includes('aka unenroll')).toBe(false);
  });

  it('names the work subscription and the opt-out for a work login while work subscriptions are on', async () => {
    dev.attach();
    dev.login({ org: dev.workOrg });
    const line = await shownAtSessionStart();
    expect(line.includes('once Claude confirms the work subscription')).toBe(true);
    expect(line.includes('only if its first reply shows')).toBe(false);
    expect(line.includes('aka unenroll --work-subscriptions')).toBe(true);
  });

  it('names the account enrolled by hand, not a work subscription, when work subscriptions are off and the login shows no plan', async () => {
    dev.attach({ workSubscriptions: 'off', manual: [`claude:${dev.workOrg}`] });
    dev.login({ org: dev.workOrg, organizationType: null });
    const line = await shownAtSessionStart();
    expect(line.includes('once Claude confirms')).toBe(true);
    expect(line.includes('work subscription')).toBe(false);
    expect(line.includes('--work-subscriptions')).toBe(false);
    expect(line.includes('aka unenroll --account')).toBe(true);
  });

  it('forwards only if the first reply shows a work subscription or an account enrolled by hand, with no stop command, when work subscriptions are on and the login shows no plan', async () => {
    dev.attach();
    dev.login({ org: dev.workOrg, organizationType: null });
    const line = await shownAtSessionStart();
    expect(
      line.includes(
        'only if its first reply shows a work subscription or an account enrolled by hand;',
      ),
    ).toBe(true);
    expect(line.includes(UNDETERMINED_TAIL)).toBe(true);
    expect(line.includes('once Claude confirms')).toBe(false);
    expect(line.includes('--work-subscriptions')).toBe(false);
    expect(line.includes('aka unenroll')).toBe(false);
  });
});
