import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type * as Persistence from '@akasecurity/persistence';
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import { recordSessionModel } from '@akasecurity/plugin-sdk';
import { ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX } from '@akasecurity/schema';
import { ESLint, Linter } from 'eslint';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as Remote from '../../../../packages/remote/src/index.ts';
import {
  NO_ACCOUNT,
  recordSessionStartAccount,
  resolveHookAccount,
  stampFor,
} from '../../src/hooks/account-stamp.ts';
import { handleProhibitedTurn } from '../../src/hooks/model-guard.ts';
import { runPreModelSwitch } from '../../src/hooks/model-switch-run.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import type * as Shared from '../../src/hooks/shared.ts';
import { openGatewayOrNull } from '../../src/hooks/store-health.ts';
import type { Device, Transcript } from '../helpers/account-fixture.ts';
import {
  device,
  isAgentKeyFor,
  OTHER_EMAIL,
  OTHER_TEST_KEY,
  PERSONAL_KEY,
  USER_EMAIL,
  WORK_KEY,
} from '../helpers/account-fixture.ts';
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

// A held lock on the identity record: the learned-org write times out and
// writes nothing, as `recordValidatedWorkAccount` does when its lock wait ends.
// `cap.filledBy` orgs are written first, as a parallel hook would write them,
// so the write's own cap check inside the lock refuses the session's org.
const lock = vi.hoisted(() => ({ held: false }));
const cap = vi.hoisted((): { filledBy: string[] } => ({ filledBy: [] }));
vi.mock('@akasecurity/persistence', async (importOriginal) => {
  const real = await importOriginal<typeof Persistence>();
  return {
    ...real,
    recordValidatedWorkAccount: (
      ...args: Parameters<typeof real.recordValidatedWorkAccount>
    ): ReturnType<typeof real.recordValidatedWorkAccount> => {
      if (lock.held) return 'timeout';
      const [dataDir, input, now] = args;
      for (const key of cap.filledBy.splice(0)) {
        real.recordValidatedWorkAccount(dataDir, { ...input, key }, now);
      }
      return real.recordValidatedWorkAccount(...args);
    },
  };
});

// The one UserPromptSubmit case drives the entry itself: stdin is the payload
// this holds, and what the entry would print is dropped. Every other case calls
// an importable run.
const stdin = vi.hoisted(() => ({ value: '' }));
vi.mock('../../src/hooks/shared.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof Shared>()),
  readStdin: () => Promise.resolve(stdin.value),
  emit: () => Promise.resolve(),
}));

let dev: Device;
beforeEach(() => {
  dev = device(sent);
});
afterEach(() => {
  lock.held = false;
  cap.filledBy = [];
  dev.dispose();
});

/** An instant `n` seconds after now, plus one, so it follows a boundary just recorded. */
const later = (n: number): string => new Date(Date.now() + (n + 1) * 1_000).toISOString();

// A session's first stretch, an hour before now: its boundary and its lines all
// precede anything a hook records now.
const AN_HOUR_AGO = Date.now() - 60 * 60 * 1_000;
const earlier = (n: number): string => new Date(AN_HOUR_AGO + n * 1_000).toISOString();

/** A session started now, with its first prompt, the host's org line and the first reply. */
function startedSession(org: string): Transcript {
  const t = dev.transcript(randomUUID());
  recordSessionStartAccount({
    config: dev.config(),
    sessionId: t.sessionId,
    transcriptPath: t.path,
    cwd: dev.personal,
    source: 'startup',
  });
  t.prompt(later(1));
  t.org(org, later(2));
  t.reply(later(3));
  return t;
}

/** A Write of `name` in `cwd`, run as the PreToolUse command hook runs it. */
async function write(t: Transcript, cwd: string, name = 'notes.md'): Promise<void> {
  await runPreToolUse(
    {
      session_id: t.sessionId,
      transcript_path: t.path,
      cwd,
      hook_event_name: 'PreToolUse',
      tool_name: 'Write',
      tool_input: { file_path: join(cwd, name), content: 'hello' },
    },
    () => Promise.resolve(),
    { mode: 'hook' },
  );
}

/** The scope key of every file write the store holds, oldest first. */
const captureKeys = (): (string | null)[] =>
  dev
    .storedRows()
    .filter((row) => row.eventType === 'code_change')
    .map((row) => row.scopeKey);

/** How many captures the client was handed. */
const forwarded = (): number => dev.sent.captures.reduce((n, batch) => n + batch.events.length, 0);

const refusalKeys = (): (string | null)[] =>
  dev
    .storedRows()
    .filter((row) => row.eventType === 'model_refusal')
    .map((row) => row.scopeKey);

function gatewayFor(): NonNullable<ReturnType<typeof openGatewayOrNull>> {
  const gateway = openGatewayOrNull(dev.config());
  if (gateway === null) throw new Error('the fixture opened no gateway');
  return gateway;
}

describe('a scoped attachment with no work-subscription setting, signed in to a work subscription', () => {
  beforeEach(() => {
    // No workSubscriptions field: a scoped attachment that never set it.
    dev.attach();
    dev.login({ org: dev.workOrg });
  });

  it('an existing attachment activates with no re-consent: a write in a personal folder is stamped with the agent key, forwarded, and its org learned', async () => {
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    expect(isAgentKeyFor(captureKeys()[0], dev.workOrg)).toBe(true);
    expect(forwarded()).toBe(1);
    expect(dev.learnedKeys()).toEqual([`claude:${dev.workOrg}`]);
  });

  it('sends that capture with no repository slug and no account material', async () => {
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    expect(dev.sent.captures[0]?.events[0]?.metadata?.repo).toBeUndefined();
    const wire = JSON.stringify(dev.sent.captures);
    for (const needle of [dev.workOrg, 'agent:', 'claude:', USER_EMAIL]) {
      expect(wire).not.toContain(needle);
    }
  });

  it('a work session in an enrolled repository keeps the repository key and its slug', async () => {
    const t = startedSession(dev.workOrg);
    await write(t, dev.work);
    expect(captureKeys()).toEqual([WORK_KEY]);
    expect(dev.sent.captures[0]?.events[0]?.metadata?.repo).toBe('work');
  });

  it("an API key helper in the folder's project settings keeps the repository key", async () => {
    mkdirSync(join(dev.personal, '.claude'), { recursive: true });
    writeFileSync(
      join(dev.personal, '.claude', 'settings.json'),
      JSON.stringify({ apiKeyHelper: 'print-key' }),
    );
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    expect(captureKeys()).toEqual([PERSONAL_KEY]);
    expect(forwarded()).toBe(0);
    expect(dev.learnedKeys()).toEqual([]);
  });

  it('turn 1 stays local: the first prompt of a new session keeps its repository key', async () => {
    const t = dev.transcript(randomUUID());
    recordSessionStartAccount({
      config: dev.config(),
      sessionId: t.sessionId,
      transcriptPath: t.path,
      cwd: dev.personal,
      source: 'startup',
    });
    t.prompt(later(1));
    stdin.value = JSON.stringify({
      session_id: t.sessionId,
      transcript_path: t.path,
      cwd: dev.personal,
      hook_event_name: 'UserPromptSubmit',
      prompt: 'a prompt',
    });
    const exit = vi
      .spyOn(process, 'exit')
      .mockImplementation((() => undefined) as typeof process.exit);
    try {
      await import('../../src/hooks/user-prompt-submit.ts');
    } finally {
      exit.mockRestore();
    }
    const prompts = dev.storedRows().filter((row) => row.eventType === 'prompt');
    expect(prompts.map((row) => row.scopeKey)).toEqual([PERSONAL_KEY]);
    expect(forwarded()).toBe(0);
  });

  it('refuses a prohibited model in a work session in a personal folder, with the row keyed to the session', async () => {
    await dev.prohibit(['claude-opus-5']);
    const t = startedSession(dev.workOrg);
    recordSessionModel(dev.dataDir, t.sessionId, 'claude-opus-5');
    const emitted: unknown[] = [];
    const refused = await handleProhibitedTurn(
      gatewayFor(),
      dev.dataDir,
      t.sessionId,
      t.path,
      dev.personal,
      (output) => {
        emitted.push(output);
        return Promise.resolve();
      },
    );
    expect(refused).toBe(true);
    expect(emitted).toEqual([expect.objectContaining({ decision: 'block' })]);
    expect(refusalKeys()).toHaveLength(1);
    expect(isAgentKeyFor(refusalKeys()[0], dev.workOrg)).toBe(true);
  });

  it('refuses a switch onto a prohibited model in a work session in a personal folder', async () => {
    await dev.prohibit(['claude-opus-5']);
    const t = startedSession(dev.workOrg);
    const config = dev.config();
    const refused = await runPreModelSwitch('claude-opus-5', t.sessionId, dev.personal, {
      config,
      openGateway: () => openGatewayOrNull(config),
      emit: () => Promise.resolve(),
      warnIfStoreRedirected: () => undefined,
      transcriptPath: t.path,
    });
    expect(refused).toBe(true);
    expect(isAgentKeyFor(refusalKeys()[0], dev.workOrg)).toBe(true);
  });

  it('a lock timeout still forwards through the admit, and the next hook writes the org', async () => {
    const t = startedSession(dev.workOrg);
    lock.held = true;
    await write(t, dev.personal);
    expect(isAgentKeyFor(captureKeys()[0], dev.workOrg)).toBe(true);
    expect(forwarded()).toBe(1);
    expect(dev.learnedKeys()).toEqual([]);
    lock.held = false;
    await write(t, dev.personal, 'second.md');
    expect(dev.learnedKeys()).toEqual([`claude:${dev.workOrg}`]);
    expect(forwarded()).toBe(2);
  });

  it("does not admit a session's account when the learned-account cap refuses it", async () => {
    const t = startedSession(dev.workOrg);
    cap.filledBy = Array.from(
      { length: ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX },
      () => `claude:${randomUUID()}`,
    );
    await write(t, dev.personal);
    expect(captureKeys()).toEqual([PERSONAL_KEY]);
    expect(forwarded()).toBe(0);
    expect(dev.learnedKeys()).toHaveLength(ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX);
    expect(dev.learnedKeys()).not.toContain(`claude:${dev.workOrg}`);
  });

  it('an opt-out written between two hooks makes the second stamp the repository key', async () => {
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    dev.optOut();
    await write(t, dev.personal, 'second.md');
    const [first, second] = captureKeys();
    expect(isAgentKeyFor(first, dev.workOrg)).toBe(true);
    expect(second).toBe(PERSONAL_KEY);
    expect(forwarded()).toBe(1);
    expect(dev.learnedKeys()).toEqual([]);
  });

  it('after an opt-out and an opt-in inside one session, the next hook learns the org again', async () => {
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    dev.optOut();
    await write(t, dev.personal, 'second.md');
    dev.optIn();
    await write(t, dev.personal, 'third.md');
    const keys = captureKeys();
    expect(keys[1]).toBe(PERSONAL_KEY);
    expect(isAgentKeyFor(keys[2], dev.workOrg)).toBe(true);
    expect(dev.learnedKeys()).toEqual([`claude:${dev.workOrg}`]);
    expect(forwarded()).toBe(2);
  });

  it('a re-attach as another user mid-session stamps the repository key', async () => {
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    dev.attach({ userEmail: OTHER_EMAIL, apiKey: OTHER_TEST_KEY });
    await write(t, dev.personal, 'second.md');
    const [first, second] = captureKeys();
    expect(isAgentKeyFor(first, dev.workOrg)).toBe(true);
    expect(second).toBe(PERSONAL_KEY);
    expect(dev.learnedKeys()).toEqual([]);
    expect(forwarded()).toBe(1);
  });
});

describe('a work session across a /clear, a missing boundary and two logins', () => {
  beforeEach(() => {
    dev.attach();
    dev.login({ org: dev.workOrg });
  });

  it('after a /clear, a hook keeps the repository key until the host names the org again, then forwards', async () => {
    const t = dev.transcript(randomUUID());
    const start = (source: 'startup' | 'clear', now?: () => number) =>
      recordSessionStartAccount({
        config: dev.config(),
        sessionId: t.sessionId,
        transcriptPath: t.path,
        cwd: dev.personal,
        source,
        now,
      });
    start('startup', () => AN_HOUR_AGO);
    t.prompt(earlier(1));
    t.org(dev.workOrg, earlier(2));
    t.reply(earlier(3));
    await write(t, dev.personal);
    start('clear');
    t.prompt(later(1));
    await write(t, dev.personal, 'after-clear.md');
    t.org(dev.workOrg, later(2));
    t.reply(later(3));
    await write(t, dev.personal, 'after-reply.md');
    const [beforeClear, afterClear, afterReply] = captureKeys();
    expect(isAgentKeyFor(beforeClear, dev.workOrg)).toBe(true);
    expect(afterClear).toBe(PERSONAL_KEY);
    expect(isAgentKeyFor(afterReply, dev.workOrg)).toBe(true);
  });

  it('a session with no recorded boundary keeps the repository key and teaches nothing', async () => {
    // No boundary: no session start recorded one for this session.
    const t = dev.transcript(randomUUID());
    t.prompt(later(1));
    t.org(dev.workOrg, later(2));
    t.reply(later(3));
    await write(t, dev.personal);
    expect(captureKeys()).toEqual([PERSONAL_KEY]);
    expect(forwarded()).toBe(0);
    expect(dev.learnedKeys()).toEqual([]);
  });

  it('two sessions under two Claude config dirs are each decided by their own login', async () => {
    const otherConfig = join(dev.home, 'personal-claude');
    dev.login({ org: dev.personalOrg, organizationType: 'claude_pro', configDir: otherConfig });
    const work = startedSession(dev.workOrg);
    vi.stubEnv('CLAUDE_CONFIG_DIR', otherConfig);
    const personal = startedSession(dev.personalOrg);
    await write(personal, dev.personal, 'personal.md');
    vi.stubEnv('CLAUDE_CONFIG_DIR', dev.home);
    await write(work, dev.personal, 'work.md');
    vi.stubEnv('CLAUDE_CONFIG_DIR', otherConfig);
    await write(personal, dev.personal, 'personal-again.md');
    const [first, second, third] = captureKeys();
    expect(first).toBe(PERSONAL_KEY);
    expect(isAgentKeyFor(second, dev.workOrg)).toBe(true);
    expect(third).toBe(PERSONAL_KEY);
    expect(forwarded()).toBe(1);
    expect(dev.sessionState(personal.sessionId).log).not.toMatch(/"k":"w"/);
  });
});

describe('a personal login on a scoped attachment', () => {
  beforeEach(() => {
    dev.attach();
    dev.login({ org: dev.personalOrg, organizationType: 'claude_pro' });
  });

  it('keeps the repository key, sends nothing and learns nothing', async () => {
    const t = startedSession(dev.personalOrg);
    await write(t, dev.personal);
    expect(captureKeys()).toEqual([PERSONAL_KEY]);
    expect(forwarded()).toBe(0);
    expect(dev.learnedKeys()).toEqual([]);
  });

  it('is not refused a prohibited model in a personal folder', async () => {
    await dev.prohibit(['claude-opus-5']);
    const t = startedSession(dev.personalOrg);
    recordSessionModel(dev.dataDir, t.sessionId, 'claude-opus-5');
    const gateway = gatewayFor();
    try {
      expect(
        await handleProhibitedTurn(gateway, dev.dataDir, t.sessionId, t.path, dev.personal, () =>
          Promise.resolve(),
        ),
      ).toBe(false);
    } finally {
      await gateway.close();
    }
    expect(refusalKeys()).toEqual([]);
  });
});

describe('an opted-out attachment', () => {
  it('an opted-out attachment stamps the repository key and learns nothing', async () => {
    dev.attach({ workSubscriptions: 'off' });
    dev.login({ org: dev.workOrg });
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    expect(captureKeys()).toEqual([PERSONAL_KEY]);
    expect(forwarded()).toBe(0);
    expect(dev.learnedKeys()).toEqual([]);
    // No reader ran: the session's state is its boundary alone, and nothing scanned the transcript.
    const state = dev.sessionState(t.sessionId);
    expect(state.log.trim().split('\n')).toEqual([expect.stringMatching(/"b":"startup"/)]);
    expect(state.scanCache).toBe(false);
  });

  it('still forwards a Claude account enrolled by hand', async () => {
    dev.attach({ workSubscriptions: 'off', manual: [`claude:${dev.workOrg}`] });
    dev.login({ org: dev.workOrg });
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    expect(isAgentKeyFor(captureKeys()[0], dev.workOrg)).toBe(true);
    expect(forwarded()).toBe(1);
    expect(dev.learnedKeys()).toEqual([]);
  });
});

describe('a machine-wide attachment', () => {
  it('stamps the repository key and keeps no session state', async () => {
    dev.attach({ mode: 'machine' });
    dev.login({ org: dev.workOrg });
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    expect(captureKeys()).toEqual([PERSONAL_KEY]);
    expect(forwarded()).toBe(1);
    expect(existsSync(join(dev.dataDir, 'session-accounts'))).toBe(false);
  });
});

describe('resolveHookAccount and stampFor', () => {
  it('a gateway with no account scope gives no account and the repository key, and records nothing', async () => {
    dev.login({ org: dev.workOrg });
    const t = dev.transcript(randomUUID());
    const gateway = resolveDataGateway(dev.config());
    try {
      const account = resolveHookAccount(gateway, {
        dataDir: dev.dataDir,
        sessionId: t.sessionId,
        transcriptPath: t.path,
        cwd: dev.personal,
      });
      expect(account).toEqual(NO_ACCOUNT);
      expect(stampFor(gateway, account, PERSONAL_KEY)).toBe(PERSONAL_KEY);
      expect(stampFor(gateway, account, undefined)).toBeUndefined();
    } finally {
      await gateway.close();
    }
    expect(existsSync(join(dev.dataDir, 'session-accounts'))).toBe(false);
  });

  it('checks a session once per gateway', async () => {
    dev.attach();
    dev.login({ org: dev.workOrg });
    const t = startedSession(dev.workOrg);
    const gateway = gatewayFor();
    try {
      const input = {
        dataDir: dev.dataDir,
        sessionId: t.sessionId,
        transcriptPath: t.path,
        cwd: dev.personal,
      };
      const first = resolveHookAccount(gateway, input);
      expect(resolveHookAccount(gateway, input)).toBe(first);
    } finally {
      await gateway.close();
    }
    // The session start's login view, then this gateway's one.
    expect(dev.sessionState(t.sessionId).log.match(/"k":"w"/g)).toHaveLength(2);
  });
});

describe('captures, policy questions and refusal rows go through stamped-capture.ts', () => {
  const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const resolved = new Map<string, Linter.RuleEntry | undefined>();

  beforeAll(async () => {
    const eslint = new ESLint({ cwd: PLUGIN_ROOT });
    for (const file of [
      'src/hooks/post-tool-use.ts',
      'src/mod/tokenize-run.ts',
      'src/hooks/stamped-capture.ts',
    ]) {
      const config = (await eslint.calculateConfigForFile(join(PLUGIN_ROOT, file))) as {
        rules?: Record<string, Linter.RuleEntry>;
      };
      resolved.set(file, config.rules?.['no-restricted-syntax']);
    }
  }, 60_000);

  /** How many messages `code` produces under the rule `file` resolves to. */
  const fired = (file: string, code: string): number =>
    new Linter().verify(code, {
      languageOptions: { ecmaVersion: 'latest', sourceType: 'module' },
      rules: { 'no-restricted-syntax': resolved.get(file) ?? 'off' },
    }).length;

  it.each([
    ['a capture', 'runtime.capture({ text });'],
    ['a capture by a computed name', "runtime['capture']({ text });"],
    ['a deferred capture', 'runtime.captureDeferred({ text });'],
    ['the governance question', 'governanceApplies(gateway, key);'],
    ['a refusal row', 'buildModelRefusalEvent({ id });'],
  ])('refuses %s in a hook and in a mod helper', (_label, code) => {
    expect(fired('src/hooks/post-tool-use.ts', code)).toBe(1);
    expect(fired('src/mod/tokenize-run.ts', code)).toBe(1);
  });

  it('allows them in stamped-capture.ts', () => {
    expect(
      fired('src/hooks/stamped-capture.ts', 'runtime.capture({ text }); governanceApplies(g, k);'),
    ).toBe(0);
  });

  it('still refuses a dynamic Drizzle or network import in a hook', () => {
    expect(fired('src/hooks/post-tool-use.ts', "await import('drizzle-orm');")).toBe(1);
    expect(fired('src/hooks/post-tool-use.ts', "await import('node:https');")).toBe(1);
  });
});
