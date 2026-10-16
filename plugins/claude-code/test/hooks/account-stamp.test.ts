import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type * as Persistence from '@akasecurity/persistence';
import { ATTACHED_IDENTITY_FILENAME, openLocalDatabase } from '@akasecurity/persistence';
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import { bundledDetections, recordSessionModel } from '@akasecurity/plugin-sdk';
import { ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX } from '@akasecurity/schema';
import { ESLint, Linter } from 'eslint';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as FileLock from '../../../../packages/persistence/src/file-lock.ts';
import type * as Remote from '../../../../packages/remote/src/index.ts';
import { scanHistory } from '../../src/history/scan.ts';
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
import { runModTokenize } from '../../src/mod/tokenize-run.ts';
import type { ToolCallAnswer } from '../../src/mod/tool-call-answer.ts';
import { runModToolCall } from '../../src/mod/tool-call-run.ts';
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

// A lock on the identity record that fails for a reason other than contention, which
// `recordValidatedWorkAccount` answers as refused rather than as a timeout. Every
// other lock is the real one.
const unavailable = vi.hoisted((): { file: string | undefined } => ({ file: undefined }));
vi.mock('../../../../packages/persistence/src/file-lock.ts', async (importOriginal) => {
  const real = await importOriginal<typeof FileLock>();
  return {
    ...real,
    withFileLock: <T>(file: string, fn: () => T, options?: FileLock.FileLockOptions): T => {
      if (file === unavailable.file) {
        throw new real.FileLockError('unavailable', file, 'refused by the test');
      }
      return real.withFileLock(file, fn, options);
    },
  };
});

// The UserPromptSubmit and PostToolUse cases drive their entries (runEntry):
// stdin is the payload this holds, and what the entry would print is dropped.
// Every other case calls an importable run. The fail-open count is a spy so a
// case can see a fault the hook swallowed.
const stdin = vi.hoisted(() => ({ value: '' }));
const failOpen = vi.hoisted(() => ({ count: vi.fn() }));
vi.mock('../../src/hooks/shared.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof Shared>()),
  readStdin: () => Promise.resolve(stdin.value),
  emit: () => Promise.resolve(),
  countFailOpen: failOpen.count,
}));

let dev: Device;
beforeEach(() => {
  failOpen.count.mockClear();
  dev = device(sent);
});
afterEach(() => {
  lock.held = false;
  cap.filledBy = [];
  unavailable.file = undefined;
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

/** The payload the host hands a hook of this session. */
const hookPayload = (t: Transcript, event: string): Record<string, unknown> => ({
  session_id: t.sessionId,
  transcript_path: t.path,
  cwd: dev.personal,
  hook_event_name: event,
});

/**
 * A hook entry run on `payload` the way the host runs it: the entry reads its
 * stdin, does its work on import, and what it would print is dropped. The module
 * registry is reset so each call runs the entry again. The clock reads zero:
 * PostToolUse spends a scan budget counted from process start, which a test
 * worker that has run for seconds has already used up.
 */
async function runEntry(entry: 'prompt' | 'post-tool-use', payload: object): Promise<void> {
  stdin.value = JSON.stringify(payload);
  vi.resetModules();
  const exit = vi
    .spyOn(process, 'exit')
    .mockImplementation((() => undefined) as typeof process.exit);
  const clock = vi.spyOn(performance, 'now').mockReturnValue(0);
  try {
    if (entry === 'prompt') await import('../../src/hooks/user-prompt-submit.ts');
    else await import('../../src/hooks/post-tool-use.ts');
  } finally {
    clock.mockRestore();
    exit.mockRestore();
  }
}

/** Every stored row of `eventType`, oldest first. */
const rowsOf = (eventType: string) => dev.storedRows().filter((row) => row.eventType === eventType);

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

const SECRET_RULE_ID = 'secrets/twilio-key';

/** The bundled secret rule's pack, and one value that rule detects. */
function secretRule() {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === SECRET_RULE_ID));
  const example = pack?.rules.find((r) => r.id === SECRET_RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${SECRET_RULE_ID} is missing or has no example`);
  }
  return { pack, example };
}

/**
 * A bundled rule's own example value, with that rule's pack set to redact in the
 * local store. A helper rewrites it in a data field and records the capture. In an
 * executable field the runtime resolves the redact into the workspace's
 * `redactFallback`: the shipped `warn` lets the command through unchanged, and a
 * `block` denies the call, which is still recorded.
 */
function redactableValue(): string {
  const { pack, example } = secretRule();
  const db = openLocalDatabase(dev.dataDir);
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(pack.namespace, pack.packId, 'redact');
  } finally {
    db.close();
  }
  return example;
}

/** What the tool.call mod helper answers for `tool` run with `input` in `t`'s session. */
async function modToolCall(
  t: Transcript,
  tool: string,
  input: Record<string, unknown>,
): Promise<ToolCallAnswer> {
  const run = await runModToolCall(
    JSON.stringify({ v: 1, tool, input, sessionId: t.sessionId, cwd: dev.personal }),
  );
  expect(run.code).toBe(0);
  return JSON.parse(run.stdout) as ToolCallAnswer;
}

const redactablePrompt = (): string =>
  `please deploy using this key: ${redactableValue()} and then tell me when it is done`;

/** How many login views of a work account the session's log holds. */
const workViews = (sessionId: string): number =>
  dev.sessionState(sessionId).log.match(/"k":"w"/g)?.length ?? 0;

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
    await runEntry('prompt', { ...hookPayload(t, 'UserPromptSubmit'), prompt: 'a prompt' });
    expect(rowsOf('prompt').map((row) => row.scopeKey)).toEqual([PERSONAL_KEY]);
    expect(forwarded()).toBe(0);
  });

  it('a later prompt, once the host has named the org, is stamped with the agent key and forwarded', async () => {
    const t = startedSession(dev.workOrg);
    t.prompt(later(4));
    await runEntry('prompt', { ...hookPayload(t, 'UserPromptSubmit'), prompt: 'a later prompt' });
    const prompts = rowsOf('prompt');
    expect(prompts).toHaveLength(1);
    expect(isAgentKeyFor(prompts[0]?.scopeKey, dev.workOrg)).toBe(true);
    expect(forwarded()).toBe(1);
  });

  it('a tool result carrying a finding is stamped with the agent key and forwarded', async () => {
    const t = startedSession(dev.workOrg);
    await runEntry('post-tool-use', {
      ...hookPayload(t, 'PostToolUse'),
      tool_name: 'Bash',
      tool_input: { command: 'cat .env' },
      tool_response: { stdout: `TWILIO=${secretRule().example}`, stderr: '' },
    });
    const responses = rowsOf('response');
    expect(responses).toHaveLength(1);
    expect(isAgentKeyFor(responses[0]?.scopeKey, dev.workOrg)).toBe(true);
    expect(forwarded()).toBe(1);
  });

  it.each([
    ['a prompt', 'prompt'],
    ['a conversation row', 'tool-result'],
  ])(
    'the tokenize mod helper stamps %s with the session account: the recorded key is the agent key, it is forwarded and the org is learned',
    async (_what, door) => {
      const t = startedSession(dev.workOrg);
      const viewsBefore = workViews(t.sessionId);
      const run = await runModTokenize(
        JSON.stringify({
          v: 1,
          text: redactablePrompt(),
          sessionId: t.sessionId,
          cwd: dev.personal,
          ...(door === 'prompt' ? {} : { row: { door } }),
        }),
      );
      expect(run.code).toBe(0);
      const recorded = rowsOf(door === 'prompt' ? 'prompt' : 'response');
      expect(recorded).toHaveLength(1);
      expect(isAgentKeyFor(recorded[0]?.scopeKey, dev.workOrg)).toBe(true);
      expect(forwarded()).toBe(1);
      expect(dev.learnedKeys()).toEqual([`claude:${dev.workOrg}`]);
      expect(failOpen.count).not.toHaveBeenCalled();
      expect(workViews(t.sessionId)).toBe(viewsBefore + 1);
    },
  );

  it('the tokenize mod helper keeps the repository key on turn 1, before the host has named the org', async () => {
    const t = dev.transcript(randomUUID());
    recordSessionStartAccount({
      config: dev.config(),
      sessionId: t.sessionId,
      transcriptPath: t.path,
      cwd: dev.personal,
      source: 'startup',
    });
    t.prompt(later(1));
    const run = await runModTokenize(
      JSON.stringify({ v: 1, text: redactablePrompt(), sessionId: t.sessionId, cwd: dev.personal }),
    );
    expect(run.code).toBe(0);
    expect(rowsOf('prompt').map((row) => row.scopeKey)).toEqual([PERSONAL_KEY]);
    expect(forwarded()).toBe(0);
  });

  it('the tool.call mod helper stamps a data field it rewrites with the session account: the recorded key is the agent key, it is forwarded and the org is learned', async () => {
    const t = startedSession(dev.workOrg);
    const value = redactableValue();
    const answer = await modToolCall(t, 'Write', {
      file_path: join(dev.personal, 'notes.md'),
      content: `key ${value}`,
    });
    expect(answer.deny === null).toBe(true);
    expect(answer.input === null).toBe(false);
    expect(JSON.stringify(answer.input).includes(value)).toBe(false);
    const recorded = rowsOf('code_change');
    expect(recorded).toHaveLength(1);
    expect(isAgentKeyFor(recorded[0]?.scopeKey, dev.workOrg)).toBe(true);
    expect(forwarded()).toBe(1);
    expect(dev.learnedKeys()).toEqual([`claude:${dev.workOrg}`]);
  });

  it('the tool.call mod helper stamps a command the shipped fallback lets through with the session account: the call is neither denied nor rewritten, the recorded key is the agent key and it is forwarded', async () => {
    const t = startedSession(dev.workOrg);
    const answer = await modToolCall(t, 'Bash', { command: `deploy --key ${redactableValue()}` });
    expect(answer.deny === null).toBe(true);
    expect(answer.input === null).toBe(true);
    const recorded = rowsOf('tool_use');
    expect(recorded).toHaveLength(1);
    expect(isAgentKeyFor(recorded[0]?.scopeKey, dev.workOrg)).toBe(true);
    expect(forwarded()).toBe(1);
  });

  it('the tool.call mod helper stamps a command the workspace blocks with the session account: the call is denied, the recorded key is the agent key, it is forwarded and the org is learned', async () => {
    dev.attach({ redactFallback: 'block' });
    const t = startedSession(dev.workOrg);
    const answer = await modToolCall(t, 'Bash', { command: `deploy --key ${redactableValue()}` });
    expect(typeof answer.deny).toBe('string');
    const recorded = rowsOf('tool_use');
    expect(recorded).toHaveLength(1);
    expect(isAgentKeyFor(recorded[0]?.scopeKey, dev.workOrg)).toBe(true);
    expect(forwarded()).toBe(1);
    expect(dev.learnedKeys()).toEqual([`claude:${dev.workOrg}`]);
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

  it('a second org named under one boundary ends the session account, and the hooks after it keep the repository key', async () => {
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    t.prompt(later(4));
    t.org(randomUUID(), later(5));
    t.reply(later(6));
    await write(t, dev.personal, 'after-change.md');
    await write(t, dev.personal, 'and-after.md');
    const keys = captureKeys();
    expect(isAgentKeyFor(keys[0], dev.workOrg)).toBe(true);
    expect(keys.slice(1).map((key) => key === PERSONAL_KEY)).toEqual([true, true]);
    expect(forwarded()).toBe(1);
    expect(dev.learnedKeys()).toEqual([`claude:${dev.workOrg}`]);
    const gateway = gatewayFor();
    try {
      const account = resolveHookAccount(gateway, {
        dataDir: dev.dataDir,
        sessionId: t.sessionId,
        transcriptPath: t.path,
        cwd: dev.personal,
      });
      expect(account.accountKey).toBeUndefined();
      expect(account.view).toEqual({ none: 'org-changed' });
    } finally {
      await gateway.close();
    }
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

describe('a session that starts before the attached-identity record exists', () => {
  beforeEach(() => {
    dev.attach({ identity: false });
    dev.login({ org: dev.workOrg });
  });

  it('is not stamped once the record appears, until a later session start records a boundary', async () => {
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    expect(dev.sessionState(t.sessionId).log.includes('"b":')).toBe(false);
    dev.writeIdentity();
    await write(t, dev.personal, 'record-present.md');
    expect(dev.sessionState(t.sessionId).log.includes('"b":')).toBe(false);
    recordSessionStartAccount({
      config: dev.config(),
      sessionId: t.sessionId,
      transcriptPath: t.path,
      cwd: dev.personal,
      source: 'clear',
    });
    await write(t, dev.personal, 'after-clear.md');
    const [first, second, third] = captureKeys();
    expect([first, second].map((key) => key === PERSONAL_KEY)).toEqual([true, true]);
    expect(isAgentKeyFor(third, dev.workOrg)).toBe(true);
    expect(forwarded()).toBe(1);
  });
});

describe('a work session whose key the identity record refuses to learn', () => {
  beforeEach(() => {
    dev.attach();
    dev.login({ org: dev.workOrg });
  });

  it.each<[string, (t: Transcript) => void]>([
    [
      'the learned-account cap is reached',
      () => {
        cap.filledBy = Array.from(
          { length: ATTACHED_IDENTITY_WORK_ACCOUNTS_MAX },
          () => `claude:${randomUUID()}`,
        );
      },
    ],
    [
      'the record does not hold for the credential the gateway was built with',
      (t) => {
        dev.attach({ apiKey: OTHER_TEST_KEY });
        dev.boundary(t);
      },
    ],
    [
      'the record lock cannot be taken for a reason other than a timeout',
      () => {
        unavailable.file = join(dev.dataDir, ATTACHED_IDENTITY_FILENAME);
      },
    ],
  ])('gives no account and answers the cap when %s', async (_cause, refuse) => {
    const t = startedSession(dev.workOrg);
    const gateway = gatewayFor();
    try {
      refuse(t);
      const account = resolveHookAccount(gateway, {
        dataDir: dev.dataDir,
        sessionId: t.sessionId,
        transcriptPath: t.path,
        cwd: dev.personal,
      });
      expect(account.accountKey).toBeUndefined();
      expect(account.admitWith).toBeUndefined();
      expect(account.view).toEqual({ none: 'cap-reached' });
      expect(stampFor(gateway, account, PERSONAL_KEY)).toBe(PERSONAL_KEY);
    } finally {
      await gateway.close();
    }
    expect(dev.learnedKeys().includes(`claude:${dev.workOrg}`)).toBe(false);
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

  it('keeps the repository key for a later prompt and a tool result, and forwards neither', async () => {
    const t = startedSession(dev.personalOrg);
    t.prompt(later(4));
    await runEntry('prompt', { ...hookPayload(t, 'UserPromptSubmit'), prompt: 'a later prompt' });
    await runEntry('post-tool-use', {
      ...hookPayload(t, 'PostToolUse'),
      tool_name: 'Bash',
      tool_input: { command: 'cat .env' },
      tool_response: { stdout: `TWILIO=${secretRule().example}`, stderr: '' },
    });
    expect(rowsOf('prompt').map((row) => row.scopeKey)).toEqual([PERSONAL_KEY]);
    expect(rowsOf('response').map((row) => row.scopeKey)).toEqual([PERSONAL_KEY]);
    expect(forwarded()).toBe(0);
    expect(dev.learnedKeys()).toEqual([]);
  });

  it('keeps the repository key for what the mod helpers record, and forwards nothing', async () => {
    dev.attach({ redactFallback: 'block' });
    const t = startedSession(dev.personalOrg);
    const value = redactableValue();
    const tokenized = await runModTokenize(
      JSON.stringify({ v: 1, text: `use ${value}`, sessionId: t.sessionId, cwd: dev.personal }),
    );
    const called = await runModToolCall(
      JSON.stringify({
        v: 1,
        tool: 'Bash',
        input: { command: `deploy --key ${value}` },
        sessionId: t.sessionId,
        cwd: dev.personal,
      }),
    );
    expect([tokenized.code, called.code]).toEqual([0, 0]);
    expect(rowsOf('prompt').map((row) => row.scopeKey)).toEqual([PERSONAL_KEY]);
    expect(rowsOf('tool_use').map((row) => row.scopeKey)).toEqual([PERSONAL_KEY]);
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

describe('a history backfill on an attachment that has learned a work account', () => {
  it("keys a leaking message by its repository alone, and sends nothing under the account's key", async () => {
    dev.attach();
    dev.login({ org: dev.workOrg });
    const t = startedSession(dev.workOrg);
    await write(t, dev.personal);
    expect(dev.learnedKeys()).toEqual([`claude:${dev.workOrg}`]);
    const sentBefore = forwarded();
    const root = join(dev.root, 'history');
    const project = join(root, '-notes');
    mkdirSync(project, { recursive: true });
    const record = {
      type: 'user',
      cwd: dev.personal,
      timestamp: new Date().toISOString(),
      message: { role: 'user', content: `deploy with ${secretRule().example}` },
    };
    writeFileSync(join(project, `${randomUUID()}.jsonl`), `${JSON.stringify(record)}\n`);
    const config = dev.config();

    await scanHistory(
      { ...config, settings: { ...config.settings, historicalAccess: 'full' } },
      { dir: root },
    );

    const prompts = dev.storedRows().filter((row) => row.eventType === 'prompt');
    expect(prompts.length).toBe(1);
    expect(prompts[0]?.scopeKey === PERSONAL_KEY).toBe(true);
    expect(forwarded()).toBe(sentBefore);
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
    ['a capture by a computed template name', 'runtime[`capture`]({ text });'],
    ['a deferred capture', 'runtime.captureDeferred({ text });'],
    ['a deferred capture by a computed template name', 'runtime[`captureDeferred`]({ text });'],
    ['a destructured capture', 'const { capture } = runtime; capture({ text });'],
    [
      'a destructured deferred capture',
      'const { captureDeferred } = runtime; captureDeferred({ text });',
    ],
    ['the governance question', 'governanceApplies(gateway, key);'],
    ['the governance question through a namespace', 'sdk.governanceApplies(gateway, key);'],
    [
      'the governance question through a namespace by a computed name',
      "sdk['governanceApplies'](gateway, key);",
    ],
    [
      'the governance question through a namespace by a computed template name',
      'sdk[`governanceApplies`](gateway, key);',
    ],
    [
      'an aliased import of the governance question',
      "import { governanceApplies as ga } from 'x';",
    ],
    [
      'an import of the governance question by a string name',
      "import { 'governanceApplies' as ga } from 'x';",
    ],
    ['a refusal row', 'buildModelRefusalEvent({ id });'],
    ['a refusal row through a namespace', 'sdk.buildModelRefusalEvent({ id });'],
    [
      'a refusal row through a namespace by a computed name',
      "sdk['buildModelRefusalEvent']({ id });",
    ],
    [
      'a refusal row through a namespace by a computed template name',
      'sdk[`buildModelRefusalEvent`]({ id });',
    ],
    [
      'an aliased import of the refusal row',
      "import { buildModelRefusalEvent as build } from 'x';",
    ],
  ])('refuses %s in a hook and in a mod helper', (_label, code) => {
    expect(fired('src/hooks/post-tool-use.ts', code)).toBe(1);
    expect(fired('src/mod/tokenize-run.ts', code)).toBe(1);
  });

  it.each([
    ['a call whose name is held in a variable', 'runtime[method]({ text });'],
    [
      'a call whose name is a template holding only an expression',
      'runtime[`${method}`]({ text });',
    ],
    [
      'a call whose name is a template that starts with a refused name and holds an expression',
      'runtime[`capture${suffix}`]({ text });',
    ],
    [
      'a call through a binding renamed by assignment',
      'const send = runtime.capture; send({ text });',
    ],
    [
      'a call through a binding renamed by destructuring',
      'const { capture: send } = runtime; send({ text });',
    ],
    ['an indirect call through call', 'runtime.capture.call(runtime, { text });'],
  ])('does not see %s', (_label, code) => {
    expect(fired('src/hooks/post-tool-use.ts', code)).toBe(0);
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
