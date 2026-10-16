/**
 * A Codex thread on a ChatGPT work subscription, driven through the REAL built
 * hooks against a throwaway attached home. A hook entry runs main() on import
 * and can never be imported by a test, so a hook that forgot to ask for the
 * thread's account, or to pass it on, is visible only in the key of the row it
 * wrote. The key never leaves the machine, so nothing else would notice.
 *
 * The deployment is an address that refuses connections: what a recognised
 * thread sends is asserted where the gateway is driven in process, and here the
 * rows the hooks leave in the local store say which key each site stamped.
 */
import { randomUUID } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  openLocalDatabase,
  readAttachedIdentity,
  sessionAccountsDir,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { createPolicyStore, SYNC_MARKER_NAME } from '@akasecurity/plugin-runtime';
import { bundledDetections, claimSessionStart } from '@akasecurity/plugin-sdk';
import { readObservations } from '@akasecurity/plugin-sdk/account';
import {
  agentKey,
  ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
  type SessionAccountObservation,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { writeCodexAuth } from '../../../../packages/plugin-sdk/test/helpers/fake-jwt.ts';
import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { runHook, tempHomeEnv } from '../helpers/run-hook.ts';

const BUILT_SCRIPTS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts');
// Detached children the hooks spawn by path, left out of the copy the hooks run
// from so none outlives the case that started it.
const DETACHED_CHILDREN = ['reconcile.js', 'sync.js', 'history-sync.js', 'content-retention.js'];

const RULE_ID = 'secrets/twilio-key';
const PERSONAL_REMOTE = 'https://github.com/me/notes.git';
const PERSONAL_KEY = 'github.com/me/notes';
const LOCAL_ONLY =
  'AKA: local-only (not enrolled); work in an enrolled repository is still forwarded';
const WORK_LINE =
  'AKA: forwarding this thread to Acme — signed in to a ChatGPT work subscription; it stops if the thread is resumed or its login changes.';
const PENDING_LINE =
  "This thread's ChatGPT account is checked once more at its next prompt or tool call. If it is a work subscription, or a workspace you enrolled by hand, the thread's prompts, tool calls and results are forwarded to Acme from any folder from then on.";
const RESUMED_LINE =
  'AKA: this thread first ran under a ChatGPT workspace forwarded to Acme; from here it follows the repository rule, so only work in an enrolled repository is forwarded.';

function secretFixture(): { pack: ReturnType<typeof bundledDetections>[number]; example: string } {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return { pack, example };
}

const { pack: SECRET_PACK, example: SECRET } = secretFixture();

interface RecordedApplyPatch extends Record<string, unknown> {
  tool_input: { command: string };
}

function recorded(file: string): RecordedApplyPatch {
  return JSON.parse(
    readFileSync(new URL(`../fixtures/hooks/${file}`, import.meta.url), 'utf8'),
  ) as RecordedApplyPatch;
}

const PATCH_PRE = recorded('apply_patch.pre-tool-use.json');
const PATCH_POST = recorded('apply_patch.post-tool-use.json');

const MANAGED_FILENAME = '"managed-settings.json"';
const ABSENT_FILENAME = '"managed-settings.absent.json"';
const HOOKS_RUN = ['session-start', 'user-prompt-submit', 'pre-tool-use', 'post-tool-use', 'stop'];

/**
 * Points every built script's administrator overlay at a file that does not
 * exist. A hook child reads the overlay from an absolute system path that a temp
 * home cannot redirect, so on a machine enrolled with an administrator it would
 * pin the attachment this case builds. The filename is the only thing that
 * differs from the shipped bundles, and every hook the cases run must hold it,
 * so a bundle that spells it differently fails here rather than keeping the
 * overlay.
 */
function withoutAdministrator(scripts: string): void {
  const rewritten: string[] = [];
  for (const name of readdirSync(scripts)) {
    if (!name.endsWith('.js')) continue;
    const file = join(scripts, name);
    const text = readFileSync(file, 'utf8');
    if (!text.includes(MANAGED_FILENAME)) continue;
    writeFileSync(file, text.replaceAll(MANAGED_FILENAME, ABSENT_FILENAME));
    rewritten.push(name);
  }
  for (const hook of HOOKS_RUN) expect(rewritten, hook).toContain(`${hook}.js`);
}

interface Row {
  kind: string;
  key: string | null;
}

interface Thread {
  sessionId: string;
  transcriptPath: string;
  /** Writes the thread's first rollout line, for a thread made `late`. */
  writeHead(): void;
}

interface Device {
  readonly personal: string;
  readonly workspace: string;
  readonly member: string;
  readonly agent: string;
  run(
    hook: string,
    payload: Record<string, unknown>,
    env?: Record<string, string>,
  ): ReturnType<typeof runHook>;
  thread(options?: { provider?: string; model?: string; late?: boolean }): Thread;
  lapseClaims(): void;
  signIn(plan: string, account?: string, email?: string): void;
  rows(): Row[];
  log(sessionId: string): SessionAccountObservation[];
  prohibit(models: string[]): Promise<void>;
}

interface DeviceOptions {
  manual?: boolean;
  signedIn?: { plan: string; email?: string } | undefined;
}

/** A personal device attached scoped, with Codex signed in as the member, and the dir it all lives under. */
function withDevice(
  options: DeviceOptions,
  body: (device: Device) => void | Promise<void>,
): Promise<void> {
  const home = mkdtempSync(join(tmpdir(), 'aka-codex-account-e2e-'));
  const base = join(home, '.aka');
  const scripts = join(home, 'scripts');
  const endpoint = 'http://127.0.0.1:9';
  const workspace = randomUUID();
  const member = `member-${randomUUID().slice(0, 8)}@example.test`;
  const apiKey = `test-${randomUUID()}`;
  const personal = join(home, 'personal');
  mkdirSync(join(personal, '.git'), { recursive: true });
  writeFileSync(
    join(personal, '.git', 'config'),
    `[remote "origin"]\n\turl = ${PERSONAL_REMOTE}\n`,
  );
  cpSync(BUILT_SCRIPTS, scripts, { recursive: true });
  withoutAdministrator(scripts);
  for (const name of DETACHED_CHILDREN) {
    rmSync(join(scripts, name));
    expect(existsSync(join(scripts, name))).toBe(false);
  }
  const db = openLocalDatabase(dataDirOf(base));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(SECRET_PACK.namespace, SECRET_PACK.packId, 'monitor');
  } finally {
    db.close();
  }
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint, label: 'Acme', attachedAt: '2026-10-01T09:00:00.000Z' },
      attachmentScope: {
        endpoint,
        tenantName: 'Acme',
        userEmail: member,
        entries:
          options.manual === true
            ? [
                {
                  kind: 'account',
                  identity: `chatgpt:${workspace}`,
                  enrolledAt: '2026-10-02T09:00:00.000Z',
                  codingAgents: true,
                },
              ]
            : [],
      },
    },
    base,
    null,
  );
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: ATTACHED_CREDENTIAL_SCOPED_SPEC_VERSION,
    mode: 'scoped',
    endpoint,
    apiKey,
  });
  writeAttachedIdentity(dataDirOf(base), {
    endpoint,
    apiKey,
    tenantName: 'Acme',
    userEmail: member,
  });
  writeFileSync(join(dataDirOf(base), SYNC_MARKER_NAME), String(Date.now()));
  const record = readAttachedIdentity(dataDirOf(base));
  if (record === undefined) throw new Error('no identity record');
  const agent = agentKey(record.scopeTag, `chatgpt:${workspace}`);
  if (agent === undefined) throw new Error('the test agent key did not form');
  const signIn = (plan: string, account = workspace, email = member): void => {
    writeCodexAuth(join(home, '.codex'), { accountId: account, email, plan });
  };
  if (options.signedIn !== undefined) {
    signIn(options.signedIn.plan, workspace, options.signedIn.email ?? member);
  }
  const device: Device = {
    personal,
    workspace,
    member,
    agent,
    run: (hook, payload, env = {}) =>
      runHook(hook, JSON.stringify(payload), {
        env: { ...tempHomeEnv(home), ...env },
        scriptsDir: scripts,
      }),
    thread: ({ provider = 'openai', model, late = false } = {}) => {
      const sessionId = randomUUID();
      const sessions = join(home, '.codex', 'sessions');
      mkdirSync(sessions, { recursive: true });
      const transcriptPath = join(sessions, `rollout-${sessionId}.jsonl`);
      const lines: unknown[] = [
        {
          timestamp: new Date().toISOString(),
          type: 'session_meta',
          payload: {
            session_id: sessionId,
            id: sessionId,
            cwd: personal,
            originator: 'codex_cli_rs',
            model_provider: provider,
            creator_account_id: workspace,
          },
        },
      ];
      if (model !== undefined) {
        lines.push({
          timestamp: new Date().toISOString(),
          type: 'turn_context',
          payload: { turn_id: 'turn-1', cwd: personal, model },
        });
      }
      const writeHead = (): void => {
        writeFileSync(transcriptPath, `${lines.map((line) => JSON.stringify(line)).join('\n')}\n`);
      };
      if (!late) writeHead();
      return { sessionId, transcriptPath, writeHead };
    },
    lapseClaims: () => {
      for (let i = 0; i < 40; i++) claimSessionStart(dataDirOf(base), randomUUID());
    },
    signIn,
    rows: () => {
      const handle = new DatabaseSync(join(dataDirOf(base), 'aka.db'), { readOnly: true });
      try {
        return handle
          .prepare(
            `SELECT event_type AS kind, scope_key AS key FROM audit_events
             WHERE event_type IN ('session', 'prompt', 'response', 'tool_use', 'code_change', 'model_refusal')`,
          )
          .all() as unknown as Row[];
      } finally {
        handle.close();
      }
    },
    log: (sessionId) =>
      readObservations(sessionAccountsDir(dataDirOf(base)), sessionId).entries.map(
        (entry) => entry.observation,
      ),
    prohibit: (models) =>
      createPolicyStore(dataDirOf(base)).write({
        version: 'test',
        policies: [],
        customKeywords: [],
        prohibitedModels: models,
        fetchedAt: new Date().toISOString(),
      }),
  };
  return Promise.resolve()
    .then(() => body(device))
    .finally(() => {
      removeTree(home);
    });
}

function startPayload(thread: Thread, cwd: string, source: string): Record<string, unknown> {
  return {
    session_id: thread.sessionId,
    transcript_path: thread.transcriptPath,
    cwd,
    hook_event_name: 'SessionStart',
    source,
  };
}

function promptPayload(thread: Thread, cwd: string, prompt: string): Record<string, unknown> {
  return {
    prompt,
    session_id: thread.sessionId,
    transcript_path: thread.transcriptPath,
    cwd,
    hook_event_name: 'UserPromptSubmit',
  };
}

/** Every hook that records, run once for a thread, with a secret so the finding-only sites record too. */
function recordEverySite(device: Device, thread: Thread): void {
  const base = { session_id: thread.sessionId, transcript_path: thread.transcriptPath };
  const cwd = device.personal;
  const runs = [
    device.run('user-prompt-submit', promptPayload(thread, cwd, `deploy using ${SECRET}`)),
    device.run('pre-tool-use', {
      ...base,
      tool_name: 'Bash',
      tool_input: { command: `export TWILIO_KEY=${SECRET}` },
      cwd,
      hook_event_name: 'PreToolUse',
    }),
    device.run('post-tool-use', {
      ...base,
      tool_name: 'Bash',
      tool_input: { command: 'cat .env' },
      tool_response: { stdout: `TWILIO_KEY=${SECRET}`, stderr: '' },
      cwd,
      hook_event_name: 'PostToolUse',
    }),
    device.run('pre-tool-use', { ...PATCH_PRE, ...base, cwd }),
    device.run('post-tool-use', {
      ...PATCH_POST,
      ...base,
      tool_response: `Exit code: 0\nOutput:\nTWILIO_KEY=${SECRET}\n`,
      cwd,
    }),
  ];
  for (const run of runs) expect(run.status, run.stderr).toBe(0);
}

const KINDS = ['session', 'prompt', 'tool_use', 'response', 'code_change'] as const;
type Kind = (typeof KINDS)[number];

/** The keys the rows of each kind carry, in no order: a Bash result and a patch result are two response rows. */
function expectKeys(rows: Row[], expected: Record<Kind, (string | null)[]>): void {
  for (const kind of KINDS) {
    const keys = rows.filter((row) => row.kind === kind).map((row) => row.key ?? '');
    expect(keys.sort(), kind).toEqual(expected[kind].map((key) => key ?? '').sort());
  }
}

/** Every site keyed by the thread, an apply_patch included. */
const workThread = (agent: string): Record<Kind, string[]> => ({
  session: [agent],
  prompt: [agent],
  tool_use: [agent],
  response: [agent, agent],
  code_change: [agent],
});

/** Every site keyed by where it ran; an apply_patch and its result carry no key. */
const folderRule: Record<Kind, (string | null)[]> = {
  session: [PERSONAL_KEY],
  prompt: [PERSONAL_KEY],
  tool_use: [PERSONAL_KEY],
  response: [PERSONAL_KEY, null],
  code_change: [null],
};

function systemMessage(stdout: string): string | undefined {
  if (stdout.trim() === '') return undefined;
  const parsed = JSON.parse(stdout) as { systemMessage?: unknown };
  return typeof parsed.systemMessage === 'string' ? parsed.systemMessage : undefined;
}

describe('a Codex thread on a ChatGPT work subscription, through the built hooks', () => {
  it('says so at session start, and every site stamps the thread key from a folder in no enrolled repository', () =>
    withDevice({ signedIn: { plan: 'business' } }, (device) => {
      const thread = device.thread();
      const started = device.run('session-start', startPayload(thread, device.personal, 'startup'));
      expect(started.status, started.stderr).toBe(0);
      const line = systemMessage(started.stdout) ?? '';
      expect(line).toContain(WORK_LINE);
      for (const material of ['chatgpt:', 'agent:', device.workspace]) {
        expect(line).not.toContain(material);
      }
      recordEverySite(device, thread);
      expectKeys(device.rows(), workThread(device.agent));
    }));

  it('keeps the repository rule for a resumed thread at session start and at every site', () =>
    withDevice({ signedIn: { plan: 'business' } }, (device) => {
      const thread = device.thread();
      const started = device.run('session-start', startPayload(thread, device.personal, 'resume'));
      expect(systemMessage(started.stdout)).toContain(LOCAL_ONLY);
      recordEverySite(device, thread);
      expectKeys(device.rows(), folderRule);
    }));

  it.each<[string, DeviceOptions, { provider?: string }, Record<string, string>]>([
    ['a personal plan', { signedIn: { plan: 'plus' } }, {}, {}],
    ['another email', { signedIn: { plan: 'business', email: 'other@example.test' } }, {}, {}],
    ['another provider', { signedIn: { plan: 'business' } }, { provider: 'azure' }, {}],
    ['no login file', {}, {}, {}],
    [
      'an API key in the environment',
      { signedIn: { plan: 'business' } },
      {},
      { CODEX_API_KEY: 'k' },
    ],
    [
      'a gateway',
      { signedIn: { plan: 'business' } },
      {},
      { OPENAI_BASE_URL: 'https://gateway.example.test/v1' },
    ],
  ])('keeps the repository rule for %s', (_name, options, head, env) =>
    withDevice(options, (device) => {
      const thread = device.thread(head);
      const started = device.run(
        'session-start',
        startPayload(thread, device.personal, 'startup'),
        env,
      );
      expect(systemMessage(started.stdout)).toContain(LOCAL_ONLY);
      for (const run of [
        device.run(
          'user-prompt-submit',
          promptPayload(thread, device.personal, `deploy using ${SECRET}`),
          env,
        ),
        device.run(
          'pre-tool-use',
          {
            session_id: thread.sessionId,
            transcript_path: thread.transcriptPath,
            tool_name: 'Bash',
            tool_input: { command: `export TWILIO_KEY=${SECRET}` },
            cwd: device.personal,
            hook_event_name: 'PreToolUse',
          },
          env,
        ),
      ]) {
        expect(run.status, run.stderr).toBe(0);
      }
      const rows = device.rows().filter((row) => row.kind === 'prompt' || row.kind === 'tool_use');
      expect(rows.length).toBe(2);
      expect(rows.every((row) => row.key === PERSONAL_KEY)).toBe(true);
    }),
  );

  it('forwards a thread of a workspace enrolled by hand whatever the plan or email, and not a resumed one', () =>
    withDevice(
      { manual: true, signedIn: { plan: 'plus', email: 'other@example.test' } },
      (device) => {
        const fresh = device.thread();
        const started = device.run(
          'session-start',
          startPayload(fresh, device.personal, 'startup'),
        );
        expect(systemMessage(started.stdout)).toContain(
          'signed in to a ChatGPT workspace you enrolled by hand',
        );
        expect(
          device.run('user-prompt-submit', promptPayload(fresh, device.personal, 'a prompt'))
            .status,
        ).toBe(0);
        const resumed = device.thread();
        device.run('session-start', startPayload(resumed, device.personal, 'resume'));
        expect(
          device.run('user-prompt-submit', promptPayload(resumed, device.personal, 'a prompt'))
            .status,
        ).toBe(0);
        const prompts = device.rows().filter((row) => row.kind === 'prompt');
        expect(prompts.map((row) => row.key).sort()).toEqual([device.agent, PERSONAL_KEY].sort());
      },
    ));

  it('ends a thread for good when its workspace changes, and the Stop check writes that down', () =>
    withDevice({ signedIn: { plan: 'business' } }, (device) => {
      const thread = device.thread();
      device.run('session-start', startPayload(thread, device.personal, 'startup'));
      device.signIn('business');
      expect(
        device.run('user-prompt-submit', promptPayload(thread, device.personal, 'first')).status,
      ).toBe(0);
      device.signIn('business', randomUUID());
      const stopped = device.run('stop', {
        session_id: thread.sessionId,
        transcript_path: thread.transcriptPath,
        cwd: device.personal,
        hook_event_name: 'Stop',
      });
      expect(stopped.status, stopped.stderr).toBe(0);
      const ended = device.log(thread.sessionId).at(-1);
      expect(ended).toMatchObject({ s: 'none' });
      expect(ended !== undefined && 'start' in ended).toBe(false);
      device.signIn('business');
      expect(
        device.run('user-prompt-submit', promptPayload(thread, device.personal, 'second')).status,
      ).toBe(0);
      const prompts = device.rows().filter((row) => row.kind === 'prompt');
      expect(prompts.map((row) => row.key)).toEqual([device.agent, PERSONAL_KEY]);
    }));

  it('says a thread whose first record is not on disk yet is checked once more, and decides it at its next prompt', () =>
    withDevice({ signedIn: { plan: 'business' } }, (device) => {
      const thread = device.thread({ late: true });
      const started = device.run('session-start', startPayload(thread, device.personal, 'startup'));
      expect(started.status, started.stderr).toBe(0);
      expect(systemMessage(started.stdout)).toContain(`${LOCAL_ONLY}. ${PENDING_LINE}`);
      thread.writeHead();
      expect(
        device.run('user-prompt-submit', promptPayload(thread, device.personal, 'a prompt')).status,
      ).toBe(0);
      const rows = device.rows();
      expect(rows.filter((row) => row.kind === 'session').map((row) => row.key)).toEqual([
        PERSONAL_KEY,
      ]);
      expect(rows.filter((row) => row.kind === 'prompt').map((row) => row.key)).toEqual([
        device.agent,
      ]);
    }));

  it('keeps the repository rule for good when the first record is still missing at the next prompt', () =>
    withDevice({ signedIn: { plan: 'business' } }, (device) => {
      const thread = device.thread({ late: true });
      device.run('session-start', startPayload(thread, device.personal, 'startup'));
      expect(
        device.run('user-prompt-submit', promptPayload(thread, device.personal, 'first')).status,
      ).toBe(0);
      thread.writeHead();
      expect(
        device.run('user-prompt-submit', promptPayload(thread, device.personal, 'second')).status,
      ).toBe(0);
      expect(
        device
          .rows()
          .filter((row) => row.kind === 'prompt')
          .map((row) => row.key),
      ).toEqual([PERSONAL_KEY, PERSONAL_KEY]);
    }));

  it('words a work thread resumed after its session claim lapsed as following the repository rule', () =>
    withDevice({ signedIn: { plan: 'business' } }, (device) => {
      const thread = device.thread();
      const first = device.run('session-start', startPayload(thread, device.personal, 'startup'));
      expect(systemMessage(first.stdout)).toContain(WORK_LINE);
      device.lapseClaims();
      const resumed = device.run('session-start', startPayload(thread, device.personal, 'resume'));
      expect(systemMessage(resumed.stdout)).toContain(RESUMED_LINE);
      expect(
        device.run('user-prompt-submit', promptPayload(thread, device.personal, 'after')).status,
      ).toBe(0);
      expect(
        device
          .rows()
          .filter((row) => row.kind === 'prompt')
          .map((row) => row.key),
      ).toEqual([PERSONAL_KEY]);
    }));

  it('refuses a prohibited model in a folder no enrolled repository covers, for a work thread only', () =>
    withDevice({ signedIn: { plan: 'business' } }, async (device) => {
      await device.prohibit(['o3']);
      const thread = device.thread({ model: 'o3' });
      device.run('session-start', startPayload(thread, device.personal, 'startup'));
      const refused = device.run(
        'user-prompt-submit',
        promptPayload(thread, device.personal, 'a prompt'),
      );
      expect(refused.stdout).toContain('"decision":"block"');
      expect(device.rows().filter((row) => row.kind === 'model_refusal')).toEqual([
        { kind: 'model_refusal', key: device.agent },
      ]);
    }));

  it('allows a prohibited model in that folder for a thread that is not a work thread', () =>
    withDevice({ signedIn: { plan: 'plus' } }, async (device) => {
      await device.prohibit(['o3']);
      const thread = device.thread({ model: 'o3' });
      device.run('session-start', startPayload(thread, device.personal, 'startup'));
      const allowed = device.run(
        'user-prompt-submit',
        promptPayload(thread, device.personal, 'a prompt'),
      );
      expect(allowed.stdout).not.toContain('"decision":"block"');
      expect(device.rows().filter((row) => row.kind === 'model_refusal')).toEqual([]);
    }));
});
