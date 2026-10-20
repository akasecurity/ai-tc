/**
 * The four in-process handlers, each driven by the VS Code 1.141.0 payloads
 * recorded for its event in `test/fixtures/vscode/plugin-load-1.141/`, against
 * a real temp home.
 *
 * The payloads are read from the fixture directory and never restated here.
 * Two things are re-pointed in each: `cwd` (and `create_file`'s `filePath`
 * under it), because the recorded workspace does not exist on this machine,
 * and a flagged VARIANT's field, which takes a value from a bundled rule's own
 * `examples` at runtime so no credential-shaped literal is written here.
 *
 * What a recording produced on the recorded host is the expectation: the rows,
 * their event types, the session's interface, the scope key, and stdout — a
 * `systemMessage` where a finding was warned (and the first-run notice), and
 * nothing otherwise. Every recording that produced no finding is paired with a
 * flagged variant that does, so its silence is a decision rather than a scan
 * that never ran.
 */
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, LARGE_INPUT_THRESHOLD_CHARS } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { runPostToolUse } from '../../src/hooks/post-tool-use-run.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import { runSessionStart } from '../../src/hooks/session-start-run.ts';
import type { HookHandler } from '../../src/hooks/shared.ts';
import { runUserPromptSubmit } from '../../src/hooks/user-prompt-submit-run.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';
import { ruleExample } from '../helpers/rule-example.ts';

const FIXTURE_DIR = fileURLToPath(
  new URL('../fixtures/vscode/plugin-load-1.141/', import.meta.url),
);

type Payload = Record<string, unknown>;

/** A recording, parsed fresh on every read so no case can mutate another's. */
function recorded(name: string): Payload {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, `${name}.json`), 'utf8')) as Payload;
}

// The handler each recording's hook command ran, and the argv token it passed:
// the camelCase `hooks.json` key the file is named after.
const HANDLERS: Record<string, HookHandler> = {
  sessionStart: runSessionStart,
  userPromptSubmitted: runUserPromptSubmit,
  preToolUse: runPreToolUse,
  postToolUse: runPostToolUse,
};

// Every recording in the directory, in the order the session fired them: the
// host stamped each payload with its own `timestamp`, so the order is read off
// the recordings rather than restated. Derived, so a recording added to the
// directory is replayed here without an edit.
const SESSION: readonly string[] = readdirSync(FIXTURE_DIR)
  .filter((file) => file !== 'README.md')
  .map((file) => {
    if (!file.endsWith('.json')) throw new Error(`unexpected fixture file ${file}`);
    return file.slice(0, -'.json'.length);
  })
  .map((name) => ({ name, at: Date.parse(String(recorded(name).timestamp)) }))
  .sort((a, b) => a.at - b.at)
  .map((entry) => entry.name);

const SESSION_ID = String(recorded('sessionStart').session_id);
const RECORDED_CWD = String(recorded('sessionStart').cwd);

const SAMPLE_RULE = 'secrets/twilio-key';
const SAMPLE = ruleExample(SAMPLE_RULE);

// The finding the recorded host stored for the recorded `run_in_terminal` call.
const COMMAND_RULE = 'command-risk/credential-file-read';
const COMMAND = ruleExample(COMMAND_RULE);

// The userinfo in an scp-style remote reads as an email address to a scanner,
// so the remote is built from parts.
const AT = String.fromCharCode(64);
const WORK_REMOTE = `git${AT}GitHub.com:acme/work-repo.git`;
const WORK_KEY = 'github.com/acme/work-repo';

let root: string;
let akaHome: string;
let home: string;
let cwd: string;
let stderr: string[];
// `(node:1234) ExperimentalWarning: …` and the `--trace-warnings` hint after it.
const NODE_WARNING = /^\(node:\d+\) |--trace-warnings/u;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-copilot-vscode-recorded-'));
  akaHome = join(root, 'aka-home');
  home = join(root, 'home');
  mkdirSync(home);
  cwd = join(root, 'work');
  mkdirSync(join(cwd, '.git'), { recursive: true });
  writeFileSync(join(cwd, '.git', 'config'), `[remote "origin"]\n\turl = ${WORK_REMOTE}\n`);
  stderr = [];
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
    stderr.push(String(chunk));
    return true;
  });
});

/**
 * Everything written to stderr except node's own runtime warnings — the hook's
 * notices AND the SDK's `[aka]` lines.
 */
function akaStderr(): string {
  return stderr.filter((line) => !NODE_WARNING.test(line)).join('');
}

afterEach(() => {
  vi.restoreAllMocks();
  removeTrees([root]);
});

/** The recording with its workspace re-pointed at this test's checkout. */
function repointed(name: string): Payload {
  const payload = recorded(name);
  expect(payload.cwd, `${name} names the recorded workspace`).toBe(RECORDED_CWD);
  payload.cwd = cwd;
  const input = payload.tool_input as Payload | undefined;
  if (typeof input?.filePath === 'string') {
    expect(input.filePath.startsWith(`${RECORDED_CWD}/`), `${name}.filePath`).toBe(true);
    input.filePath = join(cwd, input.filePath.slice(RECORDED_CWD.length + 1));
  }
  return payload;
}

/** Run one payload through the handler its recorded hook command named. */
async function drive(name: string, payload: Payload = repointed(name)): Promise<unknown> {
  const hookKey = name.split('-')[0] ?? '';
  const handler = HANDLERS[hookKey];
  if (handler === undefined) throw new Error(`no handler for ${name}`);
  return handler(hookKey, JSON.stringify(payload), { akaHome, homeDir: home });
}

function seedPolicy(namespace: string, packId: string, policy: BuiltinPolicyId): void {
  const db = openLocalDatabase(join(akaHome, 'data'));
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(namespace, packId, policy);
  } finally {
    db.close();
  }
}

/** `config.onboarded` reads `onboardedAt`; set, a clean prompt carries no nudge. */
function markOnboarded(): void {
  const dir = join(akaHome, 'settings');
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'settings.json'),
    JSON.stringify({ onboardedAt: '2026-01-01T00:00:00Z' }),
  );
}

function rows(sql: string): Record<string, unknown>[] {
  const db = new DatabaseSync(join(akaHome, 'data', 'aka.db'), { readOnly: true });
  try {
    return db.prepare(sql).all();
  } finally {
    db.close();
  }
}

/**
 * The hook-written captures. SessionStart's own rows (the root and its
 * `config_scan`) are read separately.
 */
function captures(): Record<string, unknown>[] {
  return rows(
    `SELECT event_type, content, scope_key, root_session_id FROM audit_events
      WHERE event_type IN ('prompt', 'tool_use', 'code_change', 'response')
      ORDER BY started_at, rowid`,
  );
}

function findings(): Record<string, unknown>[] {
  return rows(
    `SELECT d.rule_id, f.action_taken, e.event_type
       FROM inspection_findings f
       JOIN inspection_definitions d ON d.id = f.inspection_definition_id
       JOIN audit_events e ON e.id = f.audit_event_id
      ORDER BY e.started_at, e.rowid`,
  );
}

function systemMessage(output: unknown): string {
  const message = (output as { systemMessage?: unknown } | undefined)?.systemMessage;
  expect(typeof message).toBe('string');
  return String(message);
}

describe('the recorded VS Code 1.141.0 session, replayed through the handlers', () => {
  it('replays every recording, in the order the host fired them', () => {
    // A guard on the derivation itself: an empty or reordered directory read
    // would otherwise let the replay below assert over fewer hooks than exist.
    expect(SESSION).toEqual([
      'sessionStart',
      'userPromptSubmitted-cat-env',
      'preToolUse-run_in_terminal',
      'postToolUse-run_in_terminal',
      'userPromptSubmitted-create-notes',
      'preToolUse-create_file',
      'postToolUse-create_file',
    ]);
  });

  it('stores what the recorded host stored and writes what it wrote', async () => {
    const outputs: Record<string, unknown> = {};
    for (const name of SESSION) outputs[name] = await drive(name);

    // The session root, keyed by the payload's session id, as the vscode
    // interface.
    const sessions = rows("SELECT id, attributes FROM audit_events WHERE event_type = 'session'");
    expect(sessions.map((r) => r.id)).toEqual([SESSION_ID]);
    const attrs = JSON.parse(String(sessions[0]?.attributes)) as Record<string, unknown>;
    expect(attrs.harness_interface).toBe('vscode');

    // Two prompts, the terminal call, the file write — and no response row,
    // because neither tool result was flagged.
    const recordedPrompts = [
      recorded('userPromptSubmitted-cat-env').prompt,
      recorded('userPromptSubmitted-create-notes').prompt,
    ];
    const createInput = recorded('preToolUse-create_file').tool_input as Payload;
    expect(captures()).toEqual([
      {
        event_type: 'prompt',
        content: recordedPrompts[0],
        scope_key: WORK_KEY,
        root_session_id: SESSION_ID,
      },
      {
        event_type: 'tool_use',
        content: (recorded('preToolUse-run_in_terminal').tool_input as Payload).command,
        scope_key: WORK_KEY,
        root_session_id: SESSION_ID,
      },
      {
        event_type: 'prompt',
        content: recordedPrompts[1],
        scope_key: WORK_KEY,
        root_session_id: SESSION_ID,
      },
      {
        event_type: 'code_change',
        content: createInput.content,
        scope_key: WORK_KEY,
        root_session_id: SESSION_ID,
      },
    ]);
    expect(createInput.content).toBe('hello');

    // Exactly the one finding the host recorded: the command, warned. The
    // clean `explanation` and `goal` beside it add none.
    expect(findings()).toEqual([
      { rule_id: COMMAND_RULE, action_taken: 'warn', event_type: 'tool_use' },
    ]);

    // Stdout: the first-run notice on the first prompt, the warn on the
    // terminal call, and nothing from any other hook.
    expect(systemMessage(outputs['userPromptSubmitted-cat-env'])).toContain('AKA is active');
    expect(systemMessage(outputs['preToolUse-run_in_terminal'])).toBe(
      `AKA flagged sensitive content in run_in_terminal input (${COMMAND_RULE}).`,
    );
    for (const name of SESSION) {
      if (name === 'userPromptSubmitted-cat-env' || name === 'preToolUse-run_in_terminal') continue;
      expect(outputs[name], name).toBeUndefined();
    }
  });
});

// The flagged variants. Each starts from a session root opened by the recorded
// SessionStart, so a capture has the root it hangs off on the recorded host.
describe('a flagged variant of each recording that produced no finding', () => {
  beforeEach(async () => {
    markOnboarded();
    seedPolicy(SAMPLE.namespace, SAMPLE.packId, 'warn');
    expect(await drive('sessionStart')).toBeUndefined();
  });

  it.each(['userPromptSubmitted-cat-env', 'userPromptSubmitted-create-notes'])(
    '%s: the recorded prompt is silent, and the same prompt carrying a secret is warned',
    async (name) => {
      // The recording itself, onboarded: captured, nothing said.
      expect(await drive(name)).toBeUndefined();
      expect(findings()).toEqual([]);

      const flagged = repointed(name);
      flagged.prompt = `${String(flagged.prompt)} ${SAMPLE.example}`;
      const text = systemMessage(await drive(name, flagged));
      expect(text).toContain(SAMPLE_RULE);
      expect(findings()).toEqual([
        { rule_id: SAMPLE_RULE, action_taken: 'warn', event_type: 'prompt' },
      ]);
      expectNoEchoOf(text, SAMPLE.example);
    },
  );

  it('postToolUse-run_in_terminal: the recorded terminal text is silent, and a secret in it is warned', async () => {
    expect(await drive('postToolUse-run_in_terminal')).toBeUndefined();
    expect(captures().filter((r) => r.event_type === 'response')).toEqual([]);

    const flagged = repointed('postToolUse-run_in_terminal');
    expect(typeof flagged.tool_response).toBe('string');
    flagged.tool_response = `${String(flagged.tool_response)}\n${SAMPLE.example}`;
    const text = systemMessage(await drive('postToolUse-run_in_terminal', flagged));
    expect(text).toContain(SAMPLE_RULE);
    expect(findings()).toEqual([
      { rule_id: SAMPLE_RULE, action_taken: 'warn', event_type: 'response' },
    ]);
    expect(captures().filter((r) => r.event_type === 'response')).toEqual([
      expect.objectContaining({ scope_key: WORK_KEY, root_session_id: SESSION_ID }),
    ]);
    expectNoEchoOf(text, SAMPLE.example);
  });

  it('postToolUse-create_file: the recorded empty response is silent, and a non-empty flagged one is warned', async () => {
    const empty = repointed('postToolUse-create_file');
    expect(empty.tool_response).toBe('');
    expect(await drive('postToolUse-create_file', empty)).toBeUndefined();
    expect(captures()).toEqual([]);

    const flagged = repointed('postToolUse-create_file');
    flagged.tool_response = SAMPLE.example;
    const text = systemMessage(await drive('postToolUse-create_file', flagged));
    expect(text).toContain(SAMPLE_RULE);
    expect(findings()).toEqual([
      { rule_id: SAMPLE_RULE, action_taken: 'warn', event_type: 'response' },
    ]);
    expectNoEchoOf(text, SAMPLE.example);
  });

  it('preToolUse-create_file: the recorded content is silent, and a secret in it is warned', async () => {
    expect(await drive('preToolUse-create_file')).toBeUndefined();
    expect(captures().map((r) => r.event_type)).toEqual(['code_change']);
    expect(findings()).toEqual([]);

    const flagged = repointed('preToolUse-create_file');
    const input = flagged.tool_input as Payload;
    input.content = `${String(input.content)}\n${SAMPLE.example}\n`;
    const text = systemMessage(await drive('preToolUse-create_file', flagged));
    expect(text).toContain(SAMPLE_RULE);
    expect(findings()).toEqual([
      { rule_id: SAMPLE_RULE, action_taken: 'warn', event_type: 'code_change' },
    ]);
    expectNoEchoOf(text, SAMPLE.example);
  });
});

// `explanation` and `goal` are model-authored prose that rides along with the
// call. Both are scanned and neither executes, but a rewrite on this host
// needs an allow that would approve the command too, so a redact on either
// takes the same redactFallback as `command`.
describe('run_in_terminal explanation and goal', () => {
  beforeEach(async () => {
    markOnboarded();
    expect(await drive('sessionStart')).toBeUndefined();
  });

  /**
   * Stderr carries no run of the raw value. On this dialect the message rides
   * stdout, so these paths write nothing to stderr at all, and that is asserted
   * exactly: an empty read satisfies every run-by-run check, so the run-by-run
   * check alone would be vacuous here. The case below is the control that the
   * capture really observes what a handler writes there.
   */
  function expectStderrCarriesNoRaw(): void {
    const written = akaStderr();
    expect(written).toBe('');
    expectNoEchoOf(written, SAMPLE.example);
  }

  it('captures what the handler writes to stderr (the control for the checks above)', async () => {
    seedPolicy(SAMPLE.namespace, SAMPLE.packId, 'redact');
    const payload = withSecretIn('goal');
    const input = payload.tool_input as Payload;
    input.goal = `${String(input.goal)} ${'lorem ipsum dolor sit amet '.repeat(
      Math.ceil(LARGE_INPUT_THRESHOLD_CHARS / 27),
    )}`;
    const absent = pathToFileURL(join(root, 'no-worker-here', 'scan-worker.js'));
    await runPreToolUse('preToolUse', JSON.stringify(payload), {
      akaHome,
      homeDir: home,
      scanWorkerUrl: absent,
    });
    const written = akaStderr();
    // Positive control: the SDK's refusal line for the field it could not scan
    // reached the capture, so the capture is live on this path.
    expect(written).toMatch(/\[aka\] a large input could not be scanned.* and was refused/u);
    expectNoEchoOf(written, SAMPLE.example);
  });

  /** The recorded call with its command cleaned and one field carrying a secret. */
  function withSecretIn(field: 'command' | 'explanation' | 'goal'): Payload {
    const payload = repointed('preToolUse-run_in_terminal');
    const input = payload.tool_input as Payload;
    // The recorded command reads a credential file, which is its own finding;
    // a benign one isolates the field under test.
    input.command = 'ls';
    const recordedText = input[field];
    if (typeof recordedText !== 'string') throw new Error(`recorded ${field} is not a string`);
    input[field] = `${recordedText} ${SAMPLE.example}`;
    return payload;
  }

  it.each(['explanation', 'goal'] as const)('finds a secret in %s and warns', async (field) => {
    seedPolicy(SAMPLE.namespace, SAMPLE.packId, 'warn');
    const text = systemMessage(await drive('preToolUse-run_in_terminal', withSecretIn(field)));
    expect(text).toBe(`AKA flagged sensitive content in run_in_terminal input (${SAMPLE_RULE}).`);
    expect(findings()).toEqual([
      { rule_id: SAMPLE_RULE, action_taken: 'warn', event_type: 'tool_use' },
    ]);
    expectNoEchoOf(text, SAMPLE.example);
    expectStderrCarriesNoRaw();
  });

  it.each(['explanation', 'goal'] as const)(
    'falls back on a secret in %s under redact rather than approving the call',
    async (field) => {
      seedPolicy(SAMPLE.namespace, SAMPLE.packId, 'redact');
      const output = await drive('preToolUse-run_in_terminal', withSecretIn(field));
      const text = systemMessage(output);
      // A rewrite would need `permissionDecision: 'allow'`, which approves the
      // command riding with this prose. The exact shape is the assertion: a
      // systemMessage and nothing else, so no verdict and no updatedInput.
      expect(output).toEqual({ systemMessage: text });
      // The shipped redactFallback is `warn`, and the ledger records what was
      // emitted rather than the policy's redact.
      expect(text).toBe(`AKA flagged sensitive content in run_in_terminal input (${SAMPLE_RULE}).`);
      expect(findings()).toEqual([
        { rule_id: SAMPLE_RULE, action_taken: 'warn', event_type: 'tool_use' },
      ]);
      expectNoEchoOf(text, SAMPLE.example);
      expectStderrCarriesNoRaw();
    },
  );

  it('warns on both a degraded command finding and a prose redact, approving nothing', async () => {
    // The recorded command keeps its own finding; a redact on its pack
    // degrades to the fallback because the command executes. The prose carries
    // a second rule under redact. Both must surface, as one warn.
    seedPolicy(COMMAND.namespace, COMMAND.packId, 'redact');
    seedPolicy(SAMPLE.namespace, SAMPLE.packId, 'redact');
    const payload = repointed('preToolUse-run_in_terminal');
    const input = payload.tool_input as Payload;
    input.explanation = `${String(input.explanation)} ${SAMPLE.example}`;
    const output = await drive('preToolUse-run_in_terminal', payload);
    const text = systemMessage(output);
    expect(output).toEqual({ systemMessage: text });
    expect(text).toBe(
      `AKA flagged sensitive content in run_in_terminal input (${COMMAND_RULE}, ${SAMPLE_RULE}).`,
    );
    expect(findings()).toEqual(
      expect.arrayContaining([
        { rule_id: COMMAND_RULE, action_taken: 'warn', event_type: 'tool_use' },
        { rule_id: SAMPLE_RULE, action_taken: 'warn', event_type: 'tool_use' },
      ]),
    );
    expect(findings()).toHaveLength(2);
    expectNoEchoOf(text, SAMPLE.example);
    expectStderrCarriesNoRaw();
  });

  it('still rewrites create_file content under redact (the control that the fallback is scoped)', async () => {
    seedPolicy(SAMPLE.namespace, SAMPLE.packId, 'redact');
    const payload = repointed('preToolUse-create_file');
    const sent = payload.tool_input as Payload;
    sent.content = `${String(sent.content)}\n${SAMPLE.example}\n`;
    const output = (await drive('preToolUse-create_file', payload)) as {
      hookSpecificOutput?: { permissionDecision?: unknown; updatedInput?: Payload };
      systemMessage?: unknown;
    };
    const updated = output.hookSpecificOutput?.updatedInput;
    // A tool with no executable field keeps its rewrite, carried with an allow.
    expect(output.hookSpecificOutput?.permissionDecision).toBe('allow');
    expect(typeof updated?.content).toBe('string');
    expect(updated?.content).not.toBe(sent.content);
    expectNoEchoOf(String(updated?.content), SAMPLE.example);
    expect({ ...updated, content: sent.content }).toEqual(sent);
    expect(findings()).toEqual([
      { rule_id: SAMPLE_RULE, action_taken: 'redact', event_type: 'code_change' },
    ]);
    expectNoEchoOf(systemMessage(output), SAMPLE.example);
    expectStderrCarriesNoRaw();
  });

  it('keeps the command on the executable-field fallback under redact, never rewritten', async () => {
    seedPolicy(SAMPLE.namespace, SAMPLE.packId, 'redact');
    const output = await drive('preToolUse-run_in_terminal', withSecretIn('command'));
    const text = systemMessage(output);
    // No rewrite came back: the fallback is a decision, not an `updatedInput`,
    // and the ledger cannot stand in for this, since the runtime records the
    // fallback whatever the hook wrote.
    expect(output).toEqual({ systemMessage: text });
    // The shipped redactFallback is `warn`: no rewrite, and the ledger agrees.
    expect(text).toContain(SAMPLE_RULE);
    expect(findings()).toEqual([
      { rule_id: SAMPLE_RULE, action_taken: 'warn', event_type: 'tool_use' },
    ]);
    expectNoEchoOf(text, SAMPLE.example);
    expectStderrCarriesNoRaw();
  });
});
