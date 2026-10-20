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
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { runPostToolUse } from '../../src/hooks/post-tool-use-run.ts';
import { runPreToolUse } from '../../src/hooks/pre-tool-use-run.ts';
import { runSessionStart } from '../../src/hooks/session-start-run.ts';
import type { HookHandler } from '../../src/hooks/shared.ts';
import { runUserPromptSubmit } from '../../src/hooks/user-prompt-submit-run.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

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

// In the order the session fired them.
const SESSION = [
  'sessionStart',
  'userPromptSubmitted-cat-env',
  'preToolUse-run_in_terminal',
  'postToolUse-run_in_terminal',
  'userPromptSubmitted-create-notes',
  'preToolUse-create_file',
  'postToolUse-create_file',
] as const;

const SESSION_ID = String(recorded('sessionStart').session_id);
const RECORDED_CWD = String(recorded('sessionStart').cwd);

function ruleExample(ruleId: string): { namespace: string; packId: string; example: string } {
  // Taken from the rule's own examples rather than written here: this
  // repository is public, and a credential-shaped literal does not belong in it.
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === ruleId));
  const example = pack?.rules.find((r) => r.id === ruleId)?.examples?.[0];
  if (pack === undefined || example === undefined) {
    throw new Error(`bundled rule ${ruleId} is missing from the pack registry or has no example`);
  }
  return { namespace: pack.namespace, packId: pack.packId, example };
}
const SAMPLE_RULE = 'secrets/twilio-key';
const SAMPLE = ruleExample(SAMPLE_RULE);

// The finding the recorded host stored for the recorded `run_in_terminal` call.
const COMMAND_RULE = 'command-risk/credential-file-read';

// The userinfo in an scp-style remote reads as an email address to a scanner,
// so the remote is built from parts.
const AT = String.fromCharCode(64);
const WORK_REMOTE = `git${AT}GitHub.com:acme/work-repo.git`;
const WORK_KEY = 'github.com/acme/work-repo';

let root: string;
let akaHome: string;
let home: string;
let cwd: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-copilot-vscode-recorded-'));
  akaHome = join(root, 'aka-home');
  home = join(root, 'home');
  mkdirSync(home);
  cwd = join(root, 'work');
  mkdirSync(join(cwd, '.git'), { recursive: true });
  writeFileSync(join(cwd, '.git', 'config'), `[remote "origin"]\n\turl = ${WORK_REMOTE}\n`);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

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
// call. Both are scanned, neither executes, so a redact rewrites them in place
// while `command` keeps the executable-field fallback.
describe('run_in_terminal explanation and goal', () => {
  beforeEach(async () => {
    markOnboarded();
    expect(await drive('sessionStart')).toBeUndefined();
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
  });

  it.each(['explanation', 'goal'] as const)(
    'rewrites a secret in %s in place under redact, leaving the command as sent',
    async (field) => {
      seedPolicy(SAMPLE.namespace, SAMPLE.packId, 'redact');
      const payload = withSecretIn(field);
      const sent = payload.tool_input as Payload;
      const output = (await drive('preToolUse-run_in_terminal', payload)) as {
        hookSpecificOutput?: { permissionDecision?: unknown; updatedInput?: Payload };
      };
      const updated = output.hookSpecificOutput?.updatedInput;
      // Positive control: a rewrite came back, of this field.
      expect(output.hookSpecificOutput?.permissionDecision).toBe('allow');
      expect(typeof updated?.[field]).toBe('string');
      expect(updated?.[field]).not.toBe(sent[field]);
      expectNoEchoOf(String(updated?.[field]), SAMPLE.example);
      // Everything else is what the model sent.
      expect({ ...updated, [field]: sent[field] }).toEqual(sent);
      expect(findings()).toEqual([
        { rule_id: SAMPLE_RULE, action_taken: 'redact', event_type: 'tool_use' },
      ]);
    },
  );

  it('keeps the command on the executable-field fallback under redact, never rewritten', async () => {
    seedPolicy(SAMPLE.namespace, SAMPLE.packId, 'redact');
    const text = systemMessage(await drive('preToolUse-run_in_terminal', withSecretIn('command')));
    // The shipped redactFallback is `warn`: no rewrite, and the ledger agrees.
    expect(text).toContain(SAMPLE_RULE);
    expect(findings()).toEqual([
      { rule_id: SAMPLE_RULE, action_taken: 'warn', event_type: 'tool_use' },
    ]);
    expectNoEchoOf(text, SAMPLE.example);
  });
});
