import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { detectDialect, readCwd, readSessionId, readToolCall } from '../src/hooks/dialect.ts';
import { VSCODE_SCANNABLE_FIELDS } from '../src/hooks/pre-tool-use-decision.ts';
import { readSessionStartFacts } from '../src/hooks/session-start-payload.ts';
import { responseKey, scannableResponseFields } from '../src/hooks/tool-response.ts';
import { readPromptCapture } from '../src/hooks/user-prompt-payload.ts';

// The payloads under test/fixtures/vscode/plugin-load-1.141/ are what VS Code
// 1.141.0 wrote to this package's built hooks after loading the packed plugin
// from a local directory (the README beside them says how, and what was
// rewritten before commit). This suite pins every value the README calls out
// and the exact set of files, and drives the adapter's own readers over them,
// so a fixture edit or a reader that stops matching the host is a red test.

const FIXTURE_DIR = fileURLToPath(new URL('./fixtures/vscode/plugin-load-1.141/', import.meta.url));

// In the order the session fired them.
const FILES = [
  'sessionStart',
  'userPromptSubmitted-cat-env',
  'preToolUse-run_in_terminal',
  'postToolUse-run_in_terminal',
  'userPromptSubmitted-create-notes',
  'preToolUse-create_file',
  'postToolUse-create_file',
] as const;
type FileName = (typeof FILES)[number];

type Payload = Record<string, unknown>;

const payloads = Object.fromEntries(
  FILES.map((name) => [
    name,
    JSON.parse(readFileSync(`${FIXTURE_DIR}${name}.json`, 'utf8')) as Payload,
  ]),
) as Record<FileName, Payload>;

const SESSION_ID = 'fcbfebce-dbe0-4aa1-b640-4b6590f9a3a3';
const TRANSCRIPT_PATH =
  '/Users/dev/Library/Application Support/Code/User/workspaceStorage/' +
  `b2c7b8b81b376fdee1632645c04562bd/GitHub.copilot-chat/transcripts/${SESSION_ID}.jsonl`;
const CWD = '/Users/dev/work';

// The argv token each hook command passed: the camelCase `hooks.json` key the
// file is named after, which is NOT the event name in the payload.
const ARGV_TOKEN: Record<FileName, string> = {
  sessionStart: 'sessionStart',
  'userPromptSubmitted-cat-env': 'userPromptSubmitted',
  'preToolUse-run_in_terminal': 'preToolUse',
  'postToolUse-run_in_terminal': 'postToolUse',
  'userPromptSubmitted-create-notes': 'userPromptSubmitted',
  'preToolUse-create_file': 'preToolUse',
  'postToolUse-create_file': 'postToolUse',
};

const HOOK_EVENT_NAME: Record<FileName, string> = {
  sessionStart: 'SessionStart',
  'userPromptSubmitted-cat-env': 'UserPromptSubmit',
  'preToolUse-run_in_terminal': 'PreToolUse',
  'postToolUse-run_in_terminal': 'PostToolUse',
  'userPromptSubmitted-create-notes': 'UserPromptSubmit',
  'preToolUse-create_file': 'PreToolUse',
  'postToolUse-create_file': 'PostToolUse',
};

const TIMESTAMP: Record<FileName, string> = {
  sessionStart: '2026-10-19T10:42:00.538Z',
  'userPromptSubmitted-cat-env': '2026-10-19T10:42:00.689Z',
  'preToolUse-run_in_terminal': '2026-10-19T10:42:13.834Z',
  'postToolUse-run_in_terminal': '2026-10-19T10:42:16.964Z',
  'userPromptSubmitted-create-notes': '2026-10-19T10:42:24.441Z',
  'preToolUse-create_file': '2026-10-19T10:42:36.220Z',
  'postToolUse-create_file': '2026-10-19T10:42:36.346Z',
};

const ENVELOPE = ['cwd', 'hook_event_name', 'session_id', 'timestamp', 'transcript_path'];
const KEYS: Record<FileName, string[]> = {
  sessionStart: [...ENVELOPE, 'model', 'source'],
  'userPromptSubmitted-cat-env': [...ENVELOPE, 'prompt'],
  'preToolUse-run_in_terminal': [...ENVELOPE, 'tool_input', 'tool_name', 'tool_use_id'],
  'postToolUse-run_in_terminal': [
    ...ENVELOPE,
    'tool_input',
    'tool_name',
    'tool_response',
    'tool_use_id',
  ],
  'userPromptSubmitted-create-notes': [...ENVELOPE, 'prompt'],
  'preToolUse-create_file': [...ENVELOPE, 'tool_input', 'tool_name', 'tool_use_id'],
  'postToolUse-create_file': [
    ...ENVELOPE,
    'tool_input',
    'tool_name',
    'tool_response',
    'tool_use_id',
  ],
};

const TERMINAL_INPUT = {
  command:
    'cat .env | awk \'NR == 1 { print (index($0, "GH_TOKEN") == 1 ? "starts with GH_TOKEN" : ' +
    '"does not start with GH_TOKEN"); exit } END { if (NR == 0) print "empty file" }\'',
  explanation: 'Check the .env output prefix without displaying its contents.',
  goal: 'Safely verify .env prefix',
  mode: 'sync',
};
const TERMINAL_CALL_ID = 'call_r0TgwhwfzGi7ZFMPedEzqOas__vscode-1792406494813';
const CREATE_FILE_INPUT = { filePath: `${CWD}/notes.txt`, content: 'hello' };
const CREATE_FILE_CALL_ID = 'call_CwZtm78GScU3CHDBQ0usdUvq__vscode-1792406494814';

// The terminal's text, line by line: the echoed prompt and command wrapped at
// the terminal's width, the awk output, and the next prompt.
const TERMINAL_RESPONSE_LINES = [
  'dev@Mac work %  cat .env | awk \'NR == 1 { print (index($0, "GH_TOKEN") ==',
  '1 ? "starts with GH_TOKEN" : "does not start with GH_TOKEN"); exit } END { if (N',
  'R == 0) print "empty file" }\'',
  'does not start with GH_TOKEN',
  'dev@Mac work % ',
];

// Every path was rewritten to this placeholder home before commit.
const FOREIGN_HOME = /\/(?:Users|home)\/(?!dev\/)/u;

describe('VS Code 1.141.0 plugin-load hook payload fixtures', () => {
  it('are exactly the seven recorded payloads and their README', () => {
    expect(FILES).toHaveLength(7);
    const expected = [...FILES.map((name) => `${name}.json`), 'README.md'].sort();
    expect(readdirSync(FIXTURE_DIR).sort()).toEqual(expected);
  });

  it('carry exactly the documented keys, with the PascalCase event name', () => {
    for (const name of FILES) {
      expect(Object.keys(payloads[name]).sort(), name).toEqual([...KEYS[name]].sort());
      expect(payloads[name].hook_event_name, name).toBe(HOOK_EVENT_NAME[name]);
    }
  });

  it('share one session id, one transcript path and the placeholder cwd', () => {
    for (const name of FILES) {
      const payload = payloads[name];
      expect(payload.session_id, name).toBe(SESSION_ID);
      expect(payload.transcript_path, name).toBe(TRANSCRIPT_PATH);
      expect(payload.cwd, name).toBe(CWD);
      const text = JSON.stringify(payload);
      expect(FOREIGN_HOME.test(text), `${name} leaks a home directory`).toBe(false);
      expect(text, `${name} leaks a temp path`).not.toMatch(/\/private\/|\/tmp\//u);
    }
  });

  it('stamp an ISO string, not an epoch number, and fire SessionStart first', () => {
    for (const name of FILES) {
      expect(payloads[name].timestamp, name).toBe(TIMESTAMP[name]);
    }
    const order = [...FILES].sort((a, b) => Date.parse(TIMESTAMP[a]) - Date.parse(TIMESTAMP[b]));
    expect(order).toEqual([...FILES]);
    expect(
      Date.parse(TIMESTAMP['userPromptSubmitted-cat-env']) - Date.parse(TIMESTAMP.sessionStart),
    ).toBe(151);
  });

  it('open the session with source "new" and model "auto"', () => {
    expect(payloads.sessionStart.source).toBe('new');
    expect(payloads.sessionStart.model).toBe('auto');
  });

  it('carry both prompts verbatim', () => {
    expect(payloads['userPromptSubmitted-cat-env'].prompt).toBe(
      'Run `cat .env` in the terminal and tell me whether the output starts with GH_TOKEN. ' +
        'Do not repeat the value.',
    );
    expect(payloads['userPromptSubmitted-create-notes'].prompt).toBe(
      'Create a file notes.txt containing the word hello.',
    );
  });

  it('send run_in_terminal with command, explanation, goal and mode', () => {
    for (const name of ['preToolUse-run_in_terminal', 'postToolUse-run_in_terminal'] as const) {
      expect(payloads[name].tool_name, name).toBe('run_in_terminal');
      expect(payloads[name].tool_input, name).toEqual(TERMINAL_INPUT);
      expect(payloads[name].tool_use_id, name).toBe(TERMINAL_CALL_ID);
    }
  });

  it('send create_file with an absolute filePath and the content', () => {
    for (const name of ['preToolUse-create_file', 'postToolUse-create_file'] as const) {
      expect(payloads[name].tool_name, name).toBe('create_file');
      expect(payloads[name].tool_input, name).toEqual(CREATE_FILE_INPUT);
      expect(payloads[name].tool_use_id, name).toBe(CREATE_FILE_CALL_ID);
    }
  });

  it('hand PostToolUse a STRING tool_response on both calls', () => {
    expect(payloads['postToolUse-run_in_terminal'].tool_response).toBe(
      TERMINAL_RESPONSE_LINES.join('\n'),
    );
    expect(payloads['postToolUse-create_file'].tool_response).toBe('');
  });

  it('never carry the github-pat example the workspace .env held', () => {
    // Positive control first: the rule file still holds an example, or the
    // absence check below would pass on `undefined`.
    const rule = JSON.parse(
      readFileSync(new URL('../../../rules/secrets/github-pat.json', import.meta.url), 'utf8'),
    ) as { id: string; examples: unknown[] };
    expect(rule.id).toBe('secrets/github-pat');
    const example = rule.examples[0];
    expect(typeof example).toBe('string');
    for (const name of FILES) {
      expect(JSON.stringify(payloads[name]).includes(example as string), name).toBe(false);
    }
  });
});

describe("the adapter's readers over the VS Code 1.141.0 recordings", () => {
  it('read every payload as the vscode dialect, with its session id and cwd', () => {
    for (const name of FILES) {
      expect(detectDialect(payloads[name]), name).toBe('vscode');
      expect(readSessionId('vscode', payloads[name]), name).toBe(SESSION_ID);
      expect(readCwd('vscode', payloads[name]), name).toBe(CWD);
    }
  });

  it('open the session root as the vscode interface', () => {
    expect(readSessionStartFacts(payloads.sessionStart)).toEqual({
      dialect: 'vscode',
      sessionId: SESSION_ID,
      cwd: CWD,
      harnessInterface: 'vscode',
    });
  });

  it('read each prompt under the camelCase argv token the hook command passed', () => {
    for (const name of [
      'userPromptSubmitted-cat-env',
      'userPromptSubmitted-create-notes',
    ] as const) {
      expect(ARGV_TOKEN[name]).toBe('userPromptSubmitted');
      expect(readPromptCapture('userPromptSubmitted', payloads[name]), name).toEqual({
        event: 'submitted',
        text: payloads[name].prompt,
      });
    }
  });

  it('find every field the VS Code table scans in the recorded tool input', () => {
    for (const name of ['preToolUse-run_in_terminal', 'preToolUse-create_file'] as const) {
      const call = readToolCall('vscode', payloads[name]);
      expect(call, name).toBeDefined();
      const table = VSCODE_SCANNABLE_FIELDS[call?.name ?? ''];
      expect(table, `${name} has a field table`).toBeDefined();
      for (const spec of table ?? []) {
        expect(typeof call?.args[spec.field], `${name}.${spec.field}`).toBe('string');
      }
    }
  });

  it('read the terminal text as one field and the empty response as none', () => {
    expect(responseKey('vscode')).toBe('tool_response');
    expect(
      scannableResponseFields('vscode', payloads['postToolUse-run_in_terminal'].tool_response),
    ).toEqual({
      fields: [{ path: [], text: TERMINAL_RESPONSE_LINES.join('\n') }],
      truncated: false,
    });
    expect(
      scannableResponseFields('vscode', payloads['postToolUse-create_file'].tool_response),
    ).toEqual({ fields: [], truncated: false });
  });
});
