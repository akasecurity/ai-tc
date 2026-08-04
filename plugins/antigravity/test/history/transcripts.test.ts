// Tests the Antigravity rollout-file parser against synthetic JSONL matching the
// wire shape confirmed from openai/antigravity's own Rust types
// (antigravity-rs/protocol/src/protocol.rs — RolloutLine/RolloutItem/EventMsg;
// antigravity-rs/protocol/src/models.rs — ResponseItem/ContentItem). See the module
// comment on transcripts.ts for the exact source pointers.
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  parseTranscript,
  parseTranscriptToolCalls,
  parseTranscriptUsage,
  peekSessionOriginator,
} from '../../src/history/transcripts.ts';

function line(obj: unknown): string {
  return JSON.stringify(obj);
}

const SESSION_META = line({
  timestamp: '2026-07-14T10:00:00.000Z',
  type: 'session_meta',
  payload: {
    session_id: 'sess-1',
    id: 'thread-1',
    timestamp: '2026-07-14T10:00:00.000Z',
    cwd: '/home/me/proj',
    originator: 'codex_cli_rs',
    cli_version: '0.140.0',
  },
});

describe('parseTranscript — prompt/response text', () => {
  it('extracts a user message and an assistant reply from response_item lines', () => {
    const jsonl = [
      SESSION_META,
      line({
        timestamp: '2026-07-14T10:00:01.000Z',
        type: 'response_item',
        payload: {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'here is my api key sk-abc123' }],
        },
      }),
      line({
        timestamp: '2026-07-14T10:00:02.000Z',
        type: 'response_item',
        payload: {
          type: 'message',
          role: 'assistant',
          content: [{ type: 'output_text', text: 'I will not echo that key back.' }],
        },
      }),
    ].join('\n');

    const messages = parseTranscript(jsonl);
    expect(messages).toEqual([
      {
        kind: 'prompt',
        text: 'here is my api key sk-abc123',
        occurredAt: '2026-07-14T10:00:01.000Z',
        filePath: '',
      },
      {
        kind: 'response',
        text: 'I will not echo that key back.',
        occurredAt: '2026-07-14T10:00:02.000Z',
        filePath: '',
      },
    ]);
  });

  it('stamps the source rollout path onto every message so a surfaced finding can be located', () => {
    const path =
      '/Users/me/.gemini/antigravity-cli/brain/conv-session/.system_generated/logs/transcript.jsonl';
    const jsonl = [
      SESSION_META,
      line({
        timestamp: '2026-07-14T10:00:01.000Z',
        type: 'response_item',
        payload: {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'a prompt' }],
        },
      }),
    ].join('\n');
    const msgs = parseTranscript(jsonl, 0, Infinity, path);
    expect(msgs.length).toBeGreaterThan(0);
    for (const msg of msgs) expect(msg.filePath).toBe(path);
  });

  it('drops messages at/after the setup-start cutoff (beforeMs), keeps older ones', () => {
    const jsonl = [
      line({
        timestamp: '2026-07-14T10:00:01.000Z',
        type: 'response_item',
        payload: {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'pre-install leak' }],
        },
      }),
      line({
        timestamp: '2026-07-16T10:00:00.000Z',
        type: 'response_item',
        payload: {
          type: 'message',
          role: 'user',
          content: [{ type: 'input_text', text: 'post-install wizard output' }],
        },
      }),
    ].join('\n');

    const cutoff = Date.parse('2026-07-15T00:00:00.000Z'); // setup-start
    const bounded = parseTranscript(jsonl, 0, cutoff).map((m) => m.text);
    expect(bounded).toEqual(['pre-install leak']);
  });

  it('joins multiple text content blocks and skips input_image blocks', () => {
    const jsonl = line({
      timestamp: '2026-07-14T10:00:01.000Z',
      type: 'response_item',
      payload: {
        type: 'message',
        role: 'user',
        content: [
          { type: 'input_text', text: 'first line' },
          { type: 'input_image', image_url: 'data:image/png;base64,xyz' },
          { type: 'input_text', text: 'second line' },
        ],
      },
    });
    expect(parseTranscript(jsonl)).toEqual([
      {
        kind: 'prompt',
        text: 'first line\nsecond line',
        occurredAt: '2026-07-14T10:00:01.000Z',
        filePath: '',
      },
    ]);
  });

  it('skips non-message response_item payloads (function_call, reasoning, …)', () => {
    const jsonl = [
      line({
        timestamp: '2026-07-14T10:00:01.000Z',
        type: 'response_item',
        payload: {
          type: 'function_call',
          name: 'shell',
          arguments: '{"command":"ls"}',
          call_id: 'c1',
        },
      }),
      line({
        timestamp: '2026-07-14T10:00:02.000Z',
        type: 'response_item',
        payload: { type: 'reasoning', summary: [], content: [] },
      }),
    ].join('\n');
    expect(parseTranscript(jsonl)).toEqual([]);
  });

  it('skips malformed JSON lines without throwing', () => {
    const jsonl = ['not json at all', SESSION_META, '{"broken":'].join('\n');
    expect(() => parseTranscript(jsonl)).not.toThrow();
    expect(parseTranscript(jsonl)).toEqual([]);
  });

  it('applies the sinceMs window bound', () => {
    const jsonl = line({
      timestamp: '2026-01-01T00:00:00.000Z',
      type: 'response_item',
      payload: { type: 'message', role: 'user', content: [{ type: 'input_text', text: 'old' }] },
    });
    const sinceMs = Date.parse('2026-06-01T00:00:00.000Z');
    expect(parseTranscript(jsonl, sinceMs)).toEqual([]);
  });
});

describe('parseTranscriptUsage — token_count events', () => {
  it('threads session_id/cwd/cli_version from session_meta onto each usage record', () => {
    const jsonl = [
      SESSION_META,
      line({
        timestamp: '2026-07-14T10:00:03.000Z',
        type: 'turn_context',
        payload: { turn_id: 'turn-1', cwd: '/home/me/proj', model: 'gpt-5-antigravity' },
      }),
      line({
        timestamp: '2026-07-14T10:00:04.000Z',
        type: 'event_msg',
        payload: {
          type: 'token_count',
          info: {
            total_token_usage: {
              input_tokens: 500,
              cached_input_tokens: 100,
              output_tokens: 50,
              reasoning_output_tokens: 10,
              total_tokens: 550,
            },
            last_token_usage: {
              input_tokens: 500,
              cached_input_tokens: 100,
              output_tokens: 50,
              reasoning_output_tokens: 10,
              total_tokens: 550,
            },
            model_context_window: 200000,
          },
          rate_limits: null,
        },
      }),
    ].join('\n');

    const records = parseTranscriptUsage(jsonl);
    expect(records).toEqual([
      {
        kind: 'usage',
        sessionId: 'sess-1',
        eventKey: 'sess-1:2026-07-14T10:00:04.000Z:1',
        model: 'gpt-5-antigravity',
        runKey: 'turn-1',
        usage: {
          input_tokens: 500,
          output_tokens: 50,
          cache_read_input_tokens: 100,
          reasoning_output_tokens: 10,
        },
        occurredAt: '2026-07-14T10:00:04.000Z',
        cwd: '/home/me/proj',
        version: '0.140.0',
        originator: 'codex_cli_rs',
      },
    ]);
  });

  it('drops an all-zero token_count event', () => {
    const jsonl = [
      SESSION_META,
      line({
        timestamp: '2026-07-14T10:00:04.000Z',
        type: 'event_msg',
        payload: {
          type: 'token_count',
          info: {
            total_token_usage: {},
            last_token_usage: { input_tokens: 0, output_tokens: 0, cached_input_tokens: 0 },
            model_context_window: null,
          },
          rate_limits: null,
        },
      }),
    ].join('\n');
    expect(parseTranscriptUsage(jsonl)).toEqual([]);
  });

  it('drops usage events before session_meta has been seen (unattributable)', () => {
    const jsonl = line({
      timestamp: '2026-07-14T10:00:04.000Z',
      type: 'event_msg',
      payload: {
        type: 'token_count',
        info: {
          total_token_usage: {},
          last_token_usage: { input_tokens: 10, output_tokens: 10 },
          model_context_window: null,
        },
        rate_limits: null,
      },
    });
    expect(parseTranscriptUsage(jsonl)).toEqual([]);
  });

  it('distinguishes a ChatGPT-desktop-hosted Antigravity session from a terminal one via originator', () => {
    const desktopSessionMeta = line({
      timestamp: '2026-07-14T10:00:00.000Z',
      type: 'session_meta',
      payload: {
        session_id: 'sess-2',
        id: 'thread-2',
        timestamp: '2026-07-14T10:00:00.000Z',
        cwd: '/home/me/proj',
        originator: 'codex_desktop',
        cli_version: '0.140.0',
      },
    });
    const jsonl = [desktopSessionMeta, tokenCountLine('2026-07-14T10:00:04.000Z')].join('\n');

    const records = parseTranscriptUsage(jsonl);
    expect(records[0]?.originator).toBe('codex_desktop');
  });

  it('mints identical eventKeys for a record whether parsed whole-file or as a tail chunk', () => {
    // The incremental tail path re-parses only the newly-appended chunk of a
    // rollout file. A per-parse ordinal would restart at 1 there and collide
    // every later turn's usage row with the first turn's — the keys must
    // depend only on the record itself (timestamp + same-timestamp ordinal),
    // never on where the parse window started.
    const first = tokenCountLine('2026-07-14T10:00:04.000Z');
    const second = tokenCountLine('2026-07-14T10:05:00.000Z');

    const wholeFile = parseTranscriptUsage([SESSION_META, first, second].join('\n'));
    const pass1 = parseTranscriptUsage([SESSION_META, first].join('\n'));
    const pass2 = parseTranscriptUsage(second, 0, 'sess-1'); // tail chunk: no session_meta

    expect(wholeFile.map((r) => r.eventKey)).toEqual([pass1[0]?.eventKey, pass2[0]?.eventKey]);
    // The two turns never share a key — the collision the per-parse ordinal
    // scheme used to cause.
    expect(pass1[0]?.eventKey).not.toBe(pass2[0]?.eventKey);
  });

  it('disambiguates two token_count records sharing one timestamp, stably across filters', () => {
    const ts = '2026-07-14T10:00:04.000Z';
    const both = parseTranscriptUsage(
      [SESSION_META, tokenCountLine(ts), tokenCountLine(ts)].join('\n'),
    );
    expect(both.map((r) => r.eventKey)).toEqual([`sess-1:${ts}:1`, `sess-1:${ts}:2`]);
  });
});

// A minimal single-line token_count event, for tests that only care about
// which session_meta.originator ends up on the record.
function tokenCountLine(timestamp: string): string {
  return line({
    timestamp,
    type: 'event_msg',
    payload: {
      type: 'token_count',
      info: {
        total_token_usage: {},
        last_token_usage: { input_tokens: 10, output_tokens: 10 },
        model_context_window: null,
      },
      rate_limits: null,
    },
  });
}

describe('parseTranscriptToolCalls — exec_command and patch_apply pairs', () => {
  it('pairs an exec_command_begin/end into one shell ToolCallRecord', () => {
    const jsonl = [
      SESSION_META,
      line({
        timestamp: '2026-07-14T10:00:05.000Z',
        type: 'event_msg',
        payload: {
          type: 'exec_command_begin',
          call_id: 'call-1',
          turn_id: 'turn-1',
          started_at_ms: 0,
          command: ['ls', '-la'],
          cwd: '/home/me/proj',
          parsed_cmd: [],
        },
      }),
      line({
        timestamp: '2026-07-14T10:00:06.000Z',
        type: 'event_msg',
        payload: {
          type: 'exec_command_end',
          call_id: 'call-1',
          turn_id: 'turn-1',
          completed_at_ms: 100,
          command: ['ls', '-la'],
          cwd: '/home/me/proj',
          parsed_cmd: [],
          stdout: 'file1\nfile2\n',
          stderr: '',
          aggregated_output: 'file1\nfile2\n',
          exit_code: 0,
          duration: '0.1s',
          formatted_output: 'file1\nfile2\n',
          status: 'completed',
        },
      }),
    ].join('\n');

    const calls = parseTranscriptToolCalls(jsonl);
    expect(calls).toEqual([
      {
        sessionId: 'sess-1',
        toolUseId: 'call-1',
        toolName: 'shell',
        runKey: 'turn-1',
        occurredAt: '2026-07-14T10:00:05.000Z',
        inputSize: 'ls -la'.length,
        isError: false,
        outputSize: 'file1\nfile2\n'.length,
        target: 'ls -la',
      },
    ]);
  });

  it('marks a nonzero exit code as an error', () => {
    const jsonl = [
      SESSION_META,
      line({
        timestamp: '2026-07-14T10:00:05.000Z',
        type: 'event_msg',
        payload: {
          type: 'exec_command_begin',
          call_id: 'call-2',
          turn_id: 'turn-1',
          command: ['false'],
          cwd: '/home/me/proj',
          parsed_cmd: [],
        },
      }),
      line({
        timestamp: '2026-07-14T10:00:06.000Z',
        type: 'event_msg',
        payload: {
          type: 'exec_command_end',
          call_id: 'call-2',
          turn_id: 'turn-1',
          command: ['false'],
          cwd: '/home/me/proj',
          parsed_cmd: [],
          stdout: '',
          stderr: '',
          aggregated_output: '',
          exit_code: 1,
          duration: '0.01s',
          formatted_output: '',
          status: 'completed',
        },
      }),
    ].join('\n');

    expect(parseTranscriptToolCalls(jsonl)[0]?.isError).toBe(true);
  });

  it('pairs a patch_apply_begin/end into one apply_patch ToolCallRecord', () => {
    const jsonl = [
      SESSION_META,
      line({
        timestamp: '2026-07-14T10:00:07.000Z',
        type: 'event_msg',
        payload: {
          type: 'patch_apply_begin',
          call_id: 'call-3',
          turn_id: 'turn-2',
          auto_approved: true,
          changes: { '/home/me/proj/notes.txt': { type: 'update' } },
        },
      }),
      line({
        timestamp: '2026-07-14T10:00:08.000Z',
        type: 'event_msg',
        payload: {
          type: 'patch_apply_end',
          call_id: 'call-3',
          turn_id: 'turn-2',
          stdout: 'applied',
          stderr: '',
          success: true,
          changes: { '/home/me/proj/notes.txt': { type: 'update' } },
          status: 'completed',
        },
      }),
    ].join('\n');

    const calls = parseTranscriptToolCalls(jsonl);
    expect(calls).toEqual([
      {
        sessionId: 'sess-1',
        toolUseId: 'call-3',
        toolName: 'apply_patch',
        runKey: 'turn-2',
        occurredAt: '2026-07-14T10:00:07.000Z',
        inputSize: '/home/me/proj/notes.txt'.length,
        isError: false,
        outputSize: 'applied'.length,
        target: '/home/me/proj/notes.txt',
      },
    ]);
  });

  it('drops calls before session_meta has been seen (unattributable)', () => {
    const jsonl = line({
      timestamp: '2026-07-14T10:00:06.000Z',
      type: 'event_msg',
      payload: {
        type: 'exec_command_end',
        call_id: 'orphan',
        turn_id: 'turn-1',
        command: ['ls'],
        cwd: '/tmp',
        parsed_cmd: [],
        stdout: '',
        stderr: '',
        aggregated_output: '',
        exit_code: 0,
        duration: '0s',
        formatted_output: '',
        status: 'completed',
      },
    });
    expect(parseTranscriptToolCalls(jsonl)).toEqual([]);
  });
});

describe('peekSessionOriginator — cheap live-hook header read', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-peek-originator-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('reads the originator off a real rollout file (terminal CLI)', () => {
    const file = join(dir, 'rollout.jsonl');
    writeFileSync(file, `${SESSION_META}\n${tokenCountLine('2026-07-14T10:00:04.000Z')}\n`);
    expect(peekSessionOriginator(file)).toBe('codex_cli_rs');
  });

  it('reads a distinct originator for a ChatGPT-desktop-hosted session', () => {
    const file = join(dir, 'rollout.jsonl');
    const desktopSessionMeta = line({
      timestamp: '2026-07-14T10:00:00.000Z',
      type: 'session_meta',
      payload: {
        session_id: 'sess-2',
        id: 'thread-2',
        timestamp: '2026-07-14T10:00:00.000Z',
        cwd: '/home/me/proj',
        originator: 'codex_desktop',
        cli_version: '0.140.0',
      },
    });
    writeFileSync(file, `${desktopSessionMeta}\n`);
    expect(peekSessionOriginator(file)).toBe('codex_desktop');
  });

  it('returns undefined for a missing file (fail-open)', () => {
    expect(peekSessionOriginator(join(dir, 'does-not-exist.jsonl'))).toBeUndefined();
  });

  it('returns undefined when the first line is not session_meta', () => {
    const file = join(dir, 'rollout.jsonl');
    writeFileSync(file, `${tokenCountLine('2026-07-14T10:00:04.000Z')}\n`);
    expect(peekSessionOriginator(file)).toBeUndefined();
  });

  it('returns undefined without throwing on garbage content', () => {
    const file = join(dir, 'rollout.jsonl');
    writeFileSync(file, 'not json at all\n');
    expect(() => peekSessionOriginator(file)).not.toThrow();
    expect(peekSessionOriginator(file)).toBeUndefined();
  });
});
