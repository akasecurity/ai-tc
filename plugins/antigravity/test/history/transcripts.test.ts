// Tests the Antigravity transcript parser against synthetic JSONL matching the
// record shape pinned from a real transcript — see the module comment on
// transcripts.ts for the full shape. The fixtures here are hand-authored from
// that shape (field names and enum values only); no captured conversation text
// is checked into this repository.
//
// The parseTranscriptUsage / parseTranscriptToolCalls / peekSessionOriginator
// suites below still drive CODEX-shaped input, because those three parsers are
// still Codex-shaped and inert on this host. They pin the code as it stands;
// they are not evidence about Antigravity's wire format.
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  iterateHistory,
  parseTranscript,
  parseTranscriptToolCalls,
  parseTranscriptUsage,
  peekSessionOriginator,
  transcriptsDir,
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

// One Antigravity record. Flat — no `payload` envelope, no `role`. Only the
// fields a case actually exercises are set; every one of them is optional on
// the wire except `source`, `type` and `created_at`.
function agy(rec: {
  source: string;
  created_at: string;
  type?: string;
  content?: string;
  thinking?: string;
  tool_calls?: unknown;
  status?: string;
}): string {
  return line({ status: 'DONE', step_index: 0, type: 'PLANNER_RESPONSE', ...rec });
}

describe('parseTranscript — prompt/response text', () => {
  it('maps USER_EXPLICIT to a prompt and MODEL to a response', () => {
    const jsonl = [
      agy({
        source: 'USER_EXPLICIT',
        type: 'USER_INPUT',
        created_at: '2026-07-14T10:00:01Z',
        content: 'deploy the staging box for me',
      }),
      agy({
        source: 'MODEL',
        created_at: '2026-07-14T10:00:02Z',
        content: 'Starting the staging deploy now.',
      }),
    ].join('\n');

    expect(parseTranscript(jsonl)).toEqual([
      {
        kind: 'prompt',
        text: 'deploy the staging box for me',
        occurredAt: '2026-07-14T10:00:01Z',
        filePath: '',
      },
      {
        kind: 'response',
        text: 'Starting the staging deploy now.',
        occurredAt: '2026-07-14T10:00:02Z',
        filePath: '',
      },
    ]);
  });

  // SYSTEM is host-injected text that neither the user nor the model authored.
  // An unrecognised source is dropped by the same branch, which is what stops a
  // future actor landing as a 'response' by default.
  it('drops SYSTEM records and records whose source it does not recognise', () => {
    const jsonl = [
      agy({
        source: 'SYSTEM',
        type: 'SYSTEM_MESSAGE',
        created_at: '2026-07-14T10:00:01Z',
        content: 'host preamble',
      }),
      agy({
        source: 'SOME_FUTURE_ACTOR',
        created_at: '2026-07-14T10:00:02Z',
        content: 'from an actor this parser has never seen',
      }),
    ].join('\n');
    expect(parseTranscript(jsonl)).toEqual([]);
  });

  // The case that makes dropping `thinking` a data-loss bug rather than a
  // stylistic choice: this record shape (thinking + tool_calls, no content)
  // occurs in a real transcript, and its reasoning text is all it carries.
  it('keeps a record whose only text is thinking', () => {
    const jsonl = agy({
      source: 'MODEL',
      created_at: '2026-07-14T10:00:03Z',
      thinking: 'The user handed me a credential in the previous turn.',
      tool_calls: [{ name: 'run_command', args: { CommandLine: 'ls' } }],
    });
    expect(parseTranscript(jsonl)).toEqual([
      {
        kind: 'response',
        text: 'The user handed me a credential in the previous turn.',
        occurredAt: '2026-07-14T10:00:03Z',
        filePath: '',
      },
    ]);
  });

  it('joins content and thinking when a record carries both', () => {
    const jsonl = agy({
      source: 'MODEL',
      created_at: '2026-07-14T10:00:04Z',
      content: 'visible reply',
      thinking: 'internal reasoning',
    });
    expect(parseTranscript(jsonl)[0]?.text).toBe('visible reply\ninternal reasoning');
  });

  // Tool arguments are not scan input today (see the file header). A record
  // carrying only tool_calls therefore yields nothing rather than an empty
  // message, so the scan never records a finding-less row.
  it('skips a record whose only payload is tool_calls', () => {
    const jsonl = agy({
      source: 'MODEL',
      type: 'RUN_COMMAND',
      created_at: '2026-07-14T10:00:05Z',
      tool_calls: [{ name: 'run_command', args: { CommandLine: 'echo hi' } }],
    });
    expect(parseTranscript(jsonl)).toEqual([]);
  });

  it('stamps the source transcript path onto every message so a finding can be located', () => {
    const path =
      '/Users/me/.gemini/antigravity/brain/conv-1/.system_generated/logs/transcript_full.jsonl';
    const jsonl = agy({
      source: 'USER_EXPLICIT',
      created_at: '2026-07-14T10:00:01Z',
      content: 'a prompt',
    });
    const msgs = parseTranscript(jsonl, 0, Infinity, path);
    expect(msgs.length).toBeGreaterThan(0);
    for (const msg of msgs) expect(msg.filePath).toBe(path);
  });

  it('drops messages at/after the setup-start cutoff (beforeMs), keeps older ones', () => {
    const jsonl = [
      agy({
        source: 'USER_EXPLICIT',
        created_at: '2026-07-14T10:00:01Z',
        content: 'pre-install leak',
      }),
      agy({
        source: 'USER_EXPLICIT',
        created_at: '2026-07-16T10:00:00Z',
        content: 'post-install wizard output',
      }),
    ].join('\n');

    const cutoff = Date.parse('2026-07-15T00:00:00.000Z'); // setup-start
    expect(parseTranscript(jsonl, 0, cutoff).map((m) => m.text)).toEqual(['pre-install leak']);
  });

  it('applies the sinceMs window bound', () => {
    const jsonl = agy({
      source: 'USER_EXPLICIT',
      created_at: '2026-01-01T00:00:00Z',
      content: 'old',
    });
    expect(parseTranscript(jsonl, Date.parse('2026-06-01T00:00:00.000Z'))).toEqual([]);
  });

  it('skips a record with no created_at, and one whose timestamp will not parse', () => {
    const jsonl = [
      line({ source: 'USER_EXPLICIT', type: 'USER_INPUT', content: 'no timestamp' }),
      agy({ source: 'USER_EXPLICIT', created_at: 'not-a-date', content: 'bad timestamp' }),
    ].join('\n');
    expect(parseTranscript(jsonl)).toEqual([]);
  });

  it('skips malformed JSON lines without throwing', () => {
    const jsonl = ['not json at all', '{"broken":', 'null', '[]'].join('\n');
    expect(() => parseTranscript(jsonl)).not.toThrow();
    expect(parseTranscript(jsonl)).toEqual([]);
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

describe('iterateHistory — which of a conversations two transcript files is read', () => {
  let root: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-agy-walk-'));
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  function seed(conversation: string, files: Record<string, string>): void {
    const logs = join(root, conversation, '.system_generated', 'logs');
    mkdirSync(logs, { recursive: true });
    for (const [name, body] of Object.entries(files)) writeFileSync(join(logs, name), body);
  }

  const AT = '2026-07-14T10:00:01Z';
  const NOW = Date.parse('2026-07-15T00:00:00.000Z');
  const walk = (): string[] =>
    [...iterateHistory({ dir: root, now: NOW, windowDays: 30 })].map((m) => m.text);

  // The truncated file caps `content` and says so in `truncated_fields`. Both
  // files carry the SAME records, so reading both scans every message twice and
  // reports every finding twice.
  it('reads the full file and skips its truncated sibling', () => {
    seed('conv-a', {
      'transcript.jsonl': line({
        source: 'USER_EXPLICIT',
        type: 'USER_INPUT',
        status: 'DONE',
        step_index: 0,
        created_at: AT,
        content: 'cut short here',
        truncated_fields: ['content'],
      }),
      'transcript_full.jsonl': line({
        source: 'USER_EXPLICIT',
        type: 'USER_INPUT',
        status: 'DONE',
        step_index: 0,
        created_at: AT,
        content: 'cut short here and then the rest of it',
      }),
    });

    expect(walk()).toEqual(['cut short here and then the rest of it']);
  });

  // The pair is resolved among ONE directory's entries. A conversation that has
  // only the short file must still be read, or the skip above would silently
  // drop whole conversations.
  it('still reads a conversation that has only the truncated file', () => {
    seed('conv-b', {
      'transcript.jsonl': line({
        source: 'USER_EXPLICIT',
        type: 'USER_INPUT',
        status: 'DONE',
        step_index: 0,
        created_at: AT,
        content: 'only file present',
      }),
    });

    expect(walk()).toEqual(['only file present']);
  });

  it('resolves the pair per conversation, not once across the whole walk', () => {
    seed('conv-a', {
      'transcript.jsonl': line({
        source: 'USER_EXPLICIT',
        status: 'DONE',
        step_index: 0,
        type: 'USER_INPUT',
        created_at: AT,
        content: 'a-short',
      }),
      'transcript_full.jsonl': line({
        source: 'USER_EXPLICIT',
        status: 'DONE',
        step_index: 0,
        type: 'USER_INPUT',
        created_at: AT,
        content: 'a-full',
      }),
    });
    seed('conv-b', {
      'transcript.jsonl': line({
        source: 'USER_EXPLICIT',
        status: 'DONE',
        step_index: 0,
        type: 'USER_INPUT',
        created_at: AT,
        content: 'b-short',
      }),
    });

    expect(walk().sort()).toEqual(['a-full', 'b-short']);
  });
});

describe('transcriptsDir — the brain root', () => {
  // This package shipped `~/.gemini/antigravity-cli/brain` twice: once carried
  // over from the Codex template, once as a correction that was still wrong.
  // Both times every unit test passed, because a test that spells the same
  // literal as the implementation agrees with it whatever it says. So the
  // assertion that can actually fail on a wrong constant is the one below that
  // consults the filesystem — the two here only pin the known-wrong values out.
  it('is under ~/.gemini and is not the editor store or the -cli path', () => {
    const dir = transcriptsDir();
    expect(dir.startsWith(join(homedir(), '.gemini'))).toBe(true);
    expect(dir).not.toContain('antigravity-cli');
    expect(dir).not.toContain('antigravity-ide');
  });

  it('honours the home override so no suite depends on the real home', () => {
    expect(transcriptsDir('/tmp/fake-home')).toBe(
      join('/tmp/fake-home', '.gemini', 'antigravity', 'brain'),
    );
  });

  // The guard with teeth: where Antigravity is actually installed, the root
  // this module names must be a directory that exists. Skips where it is not
  // installed (CI, a contributor without it), so it never turns into a flake —
  // but on any machine that has run the CLI it goes red the moment the path
  // literal drifts from where the host really writes.
  it('names a directory that exists wherever Antigravity is installed', (ctx) => {
    if (!existsSync(join(homedir(), '.gemini'))) {
      ctx.skip('Antigravity is not installed on this machine');
      return;
    }
    expect(existsSync(transcriptsDir())).toBe(true);
  });
});
