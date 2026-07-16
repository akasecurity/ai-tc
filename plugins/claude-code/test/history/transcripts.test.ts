import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { AssistantUsageRecord, UserPromptRecord } from '../../src/history/transcripts.ts';
import {
  iterateHistory,
  iterateUsage,
  parseTranscript,
  parseTranscriptToolCalls,
  parseTranscriptUsage,
} from '../../src/history/transcripts.ts';

// A representative transcript: a string-content prompt, an array-content prompt
// (text + image), an assistant turn (thinking + text + tool_use), a tool_result
// user turn, an out-of-window record, plus metadata and a malformed line.
const TRANSCRIPT = [
  JSON.stringify({ type: 'ai-title', aiTitle: 'x', sessionId: 's' }),
  JSON.stringify({
    type: 'user',
    timestamp: '2026-06-20T10:00:00.000Z',
    message: { role: 'user', content: 'hello with SECRET_MARKER' },
  }),
  JSON.stringify({
    type: 'user',
    timestamp: '2026-06-20T10:01:00.000Z',
    message: {
      role: 'user',
      content: [
        { type: 'text', text: 'array prompt text' },
        { type: 'image', source: {} },
      ],
    },
  }),
  JSON.stringify({
    type: 'assistant',
    timestamp: '2026-06-20T10:02:00.000Z',
    message: {
      role: 'assistant',
      content: [
        { type: 'thinking', thinking: 'private chain of thought' },
        { type: 'text', text: 'assistant reply here' },
        { type: 'tool_use', name: 'Bash', input: { command: 'echo hi' } },
      ],
    },
  }),
  JSON.stringify({
    type: 'user',
    timestamp: '2026-06-20T10:03:00.000Z',
    message: { role: 'user', content: [{ type: 'tool_result', content: 'tool output' }] },
  }),
  JSON.stringify({
    type: 'user',
    timestamp: '2020-01-01T00:00:00.000Z',
    message: { role: 'user', content: 'ancient prompt' },
  }),
  '{ not json',
].join('\n');

describe('parseTranscript', () => {
  it('keeps user prompts + assistant text, drops everything else', () => {
    const msgs = parseTranscript(TRANSCRIPT);
    expect(msgs).toEqual([
      { kind: 'prompt', text: 'hello with SECRET_MARKER', occurredAt: '2026-06-20T10:00:00.000Z' },
      { kind: 'prompt', text: 'array prompt text', occurredAt: '2026-06-20T10:01:00.000Z' },
      { kind: 'response', text: 'assistant reply here', occurredAt: '2026-06-20T10:02:00.000Z' },
      { kind: 'prompt', text: 'ancient prompt', occurredAt: '2020-01-01T00:00:00.000Z' },
    ]);
    // thinking, tool_use, tool_result, image, metadata and malformed lines are gone.
    const joined = JSON.stringify(msgs);
    expect(joined).not.toContain('private chain of thought');
    expect(joined).not.toContain('tool output');
  });

  it('drops records whose timestamp is unparseable (never NaN downstream)', () => {
    const jsonl = [
      JSON.stringify({
        type: 'user',
        timestamp: 'not-a-date',
        message: { role: 'user', content: 'leak SECRET_MARKER here' },
      }),
      JSON.stringify({
        type: 'user',
        timestamp: '2026-06-20T10:00:00.000Z',
        message: { role: 'user', content: 'valid one' },
      }),
    ].join('\n');
    const msgs = parseTranscript(jsonl);
    expect(msgs.map((m) => m.text)).toEqual(['valid one']);
  });

  it('drops records older than the retention cutoff', () => {
    const cutoff = Date.parse('2026-01-01T00:00:00.000Z');
    const msgs = parseTranscript(TRANSCRIPT, cutoff);
    expect(msgs.map((m) => m.text)).not.toContain('ancient prompt');
    expect(msgs).toHaveLength(3);
  });
});

describe('parseTranscriptToolCalls', () => {
  // An assistant turn with two tool_use blocks, the user turn carrying their
  // tool_results, a streaming/content-block DUPLICATE of the first (same id), and a
  // tool_use with no sessionId (unaddressable), plus a malformed line.
  const TOOL_TRANSCRIPT = [
    JSON.stringify({
      type: 'assistant',
      sessionId: 'sess-1',
      uuid: 'a1',
      parentUuid: 'u1',
      timestamp: '2026-06-20T10:02:00.000Z',
      message: {
        role: 'assistant',
        content: [
          { type: 'text', text: 'running tools' },
          { type: 'tool_use', id: 'toolu_A', name: 'Bash', input: { command: 'echo hi' } },
          { type: 'tool_use', id: 'toolu_B', name: 'Read', input: { file_path: '/x' } },
        ],
      },
    }),
    JSON.stringify({
      type: 'user',
      sessionId: 'sess-1',
      timestamp: '2026-06-20T10:03:00.000Z',
      message: {
        role: 'user',
        content: [
          { type: 'tool_result', tool_use_id: 'toolu_A', content: 'hi\n' },
          { type: 'tool_result', tool_use_id: 'toolu_B', content: 'file body', is_error: true },
        ],
      },
    }),
    JSON.stringify({
      type: 'assistant',
      sessionId: 'sess-1',
      uuid: 'a1b',
      parentUuid: 'u1',
      timestamp: '2026-06-20T10:02:01.000Z',
      message: {
        role: 'assistant',
        content: [{ type: 'tool_use', id: 'toolu_A', name: 'Bash', input: { command: 'echo hi' } }],
      },
    }),
    JSON.stringify({
      type: 'assistant',
      uuid: 'a2',
      timestamp: '2026-06-20T10:04:00.000Z',
      message: {
        role: 'assistant',
        content: [{ type: 'tool_use', id: 'toolu_C', name: 'Edit', input: {} }],
      },
    }),
    '{ not json',
  ].join('\n');

  it('extracts one record per tool_use, enriched by its matching tool_result', () => {
    const calls = parseTranscriptToolCalls(TOOL_TRANSCRIPT);
    expect(calls).toHaveLength(2); // A + B; dup deduped, no-session dropped

    const bash = calls.find((c) => c.toolUseId === 'toolu_A');
    expect(bash).toMatchObject({
      sessionId: 'sess-1',
      toolName: 'Bash',
      uuid: 'a1',
      parentUuid: 'u1',
      occurredAt: '2026-06-20T10:02:00.000Z',
      isError: false,
      target: 'echo hi', // Bash → command
    });
    expect(bash?.inputSize).toBeGreaterThan(0);
    expect(bash?.outputSize).toBe('hi\n'.length);

    const read = calls.find((c) => c.toolUseId === 'toolu_B');
    expect(read?.toolName).toBe('Read');
    expect(read?.isError).toBe(true);
    expect(read?.target).toBe('/x'); // Read → file_path
  });

  it('captures a salient target per tool, falling back to JSON for unknown tools', () => {
    const jsonl = [
      JSON.stringify({
        type: 'assistant',
        sessionId: 'sess-1',
        uuid: 'x',
        timestamp: '2026-06-20T10:00:00.000Z',
        message: {
          role: 'assistant',
          content: [
            {
              type: 'tool_use',
              id: 'toolu_url',
              name: 'WebFetch',
              input: { url: 'https://ex.com/x' },
            },
            { type: 'tool_use', id: 'toolu_mcp', name: 'mcp__foo__bar', input: { a: 1, b: 'two' } },
          ],
        },
      }),
    ].join('\n');
    const calls = parseTranscriptToolCalls(jsonl);
    expect(calls.find((c) => c.toolUseId === 'toolu_url')?.target).toBe('https://ex.com/x');
    expect(calls.find((c) => c.toolUseId === 'toolu_mcp')?.target).toBe('{"a":1,"b":"two"}');
  });

  it('dedupes a repeated tool_use id, keeping the first seen', () => {
    const calls = parseTranscriptToolCalls(TOOL_TRANSCRIPT);
    expect(calls.filter((c) => c.toolUseId === 'toolu_A')).toHaveLength(1);
  });

  it('drops a tool_use with no sessionId (cannot address a session root)', () => {
    const calls = parseTranscriptToolCalls(TOOL_TRANSCRIPT);
    expect(calls.some((c) => c.toolUseId === 'toolu_C')).toBe(false);
  });

  it('honors the sinceMs window', () => {
    const after = Date.parse('2026-06-21T00:00:00.000Z');
    expect(parseTranscriptToolCalls(TOOL_TRANSCRIPT, after)).toHaveLength(0);
  });
});

describe('iterateHistory', () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-transcripts-'));
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('walks every project, applies the window, and ignores non-jsonl / unreadable', () => {
    const projectDir = join(root, '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    writeFileSync(join(projectDir, 'session.jsonl'), TRANSCRIPT);
    writeFileSync(join(projectDir, 'notes.txt'), 'ignored');

    // Anchor "now" a few days after the recent (2026-06-20) records.
    const now = Date.parse('2026-06-25T00:00:00.000Z');
    // Wide window → the three 2026 messages, not the 2020 one.
    const wide = [...iterateHistory({ dir: root, windowDays: 365, now })];
    expect(wide.map((m) => m.text)).toEqual([
      'hello with SECRET_MARKER',
      'array prompt text',
      'assistant reply here',
    ]);

    // Tiny window (1 day, cutoff 2026-06-24) → nothing recent enough.
    expect([...iterateHistory({ dir: root, windowDays: 1, now })]).toHaveLength(0);
  });

  it('yields nothing when the transcripts dir is absent (fail-open)', () => {
    expect([...iterateHistory({ dir: join(root, 'does-not-exist') })]).toHaveLength(0);
  });
});

// Self-contamination guard: the backfill must never re-scan AKA's OWN setup
// session (whose transcript carries the wizard's masked posture/values), or a
// self-scan loop records the masked values as fresh "findings" on the next
// backfill. Two id-based / time-window bounds (never a content heuristic): skip
// the *.jsonl whose basename is the current session id, and drop messages at/after
// the setup-start cutoff.
describe('iterateHistory self-contamination guard', () => {
  let root: string;
  const now = Date.parse('2026-06-25T00:00:00.000Z');
  const msg = (ts: string, text: string): string =>
    JSON.stringify({ type: 'user', timestamp: ts, message: { role: 'user', content: text } });

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-guard-'));
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('excludes the transcript whose basename matches excludeSessionId, keeps other sessions', () => {
    const projectDir = join(root, '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    // The current session's file (its own masked wizard output) and a real,
    // unrelated pre-install session — both well within the window.
    writeFileSync(
      join(projectDir, 'aka-setup-abc.jsonl'),
      msg('2026-06-20T10:00:00.000Z', 'current session masked posture'),
    );
    writeFileSync(
      join(projectDir, 'other-xyz.jsonl'),
      msg('2026-06-20T10:00:00.000Z', 'real pre-install history'),
    );

    // Without exclusion: both sessions are scanned (baseline sanity).
    const all = [...iterateHistory({ dir: root, windowDays: 365, now })].map((m) => m.text);
    expect(all).toContain('current session masked posture');
    expect(all).toContain('real pre-install history');

    // With exclusion: the current session's file is skipped entirely; a user's
    // genuine history is still fully scanned.
    const guarded = [
      ...iterateHistory({ dir: root, windowDays: 365, now, excludeSessionId: 'aka-setup-abc' }),
    ].map((m) => m.text);
    expect(guarded).toEqual(['real pre-install history']);
  });

  it('drops messages at/after the setup-start cutoff (beforeMs), keeps older ones', () => {
    const projectDir = join(root, '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    writeFileSync(
      join(projectDir, 's.jsonl'),
      [
        msg('2026-06-20T10:00:00.000Z', 'pre-install leak'),
        msg('2026-06-23T10:00:00.000Z', 'post-install wizard output'),
      ].join('\n'),
    );

    const cutoff = Date.parse('2026-06-22T00:00:00.000Z'); // setup-start
    const bounded = [...iterateHistory({ dir: root, windowDays: 365, now, beforeMs: cutoff })].map(
      (m) => m.text,
    );
    expect(bounded).toEqual(['pre-install leak']);
  });
});

// The real `usage` shape from a transcript — kept verbatim so the parser's
// passthrough of the whole bag is exercised, not a trimmed stand-in.
const REAL_USAGE = {
  input_tokens: 8424,
  cache_creation_input_tokens: 7420,
  cache_read_input_tokens: 11404,
  output_tokens: 1202,
  server_tool_use: { web_search_requests: 0, web_fetch_requests: 0 },
  service_tier: 'standard',
  cache_creation: { ephemeral_1h_input_tokens: 7420, ephemeral_5m_input_tokens: 0 },
  inference_geo: 'not_available',
  iterations: [{ input_tokens: 8424, output_tokens: 1202 }],
  speed: 'standard',
};

// A representative usage-bearing transcript: a real user prompt, an assistant
// reply carrying real `message.usage`, a tool-result user record (which still
// carries the turn's promptId), a `<synthetic>` assistant record, a zero-usage
// assistant record, an assistant record with no usage at all, a non-message
// metadata line, and a malformed line.
const USAGE_TRANSCRIPT = [
  JSON.stringify({ type: 'ai-title', aiTitle: 'x', sessionId: 's1' }),
  JSON.stringify({
    type: 'user',
    uuid: 'u-prompt',
    promptId: 'prompt-1',
    timestamp: '2026-06-20T10:00:00.000Z',
    message: { role: 'user', content: 'hello' },
  }),
  JSON.stringify({
    type: 'assistant',
    uuid: 'a-1',
    parentUuid: 'u-prompt',
    sessionId: 's1',
    cwd: '/Users/me/project',
    version: '1.2.3',
    gitBranch: 'main',
    entrypoint: 'cli',
    timestamp: '2026-06-20T10:00:05.000Z',
    message: { role: 'assistant', id: 'msg_abc', model: 'claude-opus-4-1', usage: REAL_USAGE },
  }),
  // tool-result user record: type:user, fresh uuid, SAME promptId as the prompt.
  JSON.stringify({
    type: 'user',
    uuid: 'u-toolresult',
    promptId: 'prompt-1',
    timestamp: '2026-06-20T10:00:06.000Z',
    message: { role: 'user', content: [{ type: 'tool_result', content: 'tool output' }] },
  }),
  // <synthetic> model → skipped even though it has a usage block.
  JSON.stringify({
    type: 'assistant',
    uuid: 'a-synth',
    sessionId: 's1',
    timestamp: '2026-06-20T10:00:07.000Z',
    message: {
      role: 'assistant',
      id: 'msg_synth',
      model: '<synthetic>',
      usage: { input_tokens: 5, output_tokens: 9 },
    },
  }),
  // all-zero usage (no cache either) → skipped.
  JSON.stringify({
    type: 'assistant',
    uuid: 'a-zero',
    sessionId: 's1',
    timestamp: '2026-06-20T10:00:08.000Z',
    message: {
      role: 'assistant',
      id: 'msg_zero',
      model: 'claude-opus-4-1',
      usage: { input_tokens: 0, output_tokens: 0 },
    },
  }),
  // no usage block at all → skipped.
  JSON.stringify({
    type: 'assistant',
    uuid: 'a-nousage',
    sessionId: 's1',
    timestamp: '2026-06-20T10:00:09.000Z',
    message: { role: 'assistant', id: 'msg_nousage', model: 'claude-opus-4-1', content: [] },
  }),
  '{ not json',
].join('\n');

describe('parseTranscriptUsage', () => {
  it('surfaces assistant usage records and user prompt records, skips the rest', () => {
    const records = parseTranscriptUsage(USAGE_TRANSCRIPT);

    const users = records.filter((r): r is UserPromptRecord => r.kind === 'user');
    const assistants = records.filter((r): r is AssistantUsageRecord => r.kind === 'assistant');

    // Both the real prompt AND the tool-result user record yield their promptId.
    expect(users).toEqual([
      { kind: 'user', uuid: 'u-prompt', promptId: 'prompt-1' },
      { kind: 'user', uuid: 'u-toolresult', promptId: 'prompt-1' },
    ]);

    // Exactly one usable assistant record: <synthetic>, zero-usage and no-usage
    // are all dropped.
    expect(assistants).toHaveLength(1);
    const [call] = assistants;
    if (call === undefined) throw new Error('expected one assistant usage record');
    expect(call.messageId).toBe('msg_abc');
    expect(call.uuid).toBe('a-1');
    expect(call.parentUuid).toBe('u-prompt');
    expect(call.model).toBe('claude-opus-4-1');
    expect(call.sessionId).toBe('s1');
    expect(call.occurredAt).toBe('2026-06-20T10:00:05.000Z');
    // inventory fields for the ensure-root step.
    expect(call.cwd).toBe('/Users/me/project');
    expect(call.version).toBe('1.2.3');
    expect(call.gitBranch).toBe('main');
    expect(call.entrypoint).toBe('cli');
    // the full usage bag is passed through verbatim (Tier-2 fields preserved).
    expect(call.usage).toEqual(REAL_USAGE);
  });

  it('does NOT compute run_key — that is the reconciler job', () => {
    const records = parseTranscriptUsage(USAGE_TRANSCRIPT);
    const call = records.find((r): r is AssistantUsageRecord => r.kind === 'assistant');
    if (call === undefined) throw new Error('expected one assistant usage record');
    expect(call).not.toHaveProperty('run_key');
    expect(call).not.toHaveProperty('runKey');
  });

  it('drops user records missing uuid or promptId (no run-key join possible)', () => {
    const jsonl = [
      JSON.stringify({ type: 'user', uuid: 'u-only', message: { content: 'x' } }),
      JSON.stringify({ type: 'user', promptId: 'p-only', message: { content: 'x' } }),
      JSON.stringify({
        type: 'user',
        uuid: 'u-ok',
        promptId: 'p-ok',
        message: { content: 'x' },
      }),
    ].join('\n');
    expect(parseTranscriptUsage(jsonl)).toEqual([{ kind: 'user', uuid: 'u-ok', promptId: 'p-ok' }]);
  });

  it('collapses content-block records sharing one message.id into a single record', () => {
    // A single assistant message is written as 3 records (thinking / text /
    // tool_use), all sharing message.id + requestId, carrying IDENTICAL usage.
    const usage = { input_tokens: 100, output_tokens: 42, cache_read_input_tokens: 7 };
    const jsonl = [
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-1',
        sessionId: 's1',
        timestamp: '2026-06-20T10:00:00.000Z',
        message: { role: 'assistant', id: 'msg_dup', model: 'claude-opus-4-1', usage },
      }),
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-2',
        sessionId: 's1',
        timestamp: '2026-06-20T10:00:01.000Z',
        message: { role: 'assistant', id: 'msg_dup', model: 'claude-opus-4-1', usage },
      }),
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-3',
        sessionId: 's1',
        timestamp: '2026-06-20T10:00:02.000Z',
        message: { role: 'assistant', id: 'msg_dup', model: 'claude-opus-4-1', usage },
      }),
    ].join('\n');

    const assistants = parseTranscriptUsage(jsonl).filter(
      (r): r is AssistantUsageRecord => r.kind === 'assistant',
    );
    expect(assistants).toHaveLength(1);
    const [call] = assistants;
    if (call === undefined) throw new Error('expected one collapsed assistant record');
    expect(call.messageId).toBe('msg_dup');
    expect(call.usage).toEqual(usage);
  });

  it('collapses a streaming pair to the terminal (max output_tokens) record', () => {
    // Streaming partials share message.id; only output_tokens grows. The terminal
    // record (full count, last in file order) must win — INSERT OR IGNORE keeps
    // the first row, so without the collapse the partial output is what survives.
    const jsonl = [
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-partial',
        sessionId: 's1',
        timestamp: '2026-06-20T10:00:00.000Z',
        message: {
          role: 'assistant',
          id: 'msg_stream',
          model: 'claude-opus-4-1',
          stop_reason: null,
          usage: { input_tokens: 100, output_tokens: 1 },
        },
      }),
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-terminal',
        sessionId: 's1',
        timestamp: '2026-06-20T10:00:01.000Z',
        message: {
          role: 'assistant',
          id: 'msg_stream',
          model: 'claude-opus-4-1',
          stop_reason: 'tool_use',
          usage: { input_tokens: 100, output_tokens: 338 },
        },
      }),
    ].join('\n');

    const assistants = parseTranscriptUsage(jsonl).filter(
      (r): r is AssistantUsageRecord => r.kind === 'assistant',
    );
    expect(assistants).toHaveLength(1);
    const [call] = assistants;
    if (call === undefined) throw new Error('expected one collapsed assistant record');
    expect(call.uuid).toBe('a-terminal');
    expect(call.usage.output_tokens).toBe(338);
  });

  it('preserves ordering: the collapsed record stays between its user records', () => {
    // user → (3 content-block assistant records, collapsed) → following user.
    // The collapsed record must keep its terminal file position so the second
    // user record still comes AFTER it (the reconciler carries promptId forward
    // while walking in order).
    const usage = { input_tokens: 100, output_tokens: 50 };
    const jsonl = [
      JSON.stringify({
        type: 'user',
        uuid: 'u-before',
        promptId: 'prompt-1',
        message: { role: 'user', content: 'hi' },
      }),
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-1',
        sessionId: 's1',
        timestamp: '2026-06-20T10:00:00.000Z',
        message: { role: 'assistant', id: 'msg_x', model: 'claude-opus-4-1', usage },
      }),
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-2',
        sessionId: 's1',
        timestamp: '2026-06-20T10:00:01.000Z',
        message: { role: 'assistant', id: 'msg_x', model: 'claude-opus-4-1', usage },
      }),
      JSON.stringify({
        type: 'user',
        uuid: 'u-after',
        promptId: 'prompt-1',
        message: { role: 'user', content: [{ type: 'tool_result', content: 'out' }] },
      }),
    ].join('\n');

    const records = parseTranscriptUsage(jsonl);
    expect(records.map((r) => (r.kind === 'user' ? r.uuid : `assistant:${r.messageId}`))).toEqual([
      'u-before',
      'assistant:msg_x',
      'u-after',
    ]);
  });

  it('drops an assistant record missing sessionId (not yielded with empty string)', () => {
    const jsonl = [
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-nosession',
        timestamp: '2026-06-20T10:00:00.000Z',
        message: {
          role: 'assistant',
          id: 'msg_nosession',
          model: 'claude-opus-4-1',
          usage: { input_tokens: 10, output_tokens: 5 },
        },
      }),
    ].join('\n');
    expect(parseTranscriptUsage(jsonl)).toEqual([]);
  });

  it('keeps a cache-only record (input+output=0 but cache_read>0)', () => {
    // A real billable turn always has output>0, so none are observed today; but
    // we guard cache so a cache-only record is not silently dropped as zero-usage.
    const jsonl = [
      JSON.stringify({
        type: 'assistant',
        uuid: 'a-cache',
        sessionId: 's1',
        timestamp: '2026-06-20T10:00:00.000Z',
        message: {
          role: 'assistant',
          id: 'msg_cache',
          model: 'claude-opus-4-1',
          usage: { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 11 },
        },
      }),
    ].join('\n');
    const assistants = parseTranscriptUsage(jsonl).filter(
      (r): r is AssistantUsageRecord => r.kind === 'assistant',
    );
    expect(assistants).toHaveLength(1);
    const [call] = assistants;
    if (call === undefined) throw new Error('expected the cache-only record to survive');
    expect(call.messageId).toBe('msg_cache');
    expect(call.usage.cache_read_input_tokens).toBe(11);
  });
});

describe('iterateUsage', () => {
  let root: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-usage-'));
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('walks every project and yields usage records, ignoring non-jsonl / unreadable', () => {
    const projectDir = join(root, '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    writeFileSync(join(projectDir, 'session.jsonl'), USAGE_TRANSCRIPT);
    writeFileSync(join(projectDir, 'notes.txt'), 'ignored');

    // Fixed `now` so the default retention window is deterministic against the
    // fixture's 2026-06-20 timestamps (not the wall clock).
    const records = [...iterateUsage({ dir: root, now: Date.parse('2026-06-25T00:00:00.000Z') })];
    const assistants = records.filter((r): r is AssistantUsageRecord => r.kind === 'assistant');
    const users = records.filter((r): r is UserPromptRecord => r.kind === 'user');
    expect(assistants.map((r) => r.messageId)).toEqual(['msg_abc']);
    expect(users.map((r) => r.promptId)).toEqual(['prompt-1', 'prompt-1']);
  });

  it('bounds the backfill to the retention window — out-of-window records are dropped', () => {
    const projectDir = join(root, '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    writeFileSync(join(projectDir, 'session.jsonl'), USAGE_TRANSCRIPT);

    // `now` is > 30d after the fixture's 2026-06-20 records → all filtered out, so the
    // /aka:setup backfill never re-parses a heavy user's months-old history.
    const inWindow = [...iterateUsage({ dir: root, now: Date.parse('2026-06-25T00:00:00.000Z') })];
    const outOfWindow = [
      ...iterateUsage({ dir: root, now: Date.parse('2026-08-15T00:00:00.000Z') }),
    ];
    expect(inWindow.length).toBeGreaterThan(0);
    expect(outOfWindow).toHaveLength(0);
  });

  it('yields nothing when the transcripts dir is absent (fail-open)', () => {
    expect([...iterateUsage({ dir: join(root, 'does-not-exist') })]).toHaveLength(0);
  });
});
