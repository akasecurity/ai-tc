/**
 * An activity-shaped corpus for the local store — the SQLite twin of the hosted
 * bench's `activity` corpus block, so the two stores are measured and guarded
 * on the same rows.
 *
 * Mirrors a real single-machine store observed 2026-09-03 (120k rows, 4,928
 * roots of which 86% childless, `tool_call` and `llm_call` 96% of the table,
 * ~470-character bags): roots spread over the span, half of them childless,
 * 30% of the rest promptless (no `prompt` child, so the activity test has to
 * walk them), one `tool_call` and one `llm_call` per capture with the keys real
 * bags carry, a `share` on 2% of captures, `ended_at` on `endedRate` of the
 * roots, and one giant session of `giantCaptures`. Deterministic on the
 * options (mulberry32).
 *
 * Raw `INSERT`s, deliberately, where `seedCaptureCorpus` writes through the
 * product's own `recordCapture`: what the guards over this corpus measure is
 * index behaviour over a STATED row shape — the one observed above — and a
 * prepared insert is an order of magnitude cheaper than the capture path, which
 * is what lets two sizes seed inside a hook. The cost is that the shape is
 * asserted here rather than produced by the writer, so a key the reconciler
 * starts writing differently does not show up in these rows; re-read the store
 * before trusting a shape this file states. Never `ANALYZE` here: the shipped
 * store never runs it, so SQLite plans every read from the schema alone, and a
 * corpus with statistics certifies plans no field store gets.
 */
import type { DatabaseSync } from 'node:sqlite';

import { assertNoOpenTransaction } from './transactions.ts';

export interface ActivityCorpusOptions {
  readonly captures: number;
  /**
   * The share of roots stamped with an `ended_at`. Defaults to the hosted
   * bench's 0.9 so the two stores measure the same rows; a real local store
   * has NONE — the local writer never closes a session root — so a guard on
   * the real shape passes 0.
   */
  readonly endedRate?: number;
  /** Captures in the one giant session (the first non-empty root). Default 1,000. */
  readonly giantCaptures?: number;
}

export interface ActivityCorpus {
  readonly captures: number;
  readonly sessions: number;
  /** The instant just past the last capture, epoch millis — the clock windowed reads use. */
  readonly endsAt: number;
  readonly medianSessionId: string;
  readonly largestSessionId: string;
}

const EMPTY_RATE = 0.5;
const PROMPTLESS_RATE = 0.3;
const SHARE_RATE = 0.02;
const SPACING_MS = 74_528;
export const ACTIVITY_CORPUS_EPOCH_MS = 1_704_067_200_000;
const KINDS = ['prompt', 'response', 'code_change', 'tool_use'] as const;
const PROMPTLESS_KINDS = ['response', 'code_change', 'tool_use'] as const;
const TOOLS = ['Bash', 'Read', 'Edit', 'Write', 'WebFetch', 'Grep'] as const;
const MODELS = ['claude-opus-5', 'claude-sonnet-5', 'claude-haiku-4-5-20251001'] as const;
const HARNESSES = ['claudecode', 'claudecode', 'claudecode', 'codex', 'cursor'] as const;
const DESTINATIONS = ['api.github.com', 'hooks.slack.com', 'vault.internal'] as const;

/** mulberry32, the corpus generators' PRNG. */
function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}
function pick<T>(rng: () => number, list: readonly T[]): T {
  const item = list[Math.floor(rng() * list.length)];
  if (item === undefined) throw new RangeError('empty list');
  return item;
}

/** Seed the corpus into `raw` (an open, migrated store) and describe it. */
export function seedActivityCorpus(
  raw: DatabaseSync,
  options: ActivityCorpusOptions,
): ActivityCorpus {
  const CAPTURES = options.captures;
  const ENDED_RATE = options.endedRate ?? 0.9;
  const GIANT_CAPTURES = options.giantCaptures ?? 1_000;
  const SESSIONS = Math.round(CAPTURES / 40);
  const EPOCH_MS = ACTIVITY_CORPUS_EPOCH_MS;
  const rng = seededRandom(CAPTURES + 7);
  const insert = raw.prepare(
    `INSERT INTO audit_events (id, event_type, started_at, ended_at, root_session_id, parent_id, content, attributes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  const nonEmpty: number[] = [];
  const promptless = new Set<number>();
  for (let s = 0; s < SESSIONS; s += 1) {
    const empty = rng() < EMPTY_RATE;
    if (!empty) {
      nonEmpty.push(s);
      if (rng() < PROMPTLESS_RATE) promptless.add(s);
    }
  }
  // Session-major blocks: the first non-empty session is the giant one.
  const blockStart = new Map<number, number>();
  const blockEnd = new Map<number, number>();
  const captureSession = new Int32Array(CAPTURES);
  const per = Math.ceil((CAPTURES - GIANT_CAPTURES) / (nonEmpty.length - 1));
  let cursor = 0;
  nonEmpty.forEach((s, j) => {
    const size = j === 0 ? GIANT_CAPTURES : per;
    const start = cursor;
    const end = Math.min(cursor + size, CAPTURES);
    blockStart.set(s, start);
    blockEnd.set(s, end);
    for (let i = start; i < end; i += 1) captureSession[i] = s;
    cursor = end;
  });
  const lastSession = nonEmpty[nonEmpty.length - 1] ?? 0;
  for (let i = cursor; i < CAPTURES; i += 1) captureSession[i] = lastSession;
  if (cursor < CAPTURES) blockEnd.set(lastSession, CAPTURES);

  raw.exec('BEGIN');
  const childCount = new Map<string, number>();
  for (let s = 0; s < SESSIONS; s += 1) {
    const first = blockStart.get(s);
    const startedAt =
      first === undefined
        ? EPOCH_MS + Math.floor(rng() * CAPTURES) * SPACING_MS
        : EPOCH_MS + first * SPACING_MS;
    const last = first === undefined ? null : (blockEnd.get(s) ?? first + 1) - 1;
    const endedAt =
      rng() < ENDED_RATE
        ? last === null
          ? startedAt + 60_000
          : EPOCH_MS + last * SPACING_MS + SPACING_MS
        : null;
    const repo = Math.floor(rng() * 12);
    insert.run(
      `sess-${String(s)}`,
      'session',
      startedAt,
      endedAt,
      null,
      null,
      `Session ${String(s)}: refactor the session handler in repo-${String(repo)}`,
      JSON.stringify({
        harness: pick(rng, HARNESSES),
        host: `host-${String(s % 2)}`,
        cwd: `/Users/dev/src/repo-${String(repo)}`,
        version: '2.1.7',
        os_version: 'macOS 15.5',
        harness_version: '1.0.128',
        provider: 'anthropic',
        project: `acme/repo-${String(repo)}`,
        repo: `acme/repo-${String(repo)}`,
        branches:
          rng() < 0.3 ? ['main', `feat/module-${String(Math.floor(rng() * 400))}`] : ['main'],
      }),
    );
  }
  for (let i = 0; i < CAPTURES; i += 1) {
    const s = captureSession[i] ?? 0;
    const sid = `sess-${String(s)}`;
    const kind = promptless.has(s) ? pick(rng, PROMPTLESS_KINDS) : pick(rng, KINDS);
    const at = EPOCH_MS + i * SPACING_MS;
    const filePath =
      kind === 'code_change' ? `src/module-${String(Math.floor(rng() * 400))}.ts` : null;
    insert.run(
      `cap-${String(i)}`,
      kind,
      at,
      null,
      sid,
      sid,
      'refactor the session handler so a retry never reopens the store',
      JSON.stringify({
        source_tool: 'claude-code',
        ...(filePath === null ? {} : { file_path: filePath, repo: `acme/repo-${String(s % 12)}` }),
        ...(kind === 'tool_use' ? { tool_name: pick(rng, TOOLS) } : {}),
      }),
    );
    insert.run(
      `tc-${String(i)}`,
      'tool_call',
      at + 1,
      null,
      sid,
      sid,
      null,
      JSON.stringify({
        tool_name: pick(rng, TOOLS),
        target: 'corpus',
        uuid: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`,
        parent_uuid: `00000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`,
        tool_use_id: `toolu_${String(i).padStart(24, '0')}`,
        input_size: Math.floor(rng() * 4000),
        output_size: Math.floor(rng() * 20000),
        is_error: false,
        run_key: `run-${String(s)}-${String(Math.floor(i / 8))}`,
      }),
    );
    insert.run(
      `llm-${String(i)}`,
      'llm_call',
      at + 2,
      null,
      sid,
      sid,
      null,
      JSON.stringify({
        model: pick(rng, MODELS),
        provider: 'anthropic',
        input_tokens: 400 + Math.floor(rng() * 6000),
        output_tokens: 30 + Math.floor(rng() * 1500),
        cache_creation_input_tokens: Math.floor(rng() * 3000),
        cache_read_input_tokens: Math.floor(rng() * 40000),
        ephemeral_1h_input_tokens: 0,
        ephemeral_5m_input_tokens: Math.floor(rng() * 3000),
        service_tier: rng() < 0.9 ? 'standard' : 'batch',
        web_search_requests: rng() < 0.05 ? 1 : 0,
        web_fetch_requests: 0,
        message_id: `msg_${String(i).padStart(24, '0')}`,
        run_key: `run-${String(s)}-${String(Math.floor(i / 8))}`,
      }),
    );
    let n = 3;
    if (rng() < SHARE_RATE) {
      insert.run(
        `share-${String(i)}`,
        'share',
        at + 3,
        null,
        sid,
        sid,
        null,
        JSON.stringify({ destination: pick(rng, DESTINATIONS), bytes: Math.floor(rng() * 5000) }),
      );
      n += 1;
    }
    childCount.set(sid, (childCount.get(sid) ?? 0) + n);
  }
  raw.exec('COMMIT');
  // A seeder that returns inside its BEGIN makes every read below it measure
  // an empty store and report the number as a result.
  assertNoOpenTransaction(raw);

  const sized = [...childCount.entries()].sort((a, b) => b[1] - a[1]);
  return {
    captures: CAPTURES,
    sessions: SESSIONS,
    endsAt: EPOCH_MS + CAPTURES * SPACING_MS,
    largestSessionId: sized[0]?.[0] ?? '',
    medianSessionId: sized[Math.floor(sized.length / 2)]?.[0] ?? '',
  };
}
