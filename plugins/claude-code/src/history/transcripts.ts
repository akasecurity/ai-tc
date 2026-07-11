// Claude Code transcript adapter: turn the host's `~/.claude/projects/*/*.jsonl`
// session logs into the text-bearing messages worth scanning for already-leaked
// secrets. This is the ONE place that knows the Claude Code transcript shape;
// the scan orchestrator (./scan.ts) stays format-agnostic and reuses the SDK
// detect→record path.
//
// We cover user prompts and assistant replies only (tool inputs/outputs are a
// later pass). Pure parsing (string → messages) is split from the filesystem
// walk so the parser unit-tests without touching disk.
import { readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { EventKind } from '@akasecurity/schema';

// One scannable unit pulled from a transcript. `occurredAt` is the record's own
// ISO timestamp so a recorded finding lands on the timeline when it really
// leaked, not at scan time.
export interface ScannedMessage {
  kind: EventKind; // 'prompt' (a user turn) | 'response' (an assistant reply)
  text: string;
  occurredAt: string;
}

// Where Claude Code writes its per-project, per-session transcripts.
export function transcriptsDir(): string {
  return join(homedir(), '.claude', 'projects');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

// A message's `content` is either a plain string (early user turns) or an array
// of typed blocks. We keep only the human/assistant prose — `text` blocks and
// bare strings — and drop `thinking`, `tool_use`, `tool_result` and `image`,
// which belong to the deferred tool-I/O pass.
function extractText(content: unknown): string {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  const parts: string[] = [];
  for (const block of content) {
    if (isRecord(block) && block.type === 'text' && typeof block.text === 'string') {
      parts.push(block.text);
    }
  }
  return parts.join('\n');
}

// Parse one transcript file's contents (newline-delimited JSON). `sinceMs` drops
// records older than the retention window. Malformed lines are skipped, never
// thrown — a truncated/partial transcript must not abort the scan.
export function parseTranscript(jsonl: string, sinceMs = 0): ScannedMessage[] {
  const out: ScannedMessage[] = [];
  for (const line of jsonl.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    let rec: unknown;
    try {
      rec = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (!isRecord(rec)) continue;
    if (rec.type !== 'user' && rec.type !== 'assistant') continue;
    const occurredAt = typeof rec.timestamp === 'string' ? rec.timestamp : '';
    if (occurredAt === '') continue;
    // Drop unparseable timestamps: a NaN here would slip past the window check
    // (`NaN < sinceMs` is false) and later land as NaN in the NOT NULL occurred_at
    // column, where the insert is silently rolled back — losing a real finding.
    const occurredMs = Date.parse(occurredAt);
    if (Number.isNaN(occurredMs)) continue;
    if (sinceMs > 0 && occurredMs < sinceMs) continue;
    const message = rec.message;
    if (!isRecord(message)) continue;
    const text = extractText(message.content);
    if (text.trim() === '') continue;
    out.push({ kind: rec.type === 'user' ? 'prompt' : 'response', text, occurredAt });
  }
  return out;
}

// ───────────────────────────── usage (token) path ─────────────────────────────
//
// A SECOND, independent parse of the same `~/.claude/projects/*/*.jsonl` files,
// for the token-usage reconciler. It is kept
// fully separate from the secret-scan text path above: that path keeps only
// prose and drops `usage`; this one keeps only the numeric usage facts and the
// correlation/inventory ids, and drops the prose. Same pure-parse-then-walk
// split so `parseTranscriptUsage` unit-tests without touching disk.
//
// Crucially this parser is STANDALONE: it does NOT compute `run_key` (that is
// the reconciler's job, one `parentUuid → promptId` hop), and it
// does NOT import `LlmCallAttributes` from `@akasecurity/schema`. It only surfaces the
// raw transcript fields; the reconciler maps them to the schema.

// The `message.usage` block as it appears on an `assistant` record. Every field
// is optional/loosely typed because non-Anthropic gateways may omit the
// Anthropic-specific keys; we keep the whole bag verbatim so the
// reconciler can promote whichever fields it wants (Tier 1/2).
export interface TranscriptUsage {
  input_tokens?: number;
  output_tokens?: number;
  cache_creation_input_tokens?: number;
  cache_read_input_tokens?: number;
  [key: string]: unknown;
}

// One assistant API response = one usage-bearing `llm_call`. Carries
// the token bag plus the correlation ids and the host/repo/harness
// fields the reconciler needs to ensure inventory + the session root.
export interface AssistantUsageRecord {
  kind: 'assistant';
  sessionId: string;
  messageId: string; // message.id (`msg_…`) — the deterministic llm_call key
  uuid: string;
  parentUuid: string | undefined; // points at the parent user record (carries promptId)
  model: string;
  usage: TranscriptUsage;
  occurredAt: string; // record's own ISO timestamp
  cwd: string | undefined;
  version: string | undefined;
  gitBranch: string | undefined;
  entrypoint: string | undefined;
}

// Every `user` record — real prompts AND tool-result records — carries the turn's
// `promptId`. The reconciler maps `assistant.parentUuid → user.uuid`
// to look up the `promptId` that becomes the call's `run_key`. We surface the bare
// minimum (the join key + the run key); the prose belongs to the text path.
export interface UserPromptRecord {
  kind: 'user';
  uuid: string;
  promptId: string;
}

export type UsageRecord = AssistantUsageRecord | UserPromptRecord;

function optString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

// True when a usage block has no real billable tokens. Such records are
// local/aborted turns, not real API calls — skip them so they don't pollute the
// counts. A real billable turn always has output>0; we
// additionally guard cache so a cache-only record (none observed today across
// 159 transcripts / 17,915 usage records) wouldn't be silently dropped.
function isZeroUsage(usage: TranscriptUsage): boolean {
  const input = typeof usage.input_tokens === 'number' ? usage.input_tokens : 0;
  const output = typeof usage.output_tokens === 'number' ? usage.output_tokens : 0;
  const cacheRead =
    typeof usage.cache_read_input_tokens === 'number' ? usage.cache_read_input_tokens : 0;
  const cacheCreate =
    typeof usage.cache_creation_input_tokens === 'number' ? usage.cache_creation_input_tokens : 0;
  return input + output + cacheRead + cacheCreate === 0;
}

// Parse one transcript file's contents into usage-relevant records. Like
// `parseTranscript`, malformed lines are skipped, never thrown. Yields ONE
// `AssistantUsageRecord` per usage-bearing assistant *message* (collapsed by
// `message.id`, see below) and a `UserPromptRecord` per user record (prompts +
// tool results). Skips `<synthetic>` model records and any record whose `usage`
// is absent or all-zero.
//
// `sinceMs` bounds the reconcile window (default 0 = unbounded): records older than
// it are dropped so the backfill is O(in-window records), not whole history — the
// same window the secret-scan `parseTranscript` uses. A record with a missing /
// unparseable timestamp (NaN) is KEPT (`NaN < sinceMs` is false), matching that path.
export function parseTranscriptUsage(jsonl: string, sinceMs = 0): UsageRecord[] {
  const out: UsageRecord[] = [];
  for (const line of jsonl.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    let rec: unknown;
    try {
      rec = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (!isRecord(rec)) continue;

    // Window bound (shared with parseTranscript): drop records before `sinceMs`.
    if (sinceMs > 0 && Date.parse(optString(rec.timestamp) ?? '') < sinceMs) continue;

    if (rec.type === 'user') {
      const uuid = optString(rec.uuid);
      const promptId = optString(rec.promptId);
      // Both ids are required for the run_key join — a user record missing
      // either can't contribute, so drop it.
      if (uuid === undefined || promptId === undefined) continue;
      out.push({ kind: 'user', uuid, promptId });
      continue;
    }

    if (rec.type !== 'assistant') continue;
    const message = rec.message;
    if (!isRecord(message)) continue;

    const model = optString(message.model);
    // `<synthetic>` is Claude Code's local/aborted-turn marker — not a real API
    // call.
    if (model === undefined || model === '<synthetic>') continue;

    const usage = message.usage;
    if (!isRecord(usage)) continue;
    const usageBag = usage as TranscriptUsage;
    if (isZeroUsage(usageBag)) continue;

    const messageId = optString(message.id);
    const uuid = optString(rec.uuid);
    const occurredAt = optString(rec.timestamp);
    const sessionId = optString(rec.sessionId);
    // message.id is the deterministic llm_call key, uuid is the message-join key,
    // and sessionId keys `llmCallId(sessionId, messageId)`; a record
    // missing any of them can't be addressed, so skip. An
    // empty-string sessionId would mis-key the row and orphan it, so we drop the
    // record rather than default it (0 real records lack sessionId).
    if (
      messageId === undefined ||
      uuid === undefined ||
      occurredAt === undefined ||
      sessionId === undefined
    )
      continue;

    out.push({
      kind: 'assistant',
      sessionId,
      messageId,
      uuid,
      parentUuid: optString(rec.parentUuid),
      model,
      usage: usageBag,
      occurredAt,
      cwd: optString(rec.cwd),
      version: optString(rec.version),
      gitBranch: optString(rec.gitBranch),
      entrypoint: optString(rec.entrypoint),
    });
  }

  // Collapse assistant records that share a `message.id` into one.
  //
  // WHY: `message.id` is NOT unique within a transcript. A single assistant API
  // message is written as multiple records:
  //   - one per content block (thinking / text / tool_use) — all sharing the
  //     same `message.id` + `requestId`, normally carrying IDENTICAL `usage`; and
  //   - in subagent/streaming transcripts, earlier records are streaming partials
  //     whose `output_tokens` is a SMALLER cumulative count (e.g. 1) while the
  //     terminal record carries the FULL count (e.g. 338). Within a group,
  //     input/cache tokens are constant; only `output_tokens` grows, and the
  //     terminal (max-output) record is always last in file order.
  //
  // Downstream the reconciler keys each call by `llmCallId(message.id)` and uses
  // `INSERT OR IGNORE`, so it keeps the FIRST row it sees per `message.id`.
  // Without this collapse that first row is either a duplicate (triple-count of
  // the same turn) or a streaming partial (silent output under-count). Collapsing
  // to the MAX-output record — i.e. the terminal one — is exactly what makes
  // `llmCallId` + INSERT-OR-IGNORE correct.
  //
  // We keep the kept record at its ORIGINAL (later, terminal) file position so
  // ordering relative to user records is preserved: the reconciler walks in order
  // carrying `promptId` forward, so a user record that follows the message must
  // still come after the collapsed assistant record. User records pass through
  // untouched.
  const bestByMessageId = new Map<string, number>(); // messageId → index in `out` of the max-output record
  for (let i = 0; i < out.length; i++) {
    const rec = out[i];
    if (rec?.kind !== 'assistant') continue;
    const prevIdx = bestByMessageId.get(rec.messageId);
    if (prevIdx === undefined) {
      bestByMessageId.set(rec.messageId, i);
      continue;
    }
    const prev = out[prevIdx];
    if (prev?.kind !== 'assistant') continue;
    const prevOut = typeof prev.usage.output_tokens === 'number' ? prev.usage.output_tokens : 0;
    const curOut = typeof rec.usage.output_tokens === 'number' ? rec.usage.output_tokens : 0;
    // `>=` (not `>`) so a tie keeps the later record: content-block duplicates
    // carry identical output, and on a tie we want the terminal (last-in-file)
    // one, which is the record encountered later in this forward walk.
    if (curOut >= prevOut) bestByMessageId.set(rec.messageId, i);
  }

  const kept = new Set(bestByMessageId.values());
  return out.filter((rec, i) => rec.kind === 'user' || kept.has(i));
}

// ───────────────────────────── tool-I/O path ─────────────────────────────
//
// A THIRD independent parse of the same transcripts, for the tool-call reconciler
// (the "deferred tool-I/O pass" the prose parser above defers). Kept fully separate
// from the prose (parseTranscript) and token (parseTranscriptUsage) passes: this one
// keeps only `tool_use` blocks (on assistant records) enriched with their matching
// `tool_result` (on the following user record), and drops everything else. Metadata
// only — tool input/output are MEASURED (sizes) but not captured here; the masked
// content + inspection findings are a later pass on the same rows.

// One tool call pulled from a transcript: the `tool_use` block plus its matching
// `tool_result`. `toolUseId` (`toolu_…`, globally unique per call) is the natural
// key the deterministic id hashes on. Correlation ids mirror the usage record so the
// reconciler attributes a `run_key` (parentUuid → promptId) the same way.
export interface ToolCallRecord {
  sessionId: string;
  toolUseId: string;
  toolName: string;
  uuid: string | undefined;
  parentUuid: string | undefined;
  occurredAt: string; // record's own ISO timestamp
  inputSize: number | undefined;
  isError: boolean | undefined;
  outputSize: number | undefined;
  // The salient input, RAW and UNTRUNCATED — e.g. a WebFetch url or a Bash command.
  // The reconciler masks it and THEN size-caps the masked value (never persisted raw);
  // undefined when the input has no obvious target.
  target: string | undefined;
}

// The single most identifying field of a tool's input — what answers "which
// WebFetch / which Bash / which file". Falls back to a compact JSON of the whole
// input for tools we don't special-case. Returns undefined when nothing useful is
// present. The result is RAW and UNTRUNCATED: the reconciler masks it BEFORE applying
// any size cap, so a secret can never straddle a truncation boundary and leak an
// unmasked prefix (the scanner needs the whole pattern to match). Capping the
// already-masked value is the reconciler's job (`MAX_TARGET_LEN`), not the parser's.
function toolTarget(toolName: string, input: unknown): string | undefined {
  if (!isRecord(input)) return undefined;
  const pick = (key: string): string | undefined => {
    const v = input[key];
    return typeof v === 'string' ? v : undefined;
  };

  let raw: string | undefined;
  switch (toolName) {
    case 'WebFetch':
      raw = pick('url');
      break;
    case 'WebSearch':
      raw = pick('query');
      break;
    case 'Bash':
      raw = pick('command');
      break;
    case 'Read':
    case 'Write':
    case 'Edit':
    case 'MultiEdit':
      raw = pick('file_path');
      break;
    case 'NotebookEdit':
      raw = pick('notebook_path') ?? pick('file_path');
      break;
    case 'Grep':
    case 'Glob':
      raw = pick('pattern');
      break;
    case 'Task':
    case 'Agent':
      raw = pick('description') ?? pick('subagent_type');
      break;
    default: {
      // Unknown tool (incl. MCP): a compact JSON of the whole input so the row still
      // says something about the call.
      try {
        raw = JSON.stringify(input);
      } catch {
        raw = undefined;
      }
    }
  }
  if (raw === undefined || raw === '') return undefined;
  return raw;
}

// Character length of a serialized tool input/output block — a size metric, never
// the payload. Strings measure directly; structured content is JSON-serialized.
// undefined when absent/unserializable so the size stays OUT of the bag rather than
// becoming a misleading 0.
function contentSize(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'string') return value.length;
  try {
    return JSON.stringify(value).length;
  } catch {
    return undefined;
  }
}

// Parse one transcript file's contents into `tool_call` records. Like the sibling
// parsers, malformed lines are skipped, never thrown; `sinceMs` bounds the window. A
// `tool_use` is deduped by its (unique) id keeping the first seen — a streaming/
// content-block repeat carries the same id. Its `tool_result` (a later user record)
// enriches is_error + output size. A tool_use missing sessionId/timestamp can't be
// addressed to a session root → dropped.
export function parseTranscriptToolCalls(jsonl: string, sinceMs = 0): ToolCallRecord[] {
  const uses = new Map<string, ToolCallRecord>();
  const results = new Map<string, { isError: boolean; outputSize: number | undefined }>();

  for (const line of jsonl.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === '') continue;
    let rec: unknown;
    try {
      rec = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (!isRecord(rec)) continue;
    if (sinceMs > 0 && Date.parse(optString(rec.timestamp) ?? '') < sinceMs) continue;

    const message = rec.message;
    if (!isRecord(message) || !Array.isArray(message.content)) continue;

    if (rec.type === 'assistant') {
      const sessionId = optString(rec.sessionId);
      const occurredAt = optString(rec.timestamp);
      if (sessionId === undefined || sessionId === '' || occurredAt === undefined) continue;
      for (const block of message.content) {
        if (!isRecord(block) || block.type !== 'tool_use') continue;
        const toolUseId = optString(block.id);
        const toolName = optString(block.name);
        if (toolUseId === undefined || toolName === undefined) continue;
        if (uses.has(toolUseId)) continue;
        uses.set(toolUseId, {
          sessionId,
          toolUseId,
          toolName,
          uuid: optString(rec.uuid),
          parentUuid: optString(rec.parentUuid),
          occurredAt,
          inputSize: contentSize(block.input),
          isError: undefined,
          outputSize: undefined,
          target: toolTarget(toolName, block.input),
        });
      }
      continue;
    }

    if (rec.type === 'user') {
      for (const block of message.content) {
        if (!isRecord(block) || block.type !== 'tool_result') continue;
        const toolUseId = optString(block.tool_use_id);
        if (toolUseId === undefined) continue;
        results.set(toolUseId, {
          isError: block.is_error === true,
          outputSize: contentSize(block.content),
        });
      }
    }
  }

  const out: ToolCallRecord[] = [];
  for (const record of uses.values()) {
    const result = results.get(record.toolUseId);
    if (result !== undefined) {
      record.isError = result.isError;
      record.outputSize = result.outputSize;
    }
    out.push(record);
  }
  return out;
}

const DAY_MS = 24 * 60 * 60 * 1000;

export interface HistoryWalkOptions {
  dir?: string; // override the transcripts root (tests)
  windowDays?: number; // retention window; default 30
  now?: number; // clock injection (tests); default Date.now()
}

// Shared fail-open file walk: yield each project transcript's full contents exactly
// once (projects → *.jsonl → readFileSync), skipping any unreadable root, project
// dir, or file so one bad file can't abort the sweep. Reads one file at a time to
// bound memory. The record walkers below each layer their own parser on top; the
// time window is applied inside those parsers, not here.
function* iterateFileContents(dir: string): Generator<string> {
  let projects: string[];
  try {
    projects = readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);
  } catch {
    return; // no transcripts dir → nothing to walk
  }

  for (const project of projects) {
    const projectDir = join(dir, project);
    let files: string[];
    try {
      files = readdirSync(projectDir).filter((name) => name.endsWith('.jsonl'));
    } catch {
      continue;
    }
    for (const file of files) {
      let content: string;
      try {
        content = readFileSync(join(projectDir, file), 'utf8');
      } catch {
        continue;
      }
      yield content;
    }
  }
}

// The retention-window lower bound (ms) shared by every walker: records older than
// `windowDays` (default 30) are dropped inside the parser.
function windowStartMs(opts: Pick<HistoryWalkOptions, 'windowDays' | 'now'>): number {
  const windowDays = opts.windowDays ?? 30;
  return (opts.now ?? Date.now()) - windowDays * DAY_MS;
}

// Lazily walk every project's transcripts under the root and yield each
// scannable message from the last `windowDays`. Fully best-effort: an
// unreadable root, project dir, or file is skipped so a single bad file can't
// abort the onboarding scan. Reads one file at a time to bound memory.
export function* iterateHistory(opts: HistoryWalkOptions = {}): Generator<ScannedMessage> {
  const sinceMs = windowStartMs(opts);
  for (const content of iterateFileContents(opts.dir ?? transcriptsDir()))
    yield* parseTranscript(content, sinceMs);
}

// Lazily walk every project's transcripts under the root and yield each
// usage-relevant record (assistant token rows + user prompt/run-key rows) for the
// token reconciler. Same best-effort fail-open walk as `iterateHistory` — an
// unreadable root, project dir, or file is skipped, and one file is read at a time
// to bound memory. Bounded to the retention window (`windowDays`, default 30) just
// like `iterateHistory`: idempotency keeps a re-read safe, but an UNBOUNDED sweep
// would re-parse a heavy user's entire history on every /aka:setup, so the window is
// threaded into the parser rather than left to the caller.
export function* iterateUsage(
  opts: Pick<HistoryWalkOptions, 'dir' | 'windowDays' | 'now'> = {},
): Generator<UsageRecord> {
  const sinceMs = windowStartMs(opts);
  for (const content of iterateFileContents(opts.dir ?? transcriptsDir()))
    yield* parseTranscriptUsage(content, sinceMs);
}

// One walk feeding BOTH the usage and tool-I/O reconcilers: per transcript file, parse
// its usage records and its tool-call records together so `reconcileHistory` reads a
// heavy history from disk once, not twice. Each file's two record sets are yielded as a
// pair; the caller groups each set by session independently.
export function* iterateUsageAndToolCalls(
  opts: Pick<HistoryWalkOptions, 'dir' | 'windowDays' | 'now'> = {},
): Generator<{ usage: UsageRecord[]; toolCalls: ToolCallRecord[] }> {
  const sinceMs = windowStartMs(opts);
  for (const content of iterateFileContents(opts.dir ?? transcriptsDir())) {
    yield {
      usage: parseTranscriptUsage(content, sinceMs),
      toolCalls: parseTranscriptToolCalls(content, sinceMs),
    };
  }
}
