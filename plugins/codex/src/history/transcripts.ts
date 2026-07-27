// Codex CLI transcript adapter: turn the host's `~/.codex/sessions/YYYY/MM/DD/
// rollout-*.jsonl` session logs into the text-bearing messages worth scanning
// for already-leaked secrets. This is the ONE place that knows the Codex
// rollout line shape; the scan orchestrator (./scan.ts) stays format-agnostic
// and reuses the SDK detect→record path — mirrors
// plugins/claude-code/src/history/transcripts.ts, which plays the same role
// for `~/.claude/projects/*/*.jsonl`.
//
// Field names below are taken from openai/codex's own wire types
// (codex-rs/protocol/src/protocol.rs — RolloutLine/RolloutItem/EventMsg;
// codex-rs/protocol/src/models.rs — ResponseItem/ContentItem), read directly
// from the `openai/codex` repo (main branch) rather than guessed. Still worth
// spot-checking against a live `codex` session before relying on this in
// production — Codex's rollout schema is actively evolving (see the repo's own
// "compatibility-only field" comments).
//
// Every rollout line has the shape:
//   { "timestamp": "<ISO8601>", "ordinal"?: number, "type": "<tag>", "payload": {...} }
// (`RolloutLine` flattens `RolloutItem`'s internally-tagged
// `{type, payload}` onto itself.) We only care about three tags:
//   - "session_meta"  → SessionMetaLine (session id, cwd, cli_version, once per file)
//   - "response_item" → ResponseItem (message / function_call / tool output / …)
//   - "event_msg"     → EventMsg (token_count, exec_command_begin/end, patch_apply_begin/end, …)
import type { Dirent } from 'node:fs';
import { closeSync, openSync, readdirSync, readFileSync, readSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { EventKind } from '@akasecurity/schema';

// One scannable unit pulled from a transcript. `occurredAt` is the record's own
// ISO timestamp so a recorded finding lands on the timeline when it really
// leaked, not at scan time. `filePath` is the rollout file this text came from
// ('' when parsed from an in-memory string), carried through so a surfaced
// finding can later be located and struck in place.
export interface ScannedMessage {
  kind: EventKind; // 'prompt' (a user turn) | 'response' (an assistant reply)
  text: string;
  occurredAt: string;
  filePath: string;
}

// Where Codex CLI writes its rollout files. Codex itself honors a CODEX_HOME
// override, but this reader intentionally does not — matches
// plugins/claude-code/src/history/transcripts.ts's transcriptsDir(), which
// likewise reads no env override for ~/.claude (n/no-process-env stays on for
// this package; CODEX_HOME support can be added later behind its own
// file-scoped opt-out if it turns out to be needed).
export function transcriptsDir(): string {
  return join(homedir(), '.codex', 'sessions');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function optString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

// A `message` ResponseItem's `content` is an array of ContentItem: `input_text`
// / `output_text` (both carry `text`) or `input_image` (carries `image_url`,
// never text). We keep only the text-bearing kinds — mirrors Claude Code's
// parser dropping `thinking`/`tool_use`/`image` blocks.
function extractContentText(content: unknown): string {
  if (!Array.isArray(content)) return '';
  const parts: string[] = [];
  for (const block of content) {
    if (!isRecord(block)) continue;
    if (block.type === 'input_text' || block.type === 'output_text') {
      const text = optString(block.text);
      if (text) parts.push(text);
    }
  }
  return parts.join('\n');
}

// Parse one rollout file's contents (newline-delimited JSON) for prompt/response
// text. `sinceMs` drops records older than the retention window; `beforeMs`
// (when set) is an UPPER bound that drops records at/after it — the setup-start
// cutoff, so the wizard's own (masked) output, written during onboarding, is
// never fed back into the scan. Malformed lines are skipped, never thrown — a
// truncated/partial rollout must not abort the scan.
export function parseTranscript(
  jsonl: string,
  sinceMs = 0,
  beforeMs = Infinity,
  filePath = '',
): ScannedMessage[] {
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
    if (rec.type !== 'response_item') continue;
    const occurredAt = optString(rec.timestamp) ?? '';
    if (occurredAt === '') continue;
    const occurredMs = Date.parse(occurredAt);
    if (Number.isNaN(occurredMs)) continue;
    if (sinceMs > 0 && occurredMs < sinceMs) continue;
    // Setup-start upper bound: drop anything at/after the cutoff so a re-run
    // backfill never re-scans post-install messages — the wizard's own masked
    // output among them. Default Infinity keeps normal scans unbounded.
    if (occurredMs >= beforeMs) continue;

    const payload = rec.payload;
    if (!isRecord(payload) || payload.type !== 'message') continue;
    const role = optString(payload.role);
    if (role !== 'user' && role !== 'assistant') continue;
    const text = extractContentText(payload.content);
    if (text.trim() === '') continue;
    out.push({ kind: role === 'user' ? 'prompt' : 'response', text, occurredAt, filePath });
  }
  return out;
}

// ───────────────────────────── usage (token) path ─────────────────────────────
//
// A SECOND, independent parse of the same rollout files, for the token-usage
// reconciler. Codex reports usage per-turn via `event_msg`/`token_count`
// (EventMsg::TokenCount → TokenCountEvent{ info: TokenUsageInfo, rate_limits }),
// NOT per-assistant-message like Claude Code — there is no per-record
// message.usage block to read. `TokenUsageInfo.last_token_usage` is the delta
// since the PRIOR TokenCountEvent, so one TokenCountEvent already IS one
// usage-bearing unit — no streaming-partial collapse needed (unlike Claude
// Code's message.id collapse, which exists because Anthropic streams multiple
// content-block records per API call).
//
// Codex also has no Claude-style linear uuid/parentUuid chain; `turn_id` is
// the natural run_key equivalent, carried directly on most events.

// The usage bag this parser surfaces, shaped to match the fields
// `buildAttributes` in usage.ts already knows how to promote (input_tokens /
// output_tokens / cache_read_input_tokens / …) — Codex's `cached_input_tokens`
// is the closest analog to Claude's `cache_read_input_tokens` (Codex does not
// distinguish cache creation from cache read), and `reasoning_output_tokens`
// rides the bag as an extra field (already included in `output_tokens`
// per Codex's own TokenUsage — kept here anyway so the raw fact isn't lost).
export interface TranscriptUsage {
  input_tokens?: number;
  output_tokens?: number;
  cache_read_input_tokens?: number;
  reasoning_output_tokens?: number;
  [key: string]: unknown;
}

// One `event_msg`/`token_count` = one usage-bearing unit. `runKey` is the
// nearest preceding turn_id (from a `turn_context` line or the event's own
// `turn_id`, when Codex includes one on this event type — currently it does
// not, so this is sourced from the most recent `turn_context` line seen in
// file order, best-effort).
export interface UsageEventRecord {
  kind: 'usage';
  sessionId: string;
  // Synthetic key: TokenCountEvent carries no id of its own, so the key is
  // (sessionId, occurredAt, ordinal-among-same-timestamp-records). Keying on
  // the timestamp — not a per-parse ordinal — is what makes the key stable
  // across parses that see different windows of the same file: the
  // incremental tail path re-parses only the newly-appended chunk, and a
  // per-parse ordinal would restart at 1 there, colliding every later turn's
  // usage with the first turn's row. See parseTranscriptUsage.
  eventKey: string;
  model: string | undefined;
  runKey: string | undefined;
  usage: TranscriptUsage;
  occurredAt: string;
  cwd: string | undefined;
  version: string | undefined; // cli_version, from session_meta
  // Which client wrote this rollout — session_meta.originator, e.g.
  // 'codex_cli_rs' (terminal), 'codex-tui', 'codex_exec' (non-interactive),
  // 'codex_desktop' (the Codex mode inside the ChatGPT desktop app), or
  // 'codex_vscode'. Same engine, same hooks/plugin system regardless of
  // originator — this rides as a descriptive harnessInterface fact (see
  // usage.ts's reconcileSession) so the dashboard can tell them apart
  // without forking the harness/sourceTool dimension. See
  // codex-rs/otel/src/metrics/tags.rs's KNOWN_ORIGINATOR_TAG_VALUES in
  // openai/codex for the full known set.
  originator: string | undefined;
}

export type UsageRecord = UsageEventRecord;

function isZeroUsage(usage: TranscriptUsage): boolean {
  const input = typeof usage.input_tokens === 'number' ? usage.input_tokens : 0;
  const output = typeof usage.output_tokens === 'number' ? usage.output_tokens : 0;
  const cacheRead =
    typeof usage.cache_read_input_tokens === 'number' ? usage.cache_read_input_tokens : 0;
  return input + output + cacheRead === 0;
}

// Parse one rollout file's contents into usage-relevant records. Threads a
// running "current session/turn context" forward as it walks the file in
// order (session_meta → sessionId/cwd/cli_version; turn_context → runKey/model),
// so each token_count event is stamped with the context active at that point —
// Codex writes these as separate lines rather than duplicating them onto every
// event the way Claude Code's transcript does. `sinceMs` bounds the window like
// the sibling parser; a record with a missing/unparseable timestamp is KEPT
// (matches parseTranscript's "malformed timestamp still recorded" tolerance
// being the exception, not the rule — here we simply skip it, since without a
// timestamp there is no way to bound OR display it).
//
// `knownSessionId` seeds the running session id (still overridden by an
// in-chunk `session_meta` line, if one is present). This matters for the
// INCREMENTAL tail path (reconcileSessionTail): `session_meta` is a one-time
// header written ONCE per rollout file, so any tail chunk read after the
// offset has advanced past it contains no session_meta line at all — without
// a seed, every usage/tool-call record in that chunk would be unattributable
// and silently dropped. The whole-file backfill path doesn't need the seed
// (session_meta is always the first line of a fresh parse), but passing it
// there is harmless.
export function parseTranscriptUsage(
  jsonl: string,
  sinceMs = 0,
  knownSessionId?: string,
): UsageRecord[] {
  const out: UsageRecord[] = [];
  let sessionId: string | undefined = knownSessionId;
  let cwd: string | undefined;
  let version: string | undefined;
  let originator: string | undefined;
  let runKey: string | undefined;
  let model: string | undefined;
  // Disambiguates multiple token_count records sharing one timestamp. Ticked
  // for EVERY timestamped token_count line — including ones the sinceMs /
  // zero-usage / malformed-payload filters drop below — so a record's number
  // depends only on its position in the file, never on which filters applied
  // to its neighbours in a given parse.
  const perTimestamp = new Map<string, number>();

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
    const payload = rec.payload;
    if (!isRecord(payload)) continue;

    if (rec.type === 'session_meta') {
      sessionId = optString(payload.session_id) ?? optString(payload.id);
      cwd = optString(payload.cwd);
      version = optString(payload.cli_version);
      originator = optString(payload.originator);
      continue;
    }
    if (rec.type === 'turn_context') {
      // A turn_context line without a turn_id still marks a turn boundary.
      // Falling back to the line's own timestamp keeps per-turn grouping
      // stable across re-parses of the same file, and deliberately does NOT
      // carry the previous turn's key forward (each turn_context resets it).
      const turnTs = optString(rec.timestamp);
      runKey = optString(payload.turn_id) ?? (turnTs !== undefined ? `turn-${turnTs}` : undefined);
      model = optString(payload.model) ?? model;
      const turnCwd = optString(payload.cwd);
      if (turnCwd) cwd = turnCwd;
      continue;
    }
    if (rec.type !== 'event_msg' || payload.type !== 'token_count') continue;

    const occurredAt = optString(rec.timestamp);
    if (occurredAt === undefined) continue;
    const ordinal = (perTimestamp.get(occurredAt) ?? 0) + 1;
    perTimestamp.set(occurredAt, ordinal);
    const occurredMs = Date.parse(occurredAt);
    if (!Number.isNaN(occurredMs) && sinceMs > 0 && occurredMs < sinceMs) continue;
    if (sessionId === undefined) continue; // no session_meta seen yet — can't attribute

    const info = payload.info;
    if (!isRecord(info)) continue;
    const last = info.last_token_usage;
    if (!isRecord(last)) continue;
    const usage: TranscriptUsage = {};
    if (typeof last.input_tokens === 'number') usage.input_tokens = last.input_tokens;
    if (typeof last.output_tokens === 'number') usage.output_tokens = last.output_tokens;
    if (typeof last.cached_input_tokens === 'number') {
      usage.cache_read_input_tokens = last.cached_input_tokens;
    }
    if (typeof last.reasoning_output_tokens === 'number') {
      usage.reasoning_output_tokens = last.reasoning_output_tokens;
    }
    if (isZeroUsage(usage)) continue;

    out.push({
      kind: 'usage',
      sessionId,
      eventKey: `${sessionId}:${occurredAt}:${String(ordinal)}`,
      model,
      runKey,
      usage,
      occurredAt,
      cwd,
      version,
      originator,
    });
  }
  return out;
}

// Cheap, best-effort peek at a rollout file's `session_meta.originator` — the
// live SessionStart hook needs this without paying for a full-file parse (the
// backfill/tail parsers above already extract it, but they're not meant to be
// called on a still-growing, possibly-multi-MB file from the hot hook path).
// Reads only the first ~4KB (session_meta is always the first line and is
// small) and gives up silently on anything else — a missing/unreadable/
// oversized-first-line file just means the interface fact is omitted, never a
// thrown error on the SessionStart path.
const SESSION_META_PEEK_BYTES = 4096;

export function peekSessionOriginator(transcriptPath: string): string | undefined {
  let head: string;
  try {
    const fd = openSync(transcriptPath, 'r');
    try {
      const buf = Buffer.allocUnsafe(SESSION_META_PEEK_BYTES);
      const bytesRead = readSync(fd, buf, 0, SESSION_META_PEEK_BYTES, 0);
      head = buf.subarray(0, bytesRead).toString('utf8');
    } finally {
      closeSync(fd);
    }
  } catch {
    return undefined;
  }
  const firstLine = head.split('\n')[0]?.trim();
  if (!firstLine) return undefined;
  let rec: unknown;
  try {
    rec = JSON.parse(firstLine);
  } catch {
    return undefined; // the line was cut off mid-JSON by the byte cap — give up
  }
  if (!isRecord(rec) || rec.type !== 'session_meta') return undefined;
  const payload = rec.payload;
  if (!isRecord(payload)) return undefined;
  return optString(payload.originator);
}

// ───────────────────────────── tool-I/O path ─────────────────────────────
//
// A THIRD independent parse of the same rollout files, for the tool-call
// reconciler. Codex's PreToolUse/PostToolUse HOOKS only reliably fire for
// `Bash`-equivalent (shell) calls today (see plugins/codex/hooks/hooks.json
// and the upstream issue it cites — apply_patch calls don't fire hooks yet),
// so this backfill-time parse of `exec_command_begin`/`exec_command_end` and
// `patch_apply_begin`/`patch_apply_end` event pairs is currently the ONLY way
// AKA observes a Codex file-write's content at all, live enforcement aside.
export interface ToolCallRecord {
  sessionId: string;
  toolUseId: string; // call_id
  toolName: string; // 'shell' | 'apply_patch'
  runKey: string | undefined; // turn_id
  occurredAt: string;
  inputSize: number | undefined;
  isError: boolean | undefined;
  outputSize: number | undefined;
  target: string | undefined; // the command line / changed paths, RAW and UNTRUNCATED
}

function contentSize(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'string') return value.length;
  try {
    return JSON.stringify(value).length;
  } catch {
    return undefined;
  }
}

// `knownSessionId` — see the identical parameter on parseTranscriptUsage
// above; the same one-time-header problem applies to tool-call attribution
// on the incremental tail path.
export function parseTranscriptToolCalls(
  jsonl: string,
  sinceMs = 0,
  knownSessionId?: string,
): ToolCallRecord[] {
  const sessionIdBySessionMeta = { current: knownSessionId };
  // Running turn key from the most recent turn_context line, mirroring the
  // usage parser: exec/patch events carry no turn_id of their own on current
  // rollouts, so without this fallback tool calls would never group by turn.
  let runKey: string | undefined;
  const begins = new Map<
    string,
    { toolName: string; runKey: string | undefined; occurredAt: string; target: string | undefined }
  >();
  const out: ToolCallRecord[] = [];

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
    const payload = rec.payload;
    if (!isRecord(payload)) continue;

    if (rec.type === 'session_meta') {
      sessionIdBySessionMeta.current = optString(payload.session_id) ?? optString(payload.id);
      continue;
    }
    if (rec.type === 'turn_context') {
      // Same reset-per-turn rule (and timestamp fallback) as the usage parser.
      const turnTs = optString(rec.timestamp);
      runKey = optString(payload.turn_id) ?? (turnTs !== undefined ? `turn-${turnTs}` : undefined);
      continue;
    }
    if (rec.type !== 'event_msg') continue;
    const occurredAt = optString(rec.timestamp);
    if (occurredAt === undefined) continue;
    const occurredMs = Date.parse(occurredAt);
    if (!Number.isNaN(occurredMs) && sinceMs > 0 && occurredMs < sinceMs) continue;

    if (payload.type === 'exec_command_begin') {
      const callId = optString(payload.call_id);
      if (callId === undefined) continue;
      const command = Array.isArray(payload.command)
        ? payload.command.filter((c): c is string => typeof c === 'string').join(' ')
        : undefined;
      begins.set(callId, {
        toolName: 'shell',
        runKey: optString(payload.turn_id) ?? runKey,
        occurredAt,
        target: command,
      });
      continue;
    }
    if (payload.type === 'exec_command_end') {
      const callId = optString(payload.call_id);
      if (callId === undefined || sessionIdBySessionMeta.current === undefined) continue;
      const begin = begins.get(callId);
      const exitCode = payload.exit_code;
      out.push({
        sessionId: sessionIdBySessionMeta.current,
        toolUseId: callId,
        toolName: 'shell',
        runKey: begin?.runKey ?? optString(payload.turn_id) ?? runKey,
        occurredAt: begin?.occurredAt ?? occurredAt,
        inputSize: begin?.target !== undefined ? begin.target.length : undefined,
        isError: typeof exitCode === 'number' ? exitCode !== 0 : undefined,
        outputSize: contentSize(payload.aggregated_output ?? payload.formatted_output),
        target: begin?.target,
      });
      continue;
    }
    if (payload.type === 'patch_apply_begin') {
      const callId = optString(payload.call_id);
      if (callId === undefined) continue;
      const changes = isRecord(payload.changes) ? Object.keys(payload.changes) : [];
      begins.set(callId, {
        toolName: 'apply_patch',
        runKey: optString(payload.turn_id) ?? runKey,
        occurredAt,
        target: changes.length > 0 ? changes.join(', ') : undefined,
      });
      continue;
    }
    if (payload.type === 'patch_apply_end') {
      const callId = optString(payload.call_id);
      if (callId === undefined || sessionIdBySessionMeta.current === undefined) continue;
      const begin = begins.get(callId);
      out.push({
        sessionId: sessionIdBySessionMeta.current,
        toolUseId: callId,
        toolName: 'apply_patch',
        runKey: begin?.runKey ?? optString(payload.turn_id) ?? runKey,
        occurredAt: begin?.occurredAt ?? occurredAt,
        inputSize: begin?.target !== undefined ? begin.target.length : undefined,
        isError: typeof payload.success === 'boolean' ? !payload.success : undefined,
        outputSize: contentSize(payload.stdout ?? payload.stderr),
        target: begin?.target,
      });
    }
  }
  return out;
}

// ───────────────────────────── directory walk ─────────────────────────────

const DAY_MS = 24 * 60 * 60 * 1000;

export interface HistoryWalkOptions {
  dir?: string; // override the transcripts root (tests)
  windowDays?: number; // retention window; default 30
  now?: number; // clock injection (tests); default Date.now()
  // Self-contamination guard (secret-scan path only). OFF by default, so a
  // normal user's full pre-install history is still scanned; it engages only
  // for AKA's OWN setup session.
  beforeMs?: number; // setup-start upper bound: drop messages at/after this ms
}

// Recursively collect rollout file paths under the year/month/day-sharded
// sessions root (`~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`), unlike
// Claude Code's flat two-level `projects/<project>/*.jsonl` layout. Only
// plain `.jsonl` files are read — `.jsonl.zst` (Codex's compressed archive
// format for inactive sessions) is intentionally skipped for now rather than
// guessed at: decompressing it needs a zstd dependency this self-contained
// hook bundle doesn't carry. This means the backfill sweep under-covers
// long-archived sessions; live hook capture is unaffected.
function* walkJsonlFiles(dir: string, depth = 0): Generator<string> {
  if (depth > 6) return; // guard against a pathological symlink loop
  let entries: Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkJsonlFiles(full, depth + 1);
    } else if (entry.isFile() && entry.name.endsWith('.jsonl')) {
      yield full;
    }
  }
}

function* iterateFileContents(dir: string): Generator<{ content: string; filePath: string }> {
  for (const filePath of walkJsonlFiles(dir)) {
    try {
      // Skip anything the walk can't stat (broken symlink) before the read.
      statSync(filePath);
      yield { content: readFileSync(filePath, 'utf8'), filePath };
    } catch {
      // Unreadable file — skip, same fail-open contract as the rest of the walk.
    }
  }
}

function windowStartMs(opts: Pick<HistoryWalkOptions, 'windowDays' | 'now'>): number {
  const windowDays = opts.windowDays ?? 30;
  return (opts.now ?? Date.now()) - windowDays * DAY_MS;
}

export function* iterateHistory(opts: HistoryWalkOptions = {}): Generator<ScannedMessage> {
  const sinceMs = windowStartMs(opts);
  const beforeMs = opts.beforeMs ?? Infinity;
  for (const { content, filePath } of iterateFileContents(opts.dir ?? transcriptsDir()))
    yield* parseTranscript(content, sinceMs, beforeMs, filePath);
}

export function* iterateUsage(
  opts: Pick<HistoryWalkOptions, 'dir' | 'windowDays' | 'now'> = {},
): Generator<UsageRecord> {
  const sinceMs = windowStartMs(opts);
  for (const { content } of iterateFileContents(opts.dir ?? transcriptsDir()))
    yield* parseTranscriptUsage(content, sinceMs);
}

export function* iterateUsageAndToolCalls(
  opts: Pick<HistoryWalkOptions, 'dir' | 'windowDays' | 'now'> = {},
): Generator<{ usage: UsageRecord[]; toolCalls: ToolCallRecord[] }> {
  const sinceMs = windowStartMs(opts);
  for (const { content } of iterateFileContents(opts.dir ?? transcriptsDir())) {
    yield {
      usage: parseTranscriptUsage(content, sinceMs),
      toolCalls: parseTranscriptToolCalls(content, sinceMs),
    };
  }
}
