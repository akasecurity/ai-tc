// Antigravity CLI transcript adapter: turn the host's per-conversation JSONL
// transcripts under `~/.gemini/antigravity/brain/<conversationId>/
// .system_generated/logs/` into the text-bearing messages worth scanning for
// already-leaked secrets. This is the ONE place that knows the Antigravity
// record shape; the scan orchestrator (./scan.ts) stays format-agnostic and
// reuses the SDK detect→record path — mirrors
// plugins/claude-code/src/history/transcripts.ts, which plays the same role
// for `~/.claude/projects/*/*.jsonl`.
//
// The message parser and the directory layout below are pinned against a real
// Antigravity transcript. A record is a FLAT object — there is no `payload`
// envelope and no `role` field, so none of the Codex CLI rollout tags
// (`session_meta` / `response_item` / `event_msg`) appear on this host:
//
//   { source:     'MODEL' | 'SYSTEM' | 'USER_EXPLICIT'   // the actor
//     type:       'PLANNER_RESPONSE' | 'USER_INPUT' | 'RUN_COMMAND' | …
//     created_at: ISO-8601 with a 'Z' suffix
//     status:     'DONE' | 'RUNNING'
//     step_index: number
//     content?:   string          // absent on tool-only and checkpoint records
//     thinking?:  string          // model reasoning; the ONLY text on some records
//     tool_calls?: { name, args }[]
//     exit_code?: number
//     truncated_fields?: string[] } // names the fields this file cut short
//
// What this file does NOT yet cover, and why, so a reader does not mistake
// silence for coverage:
//
//   - USAGE. The sample carries no token, model or cost field anywhere at any
//     depth, so `parseTranscriptUsage` below — still shaped for Codex's
//     `event_msg`/`token_count` lines — matches nothing here and yields no
//     rows. Whether this host records usage elsewhere is unverified.
//   - TOOL I/O. Tool calls ride INLINE on a record as `{name, args}` with no
//     call id and no begin/end pair, so `parseTranscriptToolCalls`'s
//     `exec_command_begin`/`exec_command_end` correlation matches nothing here
//     either.
//   - TOOL ARGUMENTS as scan input. `run_command` carries `CommandLine` and
//     `write_to_file` carries `CodeContent`; a secret pasted into either is
//     therefore NOT seen by the historical secret scan, which reads only the
//     message text below. Live PreToolUse capture does see tool input.
//
// All three under-report rather than mis-report, which is the intended
// direction, but none of them is a gap that reads as covered from the call
// site.
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

// Where the Antigravity CLI writes its per-conversation transcripts:
//   ~/.gemini/antigravity/brain/<conversationId>/.system_generated/logs/*.jsonl
// The directory is `antigravity`, NOT `antigravity-cli` — the sibling
// `~/.gemini/antigravity-ide` is the editor's own store and is not swept here.
// The walk below sweeps the `brain` root recursively, so it reaches the
// `.system_generated/logs` leaf without hardcoding that tail. Antigravity honors a
// GEMINI_HOME override, but this reader intentionally does not — matches
// plugins/claude-code/src/history/transcripts.ts's transcriptsDir(), which
// likewise reads no env override for ~/.claude (n/no-process-env stays on for
// this package; GEMINI_HOME support can be added later behind its own
// file-scoped opt-out if it turns out to be needed). `home` overrides the OS
// home root; it is supplied only by tests/harnesses that need a throwaway
// home in isolation — no production call site passes it, so every real run
// falls back to the OS home.
export function transcriptsDir(home?: string): string {
  return join(home ?? homedir(), '.gemini', 'antigravity', 'brain');
}

// One conversation's subtree under the brain root. The judge uses this to
// remove the conversation its own run created: this host documents no
// ephemeral/no-persist mode, so a judge run — whose prompt carries every raw
// hit — lands in the same store this file's walk scans, and would be
// re-ingested as fresh findings on the next sweep if it were left in place.
export function conversationDir(conversationId: string, home?: string): string {
  return join(transcriptsDir(home), conversationId);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function optString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

// The text-bearing fields of one record, joined. `content` is the visible turn
// text; `thinking` is model reasoning and is kept rather than dropped because
// it is the ONLY text on some records (a tool-call record carries `thinking` +
// `tool_calls` and no `content` at all), so skipping it would drop those
// records from the scan entirely. Claude Code's parser drops its own `thinking`
// blocks, but there they sit inside an assistant message whose text is already
// captured — here there is no such sibling.
//
// `tool_calls[].args` is deliberately NOT joined in: see the tool-arguments
// note in the file header.
function extractRecordText(rec: Record<string, unknown>): string {
  const parts: string[] = [];
  const content = optString(rec.content);
  if (content !== undefined && content !== '') parts.push(content);
  const thinking = optString(rec.thinking);
  if (thinking !== undefined && thinking !== '') parts.push(thinking);
  return parts.join('\n');
}

// Actor → the kind a finding is recorded under. `SYSTEM` is the host's own
// injected text (never something the user or the model authored), so it is
// dropped rather than mapped; an unrecognised source is dropped for the same
// reason, which is what keeps a future actor from silently landing as a
// 'response'.
function kindForSource(source: string | undefined): EventKind | undefined {
  if (source === 'USER_EXPLICIT') return 'prompt';
  if (source === 'MODEL') return 'response';
  return undefined;
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
    const kind = kindForSource(optString(rec.source));
    if (kind === undefined) continue;
    const occurredAt = optString(rec.created_at) ?? '';
    if (occurredAt === '') continue;
    const occurredMs = Date.parse(occurredAt);
    if (Number.isNaN(occurredMs)) continue;
    if (sinceMs > 0 && occurredMs < sinceMs) continue;
    // Setup-start upper bound: drop anything at/after the cutoff so a re-run
    // backfill never re-scans post-install messages — the wizard's own masked
    // output among them. Default Infinity keeps normal scans unbounded.
    if (occurredMs >= beforeMs) continue;

    const text = extractRecordText(rec);
    if (text.trim() === '') continue;
    out.push({ kind, text, occurredAt, filePath });
  }
  return out;
}

// ───────────────────────────── usage (token) path ─────────────────────────────
//
// A SECOND, independent parse of the same files, for the token-usage
// reconciler.
//
// NOT PORTED, AND CURRENTLY INERT ON THIS HOST. Everything below decodes the
// Codex CLI's `event_msg`/`token_count` lines and is what this package was
// templated from. A real Antigravity transcript carries no token, model or cost
// field at any depth, so every line here fails the `rec.type !== 'event_msg'`
// test and the parse yields nothing — no rows, rather than wrong rows.
//
// It is kept rather than deleted because the reconciler around it is wired and
// tested, and an empty parse is the correct behaviour until there is a verified
// usage source to decode. Whether this host records usage anywhere — a sibling
// file, a separate store, or not at all — is unverified; the one sample this
// was checked against had none. Do not read the field names below as evidence
// about Antigravity: they describe Codex.

// The usage bag this parser surfaces, shaped to match the fields
// `buildAttributes` in usage.ts already knows how to promote (input_tokens /
// output_tokens / cache_read_input_tokens / …) — Antigravity's `cached_input_tokens`
// is the closest analog to Claude's `cache_read_input_tokens` (Antigravity does not
// distinguish cache creation from cache read), and `reasoning_output_tokens`
// rides the bag as an extra field (already included in `output_tokens`
// per Antigravity's own TokenUsage — kept here anyway so the raw fact isn't lost).
export interface TranscriptUsage {
  input_tokens?: number;
  output_tokens?: number;
  cache_read_input_tokens?: number;
  reasoning_output_tokens?: number;
  [key: string]: unknown;
}

// One `event_msg`/`token_count` = one usage-bearing unit. `runKey` is the
// nearest preceding turn_id (from a `turn_context` line or the event's own
// `turn_id`, when Antigravity includes one on this event type — currently it does
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
  // Which client wrote the file, from the Codex `session_meta.originator` field
  // this parser was templated against. Antigravity writes no such field, so
  // this rides as `undefined` on every record produced here today. It stays on
  // the shape because usage.ts's reconcileSession promotes it to a descriptive
  // harnessInterface fact when one is present.
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
// Antigravity writes these as separate lines rather than duplicating them onto every
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
// A THIRD independent parse of the same files, for the tool-call reconciler.
//
// NOT PORTED, AND CURRENTLY INERT ON THIS HOST, for the same reason as the
// usage parser above: it correlates Codex's `exec_command_begin`/`_end` and
// `patch_apply_begin`/`_end` event PAIRS by `call_id`. Antigravity has no such
// pairs — a tool call rides inline on a single record as
// `tool_calls: [{ name, args }]`, carries no call id, and reports completion
// through that record's own `status` and `exit_code`. Observed names are
// `view_file`, `run_command`, `list_dir`, `grep_search`, `write_to_file` and
// `manage_task`; none of them is `apply_patch`, which is a Codex tool.
//
// So every line here fails the `payload` test and the parse yields nothing.
// Porting it is a separate change from the message parser: `ToolCallRecord`
// requires a `toolUseId`, and this host supplies no id to use as one.
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

// Recursively collect transcript file paths under the brain root
// (`<brain>/<conversationId>/.system_generated/logs/*.jsonl`), unlike Claude
// Code's flat two-level `projects/<project>/*.jsonl` layout. The recursion is
// what keeps the `.system_generated/logs` tail out of the path helper, so a
// layout change one level deep does not need a code change here. Only plain
// `.jsonl` files are read; any compressed or rotated archive format this host
// may use is skipped rather than guessed at, so the sweep under-covers
// archived conversations. Live hook capture is unaffected.
// A conversation's log dir holds the same transcript TWICE: `transcript.jsonl`
// caps each `content` at ~4KB and names what it cut in `truncated_fields`,
// while `transcript_full.jsonl` carries the untruncated text. Reading both
// would scan every message twice and report each finding twice; reading only
// the short one would silently miss whatever the cap removed — on the sample
// this was measured against, the worst record kept 4116 of 10004 bytes. So the
// full file wins and its truncated sibling is skipped, per directory: the pair
// is decided among the entries of ONE directory, never across the walk, so a
// conversation that has only the short file is still read.
const TRUNCATED_TRANSCRIPT = 'transcript.jsonl';
const FULL_TRANSCRIPT = 'transcript_full.jsonl';

function* walkJsonlFiles(dir: string, depth = 0): Generator<string> {
  if (depth > 6) return; // guard against a pathological symlink loop
  let entries: Dirent[];
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  const hasFull = entries.some((e) => e.isFile() && e.name === FULL_TRANSCRIPT);
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      yield* walkJsonlFiles(full, depth + 1);
    } else if (entry.isFile() && entry.name.endsWith('.jsonl')) {
      if (hasFull && entry.name === TRUNCATED_TRANSCRIPT) continue;
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
