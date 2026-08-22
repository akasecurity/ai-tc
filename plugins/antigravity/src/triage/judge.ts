/**
 * The setup-wizard judge runner (Antigravity `agy` CLI).
 *
 * The FP/severity judgment is the one place the wizard feeds the model RAW
 * hits (rawMatch + surrounding context) — the locked rubric (the shared
 * @akasecurity/setup-wizard asset) requires raw to judge accurately.
 *
 * This host is still the weakest of the three for that, but for one reason now
 * rather than two. The Claude Code and Codex judges each run the model in a mode
 * that persists NO session file (`--ephemeral` on Codex), which is what keeps
 * the raw prompt out of the very store AKA's own backfill scans. Antigravity's
 * CLI documents no such mode, so the run persists and this file removes the
 * conversation after the fact.
 *
 * The prompt itself does NOT ride argv. `agy` documents a streaming stdin
 * input, which is the same shape the other two judges already use:
 *
 *   agy --input-format stream-json --output-format stream-json
 *
 * with one JSON object per line written to stdin,
 *
 *   {"event":"user","message":{"content":"<prompt>"}}
 *
 * and stdin closed to end the session. The two formats are paired on purpose
 * rather than by preference: the host documents that a streaming input paired
 * with a non-streaming output emits its single envelope only as the process
 * exits, so `stream-json` on both sides is the supported combination. The
 * consequence for this file is that the verdict arrives as ONE LINE of NDJSON —
 * the terminal `result` event — rather than as the whole of stdout. See
 * parseEnvelope.
 *
 * One consequence remains, and it is disclosed in the consent copy rather than
 * papered over, because it cannot be engineered away here: the run PERSISTS.
 * `agy` writes the judge conversation — raw hits and all — under
 * ~/.gemini/antigravity/brain/<conversationId>/, the same tree
 * ../history/transcripts.ts sweeps, so a conversation left behind would be
 * re-ingested as fresh findings on the next scan. This file therefore removes
 * that conversation itself, in a finally. Removal is BEST EFFORT: a kill -9
 * between the transcript write and the cleanup leaves it on disk.
 *
 * The verdict is read from the `result` event's `response` field; stderr is
 * captured and discarded, because run logging can echo raw content and must
 * never reach the parent command's stderr, which flows into the wizard
 * conversation.
 *
 * The subprocess inherits the host environment untouched — `agy` must resolve
 * on PATH and its auth must survive.
 */
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { maskText } from '@akasecurity/plugin-sdk';
import { isBareCommandUnsupported, planBareCommand } from '@akasecurity/plugin-sdk/bare-command';
import type { TriageHit, TriageRecommendation } from '@akasecurity/schema';
import { parseRecommendation } from '@akasecurity/setup-wizard';

import { conversationDir, transcriptsDir } from '../history/transcripts.ts';

const TRIAGE_DIR = dirname(fileURLToPath(import.meta.url));
// src/triage/judge.ts -> packages/setup-wizard/assets/triage-rubric.md
const DEFAULT_RUBRIC_PATH = join(
  TRIAGE_DIR,
  '..',
  '..',
  '..',
  '..',
  'packages',
  'setup-wizard',
  'assets',
  'triage-rubric.md',
);

// -------------------------------------------------------------------------
// Pure parse: stdout event stream -> final message -> verdict
// -------------------------------------------------------------------------

// What the terminal `result` event reports. Only two fields are load-bearing
// here: the final assistant message, and the id of the conversation the run
// created (which this module must then delete). Everything else the event
// carries (status, error, num_turns, usage) is ignored rather than modelled.
export interface JudgeEnvelope {
  response: string;
  conversationId?: string | undefined;
}

// A plain JSON object, or undefined for anything else. Array.isArray is
// load-bearing: `typeof [] === 'object'`, so an array would otherwise reach the
// field reads and be reported as a missing `response` rather than as the
// malformed shape it is.
function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

// The `conversation_id` off an event or off its own payload object, or
// undefined when absent or empty. Both placements are read because both appear:
// `init` carries the id at the top level of the event, while `result` and
// `step_update` carry it inside the payload object named after the event.
function conversationIdOf(value: unknown): string | undefined {
  const record = asRecord(value);
  if (record === undefined) return undefined;
  const id = record.conversation_id;
  return typeof id === 'string' && id !== '' ? id : undefined;
}

// Pull the verdict-bearing event out of stdout.
//
// `--output-format stream-json` is NDJSON: one typed event per line — a single
// `init`, then a `step_update` per step, then one terminal `result` per turn.
// So this walks the lines rather than parsing stdout whole, and the verdict is
// `result.response`.
//
// A line that is not JSON is skipped rather than fatal. The verdict rides one
// specific event, and failing the whole stream over a stray line would turn a
// cosmetic upstream change into an unreadable verdict — while a stream that
// carried NO parseable event still fails loud, below.
//
// Never echo stdout in an error: it can carry a raw hit the model failed to
// strip, and these errors propagate to the parent command's stderr, outside the
// judge subprocess. Every failure reports only raw-free metadata, never the
// content.
export function parseEnvelope(stdout: string): JudgeEnvelope {
  if (stdout.trim() === '') {
    throw new Error('agy judge produced no output');
  }

  let sawJson = false;
  let sawObject = false;
  let sawResultEvent = false;
  let initConversationId: string | undefined;
  let resultConversationId: string | undefined;
  let result: Record<string, unknown> | undefined;

  for (const line of stdout.split('\n')) {
    if (line.trim() === '') continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    sawJson = true;
    const event = asRecord(parsed);
    if (event === undefined) continue;
    sawObject = true;

    if (event.event === 'init') {
      initConversationId ??= conversationIdOf(event) ?? conversationIdOf(event.init);
    }
    if (event.event === 'result') {
      sawResultEvent = true;
      // The LAST USABLE result event wins. One turn is written to stdin, so one
      // is expected — but a host that emitted a second must not have the first
      // read as the final word.
      //
      // The id is taken in the SAME branch as the payload, never beside it: a
      // later malformed result event would otherwise clear the id while leaving
      // the earlier event's response in place, and the run would then be cleaned
      // up by the ambiguous directory diff — which leaves a raw-bearing judge
      // conversation on disk whenever it cannot attribute one.
      const payload = asRecord(event.result);
      if (payload !== undefined) {
        result = payload;
        resultConversationId = conversationIdOf(event) ?? conversationIdOf(event.result);
      }
    }
  }

  if (!sawJson) throw new Error('agy judge output was not valid JSON');
  if (!sawObject) throw new Error('agy judge output was not a JSON object');
  if (!sawResultEvent) throw new Error('agy judge output carried no result event');
  if (result === undefined) throw new Error('agy judge result event carried no result object');

  const response = result.response;
  if (typeof response !== 'string') {
    throw new Error('agy judge output carried no response string');
  }
  return {
    response,
    // The result event's own id first, the init event's as the fallback. The
    // fallback is what lets a run whose result event was malformed still be
    // attributed for cleanup rather than dropping to the ambiguous
    // directory-diff path — and a judge conversation left on disk is a raw
    // transcript the next backfill would re-ingest.
    conversationId: resultConversationId ?? initConversationId,
  };
}

// Extract + validate the fenced TriageRecommendation from the model's final
// message via the shared parser. An empty or unparseable message is a hard
// failure, never a silent pass — the caller must not act on a verdict we could
// not read. Raw-free for the same reason as parseEnvelope.
export function parseVerdict(lastMessage: string): TriageRecommendation {
  if (lastMessage.trim() === '') {
    throw new Error('agy judge returned an empty response');
  }
  try {
    return parseRecommendation(lastMessage);
  } catch {
    throw new Error('agy judge returned an unparseable TriageRecommendation');
  }
}

// -------------------------------------------------------------------------
// Subprocess env + spawn
// -------------------------------------------------------------------------

// Env for the judge subprocess: the host environment, inherited untouched.
// `agy` must resolve on PATH and its auth must survive. Unlike the Codex
// judge, no env var or flag suppresses session persistence on this host — the
// conversation is removed after the fact instead (see cleanupConversation).
export function judgeEnv(): NodeJS.ProcessEnv {
  return { ...process.env };
}

// Real subprocess spawn used in production wiring. Kept separate from runJudge
// so unit tests inject a fake and NEVER hit a live model. Returns stdout, which
// carries the NDJSON event stream the verdict is read from. stderr is captured
// (not inherited) because `agy`'s run logging can echo raw content, and
// execFileSync's default would write it straight through to the parent's stderr
// — which flows into the wizard conversation this judge exists to keep raw
// content out of.
//
// The prompt rides `stdin`, exactly as it does in the Claude Code and Codex
// judges. That is what makes this argv fixed flags and nothing else, so it
// crosses cmd.exe intact and a Windows `agy.cmd` shim is reachable like any
// other host's. It also keeps the raw hits out of `ps` and out of any failed
// command line an error message echoes, and off the OS's ARG_MAX entirely.
//
// planBareCommand owns the Windows half. A bare `agy` is invisible to libuv's
// own executable search (which tries `.com` and `.exe` and stops), so a
// shell-free spawn fails with a bare ENOENT wherever the CLI is installed as a
// batch shim; reaching such a shim needs cmd.exe, under a cwd anchored at the
// user's home so a stray `agy.cmd` in the working directory cannot win. When
// `agy` resolves to a real executable the planner skips cmd.exe entirely and
// spawns it by absolute path with no shell.
//
// `timeout` MEANS SOMETHING WEAKER ON THE SHELL PATH, and the difference is not
// cosmetic. Node applies it to the process it started, so where `plan.options`
// carries `shell: true` the process killed at 180s is `cmd.exe` — `agy` is a
// grandchild and survives it. It also still holds the inherited stdout handle,
// so the synchronous read here waits for that pipe to close rather than for the
// kill, and can outlast the timeout it looks bounded by.
//
// Not repaired here, because the repair is to not need the shell: whenever `agy`
// resolves to a real executable the planner spawns it directly and the timeout
// bounds the real process. Written down so the next reader does not assume the
// 180s survives an interpreter it does not.
export function spawnAgy(argv: readonly string[], env: NodeJS.ProcessEnv, stdin: string): string {
  const plan = planBareCommand('agy', argv, { env });
  return execFileSync(plan.file, [...plan.args], {
    env,
    input: stdin,
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 32 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
    ...plan.options,
  });
}

// Raw-free description of a spawn failure. The prompt rides stdin now, so an
// execFileSync error's `.message` (which echoes the command line) no longer
// carries the hits — but its captured `.stdout` and `.stderr` still can, since
// both are the model's own output and `agy`'s run logging echoes prompt content.
// None of that may cross back to the parent command, so we surface ONLY
// non-content metadata (exit status / signal / node error code), never
// `.message`, `.stdout`, or `.stderr`.
function spawnFailureMeta(err: unknown): string {
  // planBareCommand's refusal is the one failure here that carries an
  // explanation worth reading, and it is raw-free by construction — it names an
  // argv index and a character class, never a value. Everything below is exit
  // metadata, which is all any other failure may contribute.
  if (isBareCommandUnsupported(err)) return err.reason;
  const e = err as { status?: number | null; signal?: string | null; code?: string };
  const parts: string[] = [];
  if (typeof e.status === 'number') parts.push(`exit ${String(e.status)}`);
  if (typeof e.signal === 'string' && e.signal) parts.push(`signal ${e.signal}`);
  if (typeof e.code === 'string' && e.code) parts.push(e.code);
  return parts.length > 0 ? parts.join(', ') : 'unknown error';
}

// -------------------------------------------------------------------------
// Judge-conversation cleanup
// -------------------------------------------------------------------------

// The conversation ids present under the brain root right now. An unreadable
// or absent root yields an empty set: the caller only ever uses this to
// SUBTRACT, and an empty "before" makes the fallback ambiguous rather than
// destructive (see cleanupConversation).
export function brainConversationIds(home?: string): ReadonlySet<string> {
  try {
    return new Set(
      readdirSync(transcriptsDir(home), { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name),
    );
  } catch {
    return new Set();
  }
}

// Remove the conversation this judge run created.
//
// Attribution is deliberately conservative, because the cost of the two errors
// is not symmetric: deleting a conversation the USER started is unrecoverable
// data loss, while leaving a judge conversation behind merely re-surfaces the
// user's own already-known secrets on the next scan. So:
//   - if the run reported its conversation_id, remove exactly that one;
//   - otherwise remove a newly-appeared conversation ONLY when there is
//     exactly one, since a second concurrent `agy` session in another terminal
//     makes the diff ambiguous and nothing here can tell the two apart.
// An ambiguous case is left on disk on purpose.
export function cleanupConversation(
  conversationId: string | undefined,
  before: ReadonlySet<string>,
  home?: string,
): void {
  let target = conversationId;
  if (target === undefined) {
    const added = [...brainConversationIds(home)].filter((id) => !before.has(id));
    // Exactly one, or nothing is safe to attribute — and the index read is
    // still narrowed explicitly so an empty array can never reach the remove.
    const only = added.length === 1 ? added[0] : undefined;
    if (only === undefined) return;
    target = only;
  }
  try {
    rmSync(conversationDir(target, home), { recursive: true, force: true });
  } catch {
    // Best effort by contract. A throw here would REPLACE whatever the try
    // block is throwing — the raw-free spawn/parse failure the caller has to
    // act on — with an fs error about a path the user can delete themselves.
  }
}

// -------------------------------------------------------------------------
// runJudge
// -------------------------------------------------------------------------

export interface JudgeDeps {
  // Injected spawn seam: receives the argv AFTER `agy`, the subprocess env, and
  // the prompt (fed on stdin, not argv — see spawnAgy), and returns the child's
  // stdout. Tests inject a fake that returns a canned NDJSON event stream so no
  // real `agy` runs.
  spawn: (argv: readonly string[], env: NodeJS.ProcessEnv, stdin: string) => string;
  // Override the rubric source (defaults to the shared package asset); injectable so
  // tests need not read the real file.
  loadRubric?: () => string;
  // Override the OS home root when locating the brain store for cleanup.
  // Supplied only by tests/harnesses; no production call site passes it.
  home?: string;
}

// The minimized egress projection: what actually crosses to the model. The
// finding's own rawMatch must cross (the rubric judges the value), and the
// context window crosses only after re-masking, so any OTHER detectable secret
// in the window never leaves raw. filePath, valueFingerprint, and keyVersion
// are dropped before egress — a new TriageHit field is not disclosed to the
// model unless this projection and the consent copy are updated together.
// maskText is fail-secure: a masking fault over-redacts, never leaks.
// The spread is load-bearing: it drops the fields from a COPY, never off the
// source hit — the surfaced-secrets writeback still reads filePath off the
// original in-memory hits, so mutating in place here would break that path.
export function toJudgePayload(
  hit: TriageHit,
): Omit<TriageHit, 'filePath' | 'valueFingerprint' | 'keyVersion'> {
  const payload: TriageHit = { ...hit, context: maskText(hit.context) };
  delete payload.filePath;
  delete payload.valueFingerprint;
  delete payload.keyVersion;
  return payload;
}

// Build the judge prompt (rubric + raw hits as JSONL), feed it to `agy` on
// stdin as a streaming `user` event, and return the parsed verdict — then
// delete the conversation the run left behind, whatever the outcome.
export function runJudge(hits: readonly TriageHit[], deps: JudgeDeps): TriageRecommendation {
  // No live-spawn fallback: a caller that forgot the seam must fail as the
  // programming error it is rather than be quietly routed to the real `agy`.
  // First statement in the function, so it throws before the rubric is read
  // and before any hit is projected — no raw is assembled for a call that
  // cannot proceed.
  if (typeof deps.spawn !== 'function') {
    throw new TypeError('runJudge requires deps.spawn — there is no live-spawn fallback');
  }

  const rubric = deps.loadRubric?.() ?? readFileSync(DEFAULT_RUBRIC_PATH, 'utf8');
  const hitsJsonl = hits.map((h) => JSON.stringify(toJudgePayload(h))).join('\n');
  const fullPrompt = `${rubric}\n\n## Hits\n\n\`\`\`\n${hitsJsonl}\n\`\`\`\n`;

  // Fixed flags and nothing else — every raw-bearing byte rides stdin. That is
  // what lets this argv cross cmd.exe intact. The two `stream-json` formats are
  // paired because the host documents that pairing: a streaming input against a
  // non-streaming output emits its one envelope only as the process exits.
  const argv = ['--input-format', 'stream-json', '--output-format', 'stream-json'] as const;

  // One NDJSON `user` event, then EOF. JSON.stringify escapes the prompt's own
  // line breaks into `\n` INSIDE the JSON string, so a multi-line prompt is
  // still exactly one line on the wire — which is what NDJSON requires, and what
  // a Windows command line could never have carried. Closing stdin is what ends
  // the session; execFileSync's `input` closes it after the write.
  const stdin = `${JSON.stringify({ event: 'user', message: { content: fullPrompt } })}\n`;

  // Snapshotted BEFORE the spawn so a run that dies without printing its
  // conversation_id can still be attributed by difference.
  const before = brainConversationIds(deps.home);
  let conversationId: string | undefined;
  try {
    let stdout: string;
    try {
      stdout = deps.spawn(argv, judgeEnv(), stdin);
    } catch (err) {
      // Deliberately NOT chaining `err` as `cause`: the error's captured stdout
      // and stderr carry the model's own output, which can echo raw hits.
      // Attaching it would re-expose exactly what this throw exists to strip.
      // Only raw-free metadata is surfaced.
      // eslint-disable-next-line preserve-caught-error -- caught error carries raw model output; see above
      throw new Error(`agy judge subprocess failed (${spawnFailureMeta(err)})`);
    }
    const envelope = parseEnvelope(stdout);
    conversationId = envelope.conversationId;
    return parseVerdict(envelope.response);
  } finally {
    cleanupConversation(conversationId, before, deps.home);
  }
}
