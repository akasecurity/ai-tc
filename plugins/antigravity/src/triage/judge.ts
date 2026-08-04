/**
 * The setup-wizard judge runner (Antigravity `agy` CLI).
 *
 * The FP/severity judgment is the one place the wizard feeds the model RAW
 * hits (rawMatch + surrounding context) — the locked rubric (the shared
 * @akasecurity/setup-wizard asset) requires raw to judge accurately.
 *
 * This host is the weakest of the three for that, and the difference is not
 * cosmetic. The Claude Code and Codex judges each run the model in a mode that
 * persists NO session file (`--ephemeral` on Codex), which is what keeps the
 * raw prompt out of the very store AKA's own backfill scans. Antigravity's CLI
 * documents no such mode, and its headless entrypoint takes the prompt in
 * ARGV rather than on stdin:
 *
 *   agy -p "<prompt>" --output-format json
 *
 * Two consequences follow. Both are disclosed in the consent copy rather than
 * papered over, because neither can be engineered away here:
 *
 *   1. The run PERSISTS. `agy` writes the judge conversation — raw hits and
 *      all — under ~/.gemini/antigravity/brain/<conversationId>/, the same
 *      tree ../history/transcripts.ts sweeps, so a conversation left behind
 *      would be re-ingested as fresh findings on the next scan. This file
 *      therefore removes that conversation itself, in a finally. Removal is
 *      BEST EFFORT: a kill -9 between the transcript write and the cleanup
 *      leaves it on disk.
 *   2. The raw hits ride ARGV, so they are visible to `ps` for the life of the
 *      run and to anything that echoes a failed command line. Nothing here can
 *      fix that — only the host growing a stdin or prompt-file input could.
 *      It also puts the prompt under the OS's ARG_MAX (~1MB typically): the
 *      caller chunks a large history, which is what keeps a sweep under it.
 *
 * The verdict is read from stdout's JSON envelope (`response`); stderr is
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
// Pure parse: stdout envelope -> final message -> verdict
// -------------------------------------------------------------------------

// What `--output-format json` reports. Only two fields are load-bearing here:
// the final assistant message, and the id of the conversation the run created
// (which this module must then delete). Everything else in the envelope
// (status, usage) is ignored rather than modelled.
export interface JudgeEnvelope {
  response: string;
  conversationId?: string | undefined;
}

// Pull the JSON envelope out of stdout. Never echo stdout in an error: it can
// carry a raw hit the model failed to strip, and these errors propagate to the
// parent command's stderr, outside the judge subprocess. Every failure reports
// only raw-free metadata, never the content.
export function parseEnvelope(stdout: string): JudgeEnvelope {
  if (stdout.trim() === '') {
    throw new Error('agy judge produced no output');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error('agy judge output was not valid JSON');
  }
  // Array.isArray is load-bearing: `typeof [] === 'object'`, so an array
  // envelope would otherwise reach the field reads and be reported as a
  // missing `response` rather than as the malformed envelope it is.
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('agy judge output was not a JSON object');
  }
  const record = parsed as Record<string, unknown>;
  const response = record.response;
  if (typeof response !== 'string') {
    throw new Error('agy judge output carried no response string');
  }
  const rawId = record.conversation_id;
  return {
    response,
    conversationId: typeof rawId === 'string' && rawId !== '' ? rawId : undefined,
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
// carries the JSON envelope the verdict is read from. stderr is captured (not
// inherited) because `agy`'s run logging can echo raw content, and execFileSync's
// default would write it straight through to the parent's stderr — which flows
// into the wizard conversation this judge exists to keep raw content out of.
export function spawnAgy(argv: readonly string[], env: NodeJS.ProcessEnv): string {
  return execFileSync('agy', [...argv], {
    env,
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 32 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

// Raw-free description of a spawn failure. On this host the prompt DOES ride
// argv, so an execFileSync error's `.message` (which echoes the command line)
// can carry the raw hits outright — as can its captured stdout/stderr. None of
// it may cross back to the parent command, so we surface ONLY non-content
// metadata (exit status / signal / node error code), never `.message`,
// `.stdout`, or `.stderr`.
function spawnFailureMeta(err: unknown): string {
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
  // Injected spawn seam: receives the argv AFTER `agy` and the subprocess env,
  // and returns the child's stdout. Tests inject a fake that returns a canned
  // JSON envelope so no real `agy` runs.
  spawn: (argv: readonly string[], env: NodeJS.ProcessEnv) => string;
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

// Build the judge prompt (rubric + raw hits as JSONL), run it through `agy -p`,
// and return the parsed verdict — then delete the conversation the run left
// behind, whatever the outcome.
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

  const argv = ['-p', fullPrompt, '--output-format', 'json'] as const;

  // Snapshotted BEFORE the spawn so a run that dies without printing its
  // conversation_id can still be attributed by difference.
  const before = brainConversationIds(deps.home);
  let conversationId: string | undefined;
  try {
    let stdout: string;
    try {
      stdout = deps.spawn(argv, judgeEnv());
    } catch (err) {
      // Deliberately NOT chaining `err` as `cause`: on this host the error's
      // `.message` echoes argv — which carries every raw hit — and its captured
      // stdout/stderr may too. Attaching it would re-expose exactly what this
      // throw exists to strip. Only raw-free metadata is surfaced.
      // eslint-disable-next-line preserve-caught-error -- caught error carries raw argv; see above
      throw new Error(`agy judge subprocess failed (${spawnFailureMeta(err)})`);
    }
    const envelope = parseEnvelope(stdout);
    conversationId = envelope.conversationId;
    return parseVerdict(envelope.response);
  } finally {
    cleanupConversation(conversationId, before, deps.home);
  }
}
