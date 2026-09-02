import {
  closeSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';

import { DATA_DIR_MODE, DATA_FILE_MODE } from './data-dir.ts';

/**
 * Prohibited-model governance: which model a session is running on, and whether
 * the tenant has forbidden it.
 *
 * THE CEILING THIS OPERATES UNDER. No harness hook fires around the LLM request
 * itself, so nothing here blocks an API call. What it blocks is a model SWITCH
 * (PreModelSwitch, which is refusable) and a TURN that would run on a prohibited
 * model (UserPromptSubmit, which is refusable). A user who disables the plugin,
 * runs the harness without it, or edits this directory is not governed by it at
 * all. This is a control on a cooperative client, and the product must not
 * describe it as anything stronger.
 */

/**
 * One file holding the last session id we resolved a model for and that model.
 *
 * Single marker, overwritten per session, exactly like `nudge.ts`'s markers —
 * a per-session file would leak one entry per session forever. The stored
 * session id is what makes a stale or foreign entry detectable: `readSessionModel`
 * returns undefined when it does not match the caller's session, so two
 * concurrent sessions clobbering each other degrade to "model unknown" and
 * therefore to NO BLOCK, never to blocking a session on another session's model.
 */
const SESSION_MODEL_MARKER = 'session-model';

/** A trailing dated release suffix (`-20250805`) on an otherwise-equal model id. */
const DATE_SUFFIX = /-\d{8}$/;

/**
 * Fold a model id to the form two ids are compared in.
 *
 * Lowercased, and a trailing `-YYYYMMDD` release stamp removed, so a tenant that
 * prohibited `claude-haiku-4-5` also stops `claude-haiku-4-5-20251001`. The
 * stripping is anchored and requires exactly eight digits behind a hyphen, so it
 * cannot collapse two genuinely different ids into one (`claude-opus-4` and
 * `claude-opus-45` stay distinct — neither has a date suffix to strip).
 *
 * Nothing broader is attempted ON PURPOSE. The ids an admin prohibits are the
 * ids the control plane OBSERVED (`audit_events.model`, surfaced verbatim in the
 * dashboard), so the two sides already speak the same vocabulary and fuzzier
 * matching would only add ways to block the wrong model. One consequence worth
 * stating: a provider that reports a decorated id — a Bedrock
 * `us.anthropic.claude-…-v1:0`, say — is prohibited under THAT string and not
 * under the bare one, because that decorated string is what was observed.
 */
export function normalizeModelId(model: string): string {
  return model.trim().toLowerCase().replace(DATE_SUFFIX, '');
}

/**
 * Whether `model` is prohibited by `prohibited`.
 *
 * Returns false for an empty/unknown model and for an empty prohibition list —
 * the two "we do not know" cases, which must never block (a prohibition is
 * enforced on KNOWLEDGE, never on ignorance).
 */
export function isModelProhibited(
  model: string | undefined,
  prohibited: readonly string[] | undefined,
): boolean {
  if (model === undefined || model === '') return false;
  if (prohibited === undefined || prohibited.length === 0) return false;
  const needle = normalizeModelId(model);
  if (needle === '') return false;
  return prohibited.some((p) => normalizeModelId(p) === needle);
}

/**
 * Words that mean "whatever the parent is on" rather than naming a model.
 *
 * They resolve to the session's own model, which the switch and turn seams have
 * already vetted, so a spawn carrying one is not a second decision to take.
 */
const SPAWN_INHERIT_WORDS: ReadonlySet<string> = new Set(['inherit', 'default']);

/** Whether `char` ends an id rather than continuing it. */
function isBoundary(char: string): boolean {
  return char === '' || /[^a-z0-9]/.test(char);
}

/**
 * The prohibited id a subagent spawn's requested model names, or undefined.
 *
 * Returns the MATCHED ENTRY rather than a boolean because the audit row is
 * keyed on it: `buildModelRefusalEvent` exists so a control plane can group
 * refusals by the same id the prohibition was keyed on, and recording the
 * caller's spelling instead would file every spawn refusal under a string no
 * prohibition list contains.
 *
 * THE STRING COMPARED HERE IS CALLER-CHOSEN, and that is what separates this
 * seam from the other two. Their model is read from the session marker or the
 * transcript, so `normalizeModelId`'s exactness argument holds: both sides
 * speak the ids the control plane observed. Here the value is whatever the
 * caller put in the spawn's `model` argument, so an exact matcher is a matcher
 * with known spellings around it — `claude-opus-5[1m]`, `claude-opus-5-latest`,
 * `us.anthropic.claude-opus-5-v1:0` all name a prohibited build and none of
 * them is that build's id. Three shapes are therefore matched, each widening
 * bounded by what the organization actually prohibited:
 *
 *   1. The id itself, folded exactly as everywhere else.
 *   2. A BARE WORD (no hyphen) naming a tier — `opus`, `haiku`, `fable` —
 *      matched when some prohibited id carries it as a segment. Which words are
 *      tiers is the HARNESS's vocabulary and it grows; a fixed list of them is a
 *      list that drifts toward allow the next time one is added, silently, which
 *      is the failure this seam's own manifest matcher already made once.
 *      Deriving it from the prohibition list needs no edit to cover a tier that
 *      does not exist yet, at the cost of also matching a bare word that merely
 *      happens to be a segment (`claude`); that is not a value the harness
 *      accepts, and the refusal names what it matched.
 *   3. A prohibited id CARRIED INSIDE the requested string at non-alphanumeric
 *      boundaries on both ends — the decorated and suffixed spellings above.
 *      The boundary is what stops `claude-opus-4` from swallowing
 *      `claude-opus-45`.
 *
 * Undefined for every genuinely unknown case: an empty request, an empty list,
 * an inherit word, and a string that matches none of the three. This control
 * refuses on knowledge, never on ignorance.
 */
export function matchProhibitedSpawnModel(
  requested: string | undefined,
  prohibited: readonly string[] | undefined,
): string | undefined {
  if (requested === undefined || requested === '') return undefined;
  if (prohibited === undefined || prohibited.length === 0) return undefined;
  const needle = normalizeModelId(requested);
  if (needle === '' || SPAWN_INHERIT_WORDS.has(needle)) return undefined;

  const exact = prohibited.find((p) => normalizeModelId(p) === needle);
  if (exact !== undefined) return exact;

  if (!needle.includes('-')) {
    return prohibited.find((p) => normalizeModelId(p).split('-').includes(needle));
  }

  return prohibited.find((p) => {
    const base = normalizeModelId(p);
    if (base === '') return false;
    const at = needle.indexOf(base);
    if (at === -1) return false;
    return (
      isBoundary(at === 0 ? '' : needle.charAt(at - 1)) &&
      isBoundary(needle.charAt(at + base.length))
    );
  });
}

/**
 * Record the model a session is running on.
 *
 * Best-effort and silent: this is a governance CONVENIENCE (it saves the
 * enforcement path a transcript read), never a correctness requirement. A failed
 * write costs a fallback, not a wrong decision.
 */
export function recordSessionModel(
  dataDir: string,
  sessionId: string | undefined,
  model: string | undefined,
): void {
  if (sessionId === undefined || sessionId === '') return;
  if (model === undefined || model === '') return;
  try {
    mkdirSync(dataDir, { recursive: true, mode: DATA_DIR_MODE });
    writeFileSync(join(dataDir, SESSION_MODEL_MARKER), JSON.stringify({ sessionId, model }), {
      encoding: 'utf8',
      mode: DATA_FILE_MODE,
    });
  } catch {
    // Fail-open: the enforcement path falls back to the transcript.
  }
}

/**
 * The model recorded for THIS session, or undefined.
 *
 * Synchronous by contract — every caller is a hook deciding whether to allow a
 * turn, and none of them can await. Undefined on absence, a torn read, a parse
 * failure, or a session-id mismatch; all four mean "not known", which the caller
 * must treat as allow.
 */
export function readSessionModel(
  dataDir: string,
  sessionId: string | undefined,
): string | undefined {
  if (sessionId === undefined || sessionId === '') return undefined;
  try {
    const parsed: unknown = JSON.parse(readFileSync(join(dataDir, SESSION_MODEL_MARKER), 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return undefined;
    const record = parsed as { sessionId?: unknown; model?: unknown };
    // The id gate: a marker written by a DIFFERENT session says nothing about
    // this one, and acting on it would block a session on a model it is not
    // running.
    if (record.sessionId !== sessionId) return undefined;
    return typeof record.model === 'string' && record.model !== '' ? record.model : undefined;
  } catch {
    return undefined;
  }
}

/** How much of a transcript's tail is scanned for the last model. */
const TAIL_BYTES = 256 * 1024;

/**
 * The last `TAIL_BYTES` of a file, as text, without reading the rest of it.
 *
 * `readFileSync` then `.slice()` reads and UTF-8-decodes the WHOLE file first,
 * so it is not a bounded read however small the slice — and a transcript grows
 * for the life of a session, on a path a hook runs every turn. This seeks, so
 * the cost is the constant rather than the file.
 *
 * Decoding starts mid-file, so the first bytes may be the tail of a multi-byte
 * character. Harmless for the same reason the first LINE is dropped: a torn
 * prefix cannot parse as JSON and is skipped either way.
 */
function readTail(path: string): { text: string; truncated: boolean } {
  const fd = openSync(path, 'r');
  try {
    const { size } = fstatSync(fd);
    if (size <= TAIL_BYTES) return { text: readFileSync(fd, 'utf8'), truncated: false };
    // LOOPED, because a short read here loses the WRONG END. The window is
    // filled from its start, so bytes a single `readSync` failed to deliver are
    // the ones nearest EOF — the NEWEST records — and the scan below would then
    // answer from an older one.
    //
    // That direction is the expensive one on this path. Everywhere else an
    // unknown means allow; this is the one shape that fails toward a wrong
    // BLOCK, because a user who has just switched AWAY from a prohibited model
    // would still read as running on it and be refused with a message telling
    // them to do what they already did.
    //
    // A positional read wholly inside a local regular file returns the full
    // count, so this loop is not reachable there. `~/.aka` on a network home
    // (NFS/SMB) is where that stops being guaranteed, and this product supports
    // one. `readFileSync` looped on the caller's behalf; `readSync` does not.
    const buffer = Buffer.allocUnsafe(TAIL_BYTES);
    let filled = 0;
    while (filled < TAIL_BYTES) {
      const n = readSync(fd, buffer, filled, TAIL_BYTES - filled, size - TAIL_BYTES + filled);
      // EOF, or a reader that will deliver nothing more — the file cannot have
      // shrunk under us without `size` being stale, and stopping beats spinning.
      if (n === 0) break;
      filled += n;
    }
    return { text: buffer.subarray(0, filled).toString('utf8'), truncated: true };
  } finally {
    closeSync(fd);
  }
}

/**
 * Pull a model id out of one parsed transcript record, or undefined when that
 * record carries none.
 *
 * The one harness-specific part of reading a transcript, taken as a parameter
 * because the scanning around it is identical everywhere and the record shapes
 * are not: Claude Code writes `{type:'assistant', message:{model}}` per
 * response, Codex `{type:'turn_context', payload:{model}}` per turn. A
 * per-harness copy is how the two drift on the parts that genuinely are shared —
 * the byte bound, the torn first line, the newest-first order.
 */
export type ModelFromRecord = (record: unknown) => string | undefined;

/**
 * The model named by the LAST record in a transcript that names one.
 *
 * Reads only the tail (see `readTail` above), so the cost is the constant rather
 * than the transcript — this runs on a hook path once per turn.
 *
 * Scanned newest-first and the first match wins, because a model switch
 * mid-session makes only the LATEST record current. The first line is dropped
 * when the file was actually cut: a positional read lands mid-line, and half a
 * JSON object is not a record.
 */
export function modelFromTranscriptTail(
  transcriptPath: string | undefined,
  fromRecord: ModelFromRecord,
): string | undefined {
  if (transcriptPath === undefined || transcriptPath === '') return undefined;
  try {
    const { text: slice, truncated } = readTail(transcriptPath);
    const lines = slice.split('\n');
    if (truncated) lines.shift();
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i];
      if (line === undefined || line === '') continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        continue;
      }
      const model = fromRecord(parsed);
      if (model !== undefined && model !== '') return model;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/** Claude Code: one `assistant` record per response, model on `message`. */
export const claudeCodeModelFromRecord: ModelFromRecord = (record) => {
  if (typeof record !== 'object' || record === null) return undefined;
  const { type, message } = record as { type?: unknown; message?: unknown };
  if (type !== 'assistant') return undefined;
  if (typeof message !== 'object' || message === null) return undefined;
  const model = (message as { model?: unknown }).model;
  return typeof model === 'string' && model !== '' ? model : undefined;
};

/**
 * Codex: one `turn_context` record per turn, model on `payload`.
 *
 * The model is a property of the TURN rather than of a response there, so there
 * is no per-response line to read instead.
 */
export const codexModelFromRecord: ModelFromRecord = (record) => {
  if (typeof record !== 'object' || record === null) return undefined;
  const { type, payload } = record as { type?: unknown; payload?: unknown };
  if (type !== 'turn_context') return undefined;
  if (typeof payload !== 'object' || payload === null) return undefined;
  const model = (payload as { model?: unknown }).model;
  return typeof model === 'string' && model !== '' ? model : undefined;
};

/** The Claude Code spelling, kept as its own name for that plugin's callers. */
export function modelFromTranscript(transcriptPath: string | undefined): string | undefined {
  return modelFromTranscriptTail(transcriptPath, claudeCodeModelFromRecord);
}

/**
 * The reason shown to the user when a model is refused.
 *
 * Names the model and the mechanism, and says who can change it — a governance
 * refusal the user cannot act on is just an obstacle. Deliberately does NOT
 * claim the call was intercepted: nothing here sits in the network path, and
 * saying otherwise would overstate the control.
 */
export function prohibitedModelMessage(model: string, action: 'switch' | 'turn' | 'spawn'): string {
  const subject =
    action === 'switch'
      ? `Cannot switch to ${model}`
      : action === 'spawn'
        ? `Cannot start a subagent on ${model}`
        : `This session is running on ${model}, which cannot be used`;
  // The remedy differs by seam: a spawn is refused on an argument the caller
  // chose, so pointing it at /model would name the wrong control.
  const remedy =
    action === 'spawn'
      ? 'Name an approved model on the subagent'
      : 'Switch to an approved model with /model';
  return (
    `${subject} — your organization has prohibited this model. ` +
    `${remedy}, or ask an administrator to change ` +
    `its status in AKA under Govern → LLM Providers.`
  );
}

/**
 * Refuse a TURN whose session is running on a prohibited model.
 *
 * Lives here rather than in either plugin because nothing in it is
 * harness-specific: both hosts spell a blocked prompt as a top-level
 * `{decision:'block'}`, and both reach the same message. Two copies of one
 * decision drift on exactly the parts that are shared — the same argument that
 * put the tail scanner here.
 *
 * The genuinely host-specific half stays in each plugin: resolving WHICH model
 * the session is on (a marker plus that harness's own record shape), which is
 * where the two really differ.
 *
 * Null (allow) for every uncertain case — an unresolvable model, an absent
 * list, a model not on it. This control refuses on knowledge, never on
 * ignorance.
 */
export function decideProhibitedModelTurn(
  model: string | undefined,
  prohibitedModels: readonly string[] | undefined,
): { decision: 'block'; reason: string } | null {
  // Narrowed before the check rather than asserted after it, so the compiler
  // sees a `string` at the message call — both `as` and `!` are refused here.
  if (model === undefined || model === '') return null;
  if (!isModelProhibited(model, prohibitedModels)) return null;
  return { decision: 'block', reason: prohibitedModelMessage(model, 'turn') };
}

/**
 * Which seam refused: a model switch, a turn already running on one, or a
 * subagent spawn asking for one.
 */
export type RefusalSeam = 'switch' | 'turn' | 'spawn';

/**
 * The audit row for one refusal.
 *
 * WHAT IT DELIBERATELY DOES NOT CARRY is the point: no prompt, no response, no
 * content of any kind. A governance refusal is worth recording so an operator
 * can see the control working and on which machines — that question is answered
 * by the model, the seam and the session, and answering it does not require
 * moving anything the user typed. `content` is left unset rather than set to a
 * summary, so there is no field for text to creep into later.
 *
 * `id` is random rather than content-addressed: refusals are facts, and two
 * identical refusals a minute apart are two events, not one recorded twice.
 *
 * The caller owns whether this is written at all — every call site is
 * best-effort and swallows its own failure, because a refusal that cannot be
 * recorded must still be a refusal.
 */
export function buildModelRefusalEvent(input: {
  id: string;
  sessionId: string | undefined;
  model: string;
  seam: RefusalSeam;
  sourceTool: string;
  occurredAt: string;
  /**
   * What the caller ASKED for, when that is not the id `model` carries.
   *
   * The spawn seam matches a tier word or a decorated spelling against the
   * prohibited id, and `model` records the id so a control plane can group the
   * refusal with the prohibition. That would otherwise lose the string the user
   * actually typed, which is the half the refusal message quotes back at them —
   * so the two stay reconcilable rather than the row silently rewriting history.
   */
  requestedModel?: string;
}): {
  id: string;
  eventType: 'model_refusal';
  startedAt: string;
  rootSessionId?: string;
  attributes: Record<string, unknown>;
} {
  return {
    id: input.id,
    eventType: 'model_refusal',
    startedAt: input.occurredAt,
    // Omitted rather than nulled when unknown: `root_session_id` is a self-FK,
    // and a session id naming no row would fail the insert outright.
    ...(input.sessionId === undefined || input.sessionId === ''
      ? {}
      : { rootSessionId: input.sessionId }),
    attributes: {
      // `model` is a generated column on audit_events, so the refused model is
      // queryable without unpacking the bag — which is what lets the control
      // plane group refusals by the same id the prohibition was keyed on.
      model: input.model,
      refusal_seam: input.seam,
      source_tool: input.sourceTool,
      // Omitted rather than duplicated when the caller named the id itself.
      ...(input.requestedModel === undefined || input.requestedModel === input.model
        ? {}
        : { requested_model: input.requestedModel }),
    },
  };
}
