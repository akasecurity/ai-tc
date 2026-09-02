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
 * The model of the most recent assistant record in a transcript, or undefined.
 *
 * The fallback for a session with no recorded model — one that started before
 * this plugin version, or whose marker a concurrent session clobbered.
 *
 * Records are scanned NEWEST-FIRST and the first assistant record wins, because
 * a `/model` switch mid-session makes only the latest record's model current.
 * The first line of the slice is dropped when the file was cut: a positional
 * read lands mid-line, and half a JSON object is not a record.
 *
 * Cost is bounded by `TAIL_BYTES` rather than by transcript length — see
 * `readTail`, which is what makes that true.
 */
export function modelFromTranscript(transcriptPath: string | undefined): string | undefined {
  if (transcriptPath === undefined || transcriptPath === '') return undefined;
  try {
    const { text: slice, truncated } = readTail(transcriptPath);
    const lines = slice.split('\n');
    // Only when the slice was actually cut — an untruncated file's first line is
    // a whole record and dropping it would lose a single-record transcript.
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
      if (typeof parsed !== 'object' || parsed === null) continue;
      const record = parsed as { type?: unknown; message?: unknown };
      if (record.type !== 'assistant') continue;
      const message = record.message;
      if (typeof message !== 'object' || message === null) continue;
      const model = (message as { model?: unknown }).model;
      if (typeof model === 'string' && model !== '') return model;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * The reason shown to the user when a model is refused.
 *
 * Names the model and the mechanism, and says who can change it — a governance
 * refusal the user cannot act on is just an obstacle. Deliberately does NOT
 * claim the call was intercepted: nothing here sits in the network path, and
 * saying otherwise would overstate the control.
 */
export function prohibitedModelMessage(model: string, action: 'switch' | 'turn'): string {
  const subject =
    action === 'switch'
      ? `Cannot switch to ${model}`
      : `This session is running on ${model}, which cannot be used`;
  return (
    `${subject} — your organization has prohibited this model. ` +
    `Switch to an approved model with /model, or ask an administrator to change ` +
    `its status in AKA under Govern → LLM Providers.`
  );
}
