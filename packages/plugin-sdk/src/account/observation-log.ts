import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, mkdirSync, openSync, readSync, writeSync } from 'node:fs';
import { join } from 'node:path';

import { DATA_DIR_MODE, DATA_FILE_MODE } from '@akasecurity/persistence/sqlite-free';
import { SessionAccountObservation } from '@akasecurity/schema';

// Per-session account state under the session-accounts directory: the
// append-only observation log (<id>.log), and the name of the transcript scan
// cache beside it (<id>.scan.json). Every function here never throws.

export const SESSION_LOG_CAP_BYTES = 16 * 1024 * 1024;
export const SESSION_LOG_TAIL_BYTES = 64 * 1024;

const NEWLINE = 0x0a;
const SAFE_SESSION_ID = /^[A-Za-z0-9._-]+$/;

/**
 * The flags the log is opened with: write-only, append, create, and no symlink
 * followed where the platform has the flag. Windows has none, so there the
 * open is a plain append.
 */
export function sessionLogOpenFlags(noFollow: number | undefined): number {
  return constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | (noFollow ?? 0);
}

const SESSION_LOG_OPEN_FLAGS = sessionLogOpenFlags(
  (constants as { O_NOFOLLOW?: number }).O_NOFOLLOW,
);

function closeQuietly(fd: number): void {
  try {
    closeSync(fd);
  } catch {
    // already closed
  }
}

/** The id itself when it is a plain filename token, else its SHA-256 hex. */
export function sessionStateName(sessionId: string): string {
  if (SAFE_SESSION_ID.test(sessionId) && sessionId !== '.' && sessionId !== '..') return sessionId;
  return createHash('sha256').update(sessionId).digest('hex');
}

export function sessionLogPath(stateDir: string, sessionId: string): string {
  return join(stateDir, `${sessionStateName(sessionId)}.log`);
}

export function sessionScanCachePath(stateDir: string, sessionId: string): string {
  return join(stateDir, `${sessionStateName(sessionId)}.scan.json`);
}

/** The hash a work view and a start line carry for an account key. */
export function sessionAccountHash(accountKey: string): string {
  return createHash('sha256').update(`aka-session-account:v1\n${accountKey}`).digest('hex');
}

/**
 * Append one observation as one O_APPEND write, so concurrent writers never lose
 * a line. False when the line is not a session-state shape, the log is at its
 * cap, or the write fails.
 */
export function appendObservation(
  stateDir: string,
  sessionId: string,
  observation: SessionAccountObservation,
  capBytes: number = SESSION_LOG_CAP_BYTES,
  openFlags: number = SESSION_LOG_OPEN_FLAGS,
): boolean {
  const parsed = SessionAccountObservation.safeParse(observation);
  if (!parsed.success) return false;
  const line = `${JSON.stringify(parsed.data)}\n`;
  let fd: number | undefined;
  try {
    mkdirSync(stateDir, { recursive: true, mode: DATA_DIR_MODE });
    fd = openSync(sessionLogPath(stateDir, sessionId), openFlags, DATA_FILE_MODE);
    if (fstatSync(fd).size + Buffer.byteLength(line) > capBytes) return false;
    writeSync(fd, line);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) closeQuietly(fd);
  }
}

export interface LoggedObservation {
  readonly observation: SessionAccountObservation;
  /** The byte offset just past this line. */
  readonly end: number;
}

export interface ObservationRead {
  readonly entries: readonly LoggedObservation[];
  readonly size: number;
}

function parseObservation(text: string): SessionAccountObservation | undefined {
  try {
    const parsed = SessionAccountObservation.safeParse(JSON.parse(text));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

function parseLines(buffer: Buffer, base: number): LoggedObservation[] {
  const entries: LoggedObservation[] = [];
  let start = 0;
  for (
    let newline = buffer.indexOf(NEWLINE);
    newline !== -1;
    newline = buffer.indexOf(NEWLINE, start)
  ) {
    const observation = parseObservation(buffer.toString('utf8', start, newline));
    start = newline + 1;
    if (observation !== undefined) entries.push({ observation, end: base + start });
  }
  return entries;
}

function readRange(
  path: string,
  from: number,
  capBytes: number,
): { buffer: Buffer; size: number } | undefined {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    return undefined;
  }
  try {
    const size = fstatSync(fd).size;
    const length = Math.max(0, Math.min(size, capBytes) - from);
    const buffer = Buffer.alloc(length);
    let filled = 0;
    while (filled < length) {
      const chunk = readSync(fd, buffer, filled, length - filled, from + filled);
      if (chunk === 0) break;
      filled += chunk;
    }
    return { buffer: buffer.subarray(0, filled), size };
  } catch {
    return undefined;
  } finally {
    closeQuietly(fd);
  }
}

/** Every complete, well-formed line from `from`, up to the cap. */
export function readObservations(
  stateDir: string,
  sessionId: string,
  from = 0,
  capBytes: number = SESSION_LOG_CAP_BYTES,
): ObservationRead {
  const range = readRange(sessionLogPath(stateDir, sessionId), from, capBytes);
  if (range === undefined) return { entries: [], size: from };
  return { entries: parseLines(range.buffer, from), size: range.size };
}

/** The complete lines in the last `windowBytes` of the log; `complete` when that is the whole log. */
export function readObservationTail(
  stateDir: string,
  sessionId: string,
  windowBytes: number = SESSION_LOG_TAIL_BYTES,
): { readonly entries: readonly SessionAccountObservation[]; readonly complete: boolean } {
  const path = sessionLogPath(stateDir, sessionId);
  const whole = readRange(path, 0, 0);
  if (whole === undefined) return { entries: [], complete: true };
  const from = Math.max(0, Math.min(whole.size, SESSION_LOG_CAP_BYTES) - windowBytes);
  // One byte early, so a window that starts on a line boundary keeps that line.
  const readFrom = from === 0 ? 0 : from - 1;
  const range = readRange(path, readFrom, SESSION_LOG_CAP_BYTES);
  if (range === undefined) return { entries: [], complete: true };
  const firstLine = readFrom === 0 ? 0 : range.buffer.indexOf(NEWLINE) + 1;
  return {
    entries: parseLines(range.buffer.subarray(firstLine), readFrom + firstLine).map(
      (entry) => entry.observation,
    ),
    complete: from === 0,
  };
}

export type ObservationKind =
  | {
      readonly kind: 'view';
      readonly t: number;
      readonly bd: string | undefined;
      readonly k: 'w' | 'n' | 'v' | 'u';
      readonly h: string | undefined;
    }
  | { readonly kind: 'boundary'; readonly t: number; readonly b: 'startup' | 'clear' | 'resume' }
  | { readonly kind: 'inherit'; readonly t: number; readonly bd: string }
  | {
      readonly kind: 'start';
      readonly t: number;
      readonly bd: string;
      readonly start: string;
      readonly s: string;
      readonly fp: string | undefined;
    }
  | {
      readonly kind: 'baseline';
      readonly t: number;
      readonly bd: string;
      readonly s: string;
      readonly fp: string;
    }
  | { readonly kind: 'sticky'; readonly t: number; readonly bd: string }
  | { readonly kind: 'other'; readonly t: number };

const VIEW_KINDS: ReadonlySet<string> = new Set(['w', 'n', 'v', 'u']);
const BOUNDARY_KINDS: ReadonlySet<string> = new Set(['startup', 'clear', 'resume']);

/** Which of the session-state lines an observation is, by the fields it carries. */
export function classifyObservation(observation: SessionAccountObservation): ObservationKind {
  const line = observation as Readonly<Record<string, unknown>>;
  const t = typeof line.t === 'number' ? line.t : Number.NaN;
  const bd = typeof line.bd === 'string' ? line.bd : undefined;
  const s = typeof line.s === 'string' ? line.s : undefined;
  const fp = typeof line.fp === 'string' ? line.fp : undefined;
  if (typeof line.k === 'string' && VIEW_KINDS.has(line.k)) {
    const h = typeof line.h === 'string' ? line.h : undefined;
    return { kind: 'view', t, bd, k: line.k as 'w' | 'n' | 'v' | 'u', h };
  }
  if (typeof line.b === 'string' && BOUNDARY_KINDS.has(line.b)) {
    return { kind: 'boundary', t, b: line.b as 'startup' | 'clear' | 'resume' };
  }
  if (line.inh === true && bd !== undefined) return { kind: 'inherit', t, bd };
  if (typeof line.start === 'string' && bd !== undefined && s !== undefined) {
    return { kind: 'start', t, bd, start: line.start, s, fp };
  }
  if (bd !== undefined && s !== undefined && fp !== undefined)
    return { kind: 'baseline', t, bd, s, fp };
  if (bd !== undefined && s === 'none') return { kind: 'sticky', t, bd };
  return { kind: 'other', t };
}

/** The last boundary in a session's log, and whether this binding inherited across it. */
export interface SessionBoundary {
  readonly t: number;
  readonly kind: 'startup' | 'clear' | 'resume';
  readonly inherited: boolean;
}

export function latestBoundary(
  entries: readonly SessionAccountObservation[],
  bindingHash: string,
): SessionBoundary | undefined {
  let boundary: SessionBoundary | undefined;
  for (const entry of entries) {
    const line = classifyObservation(entry);
    if (line.kind === 'boundary') {
      boundary = { t: line.t, kind: line.b, inherited: false };
    } else if (
      line.kind === 'inherit' &&
      line.bd === bindingHash &&
      boundary?.kind === 'resume' &&
      line.t >= boundary.t
    ) {
      boundary = { ...boundary, inherited: true };
    }
  }
  return boundary;
}
