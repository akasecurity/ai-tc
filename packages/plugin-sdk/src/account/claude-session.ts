import {
  closeSync,
  fstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';

import { DATA_DIR_MODE, DATA_FILE_MODE } from '@akasecurity/persistence/sqlite-free';
import { z } from 'zod';

import type { SessionBoundary } from './observation-log.ts';
import { sessionScanCachePath } from './observation-log.ts';

// The organization a Claude Code session runs under, from the host's own
// transcript: the credential_org attachment it writes per request, under
// claude.ai OAuth only, whenever the value differs from the last one in context.

export const TRANSCRIPT_SCAN_CAP_BYTES = 64 * 1024 * 1024;

const CHUNK_BYTES = 4 * 1024 * 1024;
const LINE_MAX_BYTES = 1024 * 1024;
const NEWLINE = 0x0a;
const NEEDLE = Buffer.from('"credential_org"');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface CredentialOrgSighting {
  /** The byte offset of the line's first byte. */
  readonly pos: number;
  readonly t: number;
  readonly org: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function closeQuietly(fd: number): void {
  try {
    closeSync(fd);
  } catch {
    // already closed
  }
}

/**
 * The org and time of one transcript line when it is a credential_org
 * attachment of `sessionId` with a UUID value. Any other record, a tool result
 * that happens to contain the same words included, is not one.
 */
export function credentialOrgOf(
  line: string,
  sessionId: string,
): { readonly t: number; readonly org: string } | undefined {
  let record: unknown;
  try {
    record = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!isRecord(record) || record.type !== 'attachment' || record.sessionId !== sessionId)
    return undefined;
  const attachment = record.attachment;
  if (!isRecord(attachment) || attachment.type !== 'credential_org') return undefined;
  const raw = attachment.organizationUuid;
  if (typeof raw !== 'string') return undefined;
  const org = raw.toLowerCase();
  if (!UUID.test(org)) return undefined;
  const t = typeof record.timestamp === 'string' ? Date.parse(record.timestamp) : Number.NaN;
  return Number.isFinite(t) ? { t, org } : undefined;
}

function collect(
  buffer: Buffer,
  base: number,
  sessionId: string,
  out: CredentialOrgSighting[],
): void {
  let hit = buffer.indexOf(NEEDLE);
  while (hit !== -1) {
    const start = buffer.lastIndexOf(NEWLINE, hit) + 1;
    const newline = buffer.indexOf(NEWLINE, hit);
    const end = newline === -1 ? buffer.length : newline;
    const found = credentialOrgOf(buffer.toString('utf8', start, end), sessionId);
    if (found !== undefined) out.push({ pos: base + start, t: found.t, org: found.org });
    hit = buffer.indexOf(NEEDLE, end);
  }
}

function newlineBefore(fd: number, offset: number): boolean {
  const byte = Buffer.alloc(1);
  return readSync(fd, byte, 0, 1, offset - 1) === 1 && byte[0] === NEWLINE;
}

export interface TranscriptDelta {
  readonly sightings: readonly CredentialOrgSighting[];
  /** One past the last complete line read. */
  readonly nextOffset: number;
  /** True when a shrink or a rewrite under `from` sent the scan back to 0. */
  readonly rescanned: boolean;
}

/**
 * The credential_org sightings from `from` to the last complete line. A file
 * smaller than `from`, or one whose byte before `from` is not a newline, is
 * scanned from 0 instead. Undefined when it cannot be read, or the bytes to
 * scan pass the cap.
 */
export function scanCredentialOrgs(
  path: string,
  sessionId: string,
  from: number,
  capBytes: number = TRANSCRIPT_SCAN_CAP_BYTES,
): TranscriptDelta | undefined {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    return undefined;
  }
  try {
    const size = fstatSync(fd).size;
    let start = from;
    let rescanned = false;
    if (start > size || (start > 0 && !newlineBefore(fd, start))) {
      start = 0;
      rescanned = true;
    }
    if (size - start > capBytes) return undefined;
    const sightings: CredentialOrgSighting[] = [];
    let carry = Buffer.alloc(0);
    let carryAt = start;
    let position = start;
    while (position < size) {
      const want = Math.min(CHUNK_BYTES, size - position);
      const chunk = Buffer.allocUnsafe(want);
      const read = readSync(fd, chunk, 0, want, position);
      if (read === 0) break;
      position += read;
      const data =
        carry.length === 0
          ? chunk.subarray(0, read)
          : Buffer.concat([carry, chunk.subarray(0, read)]);
      const complete = data.lastIndexOf(NEWLINE) + 1;
      collect(data.subarray(0, complete), carryAt, sessionId, sightings);
      carry = Buffer.from(data.subarray(complete));
      carryAt += complete;
    }
    return { sightings, nextOffset: carryAt, rescanned };
  } catch {
    return undefined;
  } finally {
    closeQuietly(fd);
  }
}

/** The credential_org org on the line that starts at `pos`, read again; undefined for anything else. */
export function credentialOrgAt(path: string, sessionId: string, pos: number): string | undefined {
  let fd: number;
  try {
    fd = openSync(path, 'r');
  } catch {
    return undefined;
  }
  try {
    const buffer = Buffer.alloc(LINE_MAX_BYTES);
    const read = readSync(fd, buffer, 0, LINE_MAX_BYTES, pos);
    const newline = buffer.subarray(0, read).indexOf(NEWLINE);
    if (newline === -1) return undefined;
    return credentialOrgOf(buffer.toString('utf8', 0, newline), sessionId)?.org;
  } catch {
    return undefined;
  } finally {
    closeQuietly(fd);
  }
}

export type SessionAnchor =
  | { readonly kind: 'anchor'; readonly org: string; readonly at: number }
  | { readonly kind: 'none'; readonly reason: 'no-session-account' | 'org-changed' };

export interface AnchorOutcome {
  readonly anchor: SessionAnchor;
  readonly anchorAt: number | undefined;
  readonly changedAt: number | undefined;
}

const NO_ANCHOR: AnchorOutcome = {
  anchor: { kind: 'none', reason: 'no-session-account' },
  anchorAt: undefined,
  changedAt: undefined,
};

/**
 * The session's org under the last boundary: the first sighting at or after
 * it, or, after a resume this binding inherited across, the last one before
 * it. A later sighting with another value ends attribution until the next
 * boundary. No boundary, no anchor.
 */
export function anchorOf(
  sightings: readonly CredentialOrgSighting[],
  boundary: SessionBoundary | undefined,
): AnchorOutcome {
  if (boundary === undefined) return NO_ANCHOR;
  let index = -1;
  if (boundary.kind === 'resume' && boundary.inherited) {
    sightings.forEach((sighting, i) => {
      if (sighting.t < boundary.t) index = i;
    });
  } else {
    index = sightings.findIndex((sighting) => sighting.t >= boundary.t);
  }
  const anchor = sightings[index];
  if (anchor === undefined) return NO_ANCHOR;
  const changed = sightings.slice(index + 1).find((sighting) => sighting.org !== anchor.org);
  if (changed !== undefined) {
    return {
      anchor: { kind: 'none', reason: 'org-changed' },
      anchorAt: anchor.pos,
      changedAt: changed.pos,
    };
  }
  return {
    anchor: { kind: 'anchor', org: anchor.org, at: anchor.pos },
    anchorAt: anchor.pos,
    changedAt: undefined,
  };
}

/** What is kept between scans of one transcript: offsets, a time and a flag, never an org. */
export interface AnchorState {
  readonly offset: number;
  readonly anchorAt?: number | undefined;
  readonly changedAt?: number | undefined;
  readonly lastBoundaryAt?: number | undefined;
  /** Whether the anchor was read across an inherited resume. */
  readonly inherited?: boolean | undefined;
}

export interface ResolvedAnchor {
  readonly anchor: SessionAnchor;
  readonly state: AnchorState;
}

const ORG_CHANGED: SessionAnchor = { kind: 'none', reason: 'org-changed' };

/**
 * The anchor under `boundary`, scanning only what the host appended since `state`. A boundary or
 * an inheritance other than the one `state` was read under, a rewrite under the offset, an
 * inherited boundary with no anchor yet, or an anchor line that no longer reads as a
 * credential_org record of this session each rescan from 0. Undefined when the transcript cannot
 * be read.
 */
export function resolveSessionAnchor(
  path: string,
  sessionId: string,
  boundary: SessionBoundary | undefined,
  state: AnchorState | undefined,
  capBytes: number = TRANSCRIPT_SCAN_CAP_BYTES,
): ResolvedAnchor | undefined {
  if (boundary === undefined) return { anchor: NO_ANCHOR.anchor, state: state ?? { offset: 0 } };
  const full = (): ResolvedAnchor | undefined => {
    const delta = scanCredentialOrgs(path, sessionId, 0, capBytes);
    if (delta === undefined) return undefined;
    const outcome = anchorOf(delta.sightings, boundary);
    return {
      anchor: outcome.anchor,
      state: {
        offset: delta.nextOffset,
        anchorAt: outcome.anchorAt,
        changedAt: outcome.changedAt,
        lastBoundaryAt: boundary.t,
        inherited: boundary.inherited,
      },
    };
  };
  if (state?.lastBoundaryAt !== boundary.t || (state.inherited ?? false) !== boundary.inherited)
    return full();
  if (state.anchorAt === undefined && boundary.inherited) return full();
  const delta = scanCredentialOrgs(path, sessionId, state.offset, capBytes);
  if (delta === undefined) return undefined;
  if (delta.rescanned) return full();
  if (state.changedAt !== undefined)
    return { anchor: ORG_CHANGED, state: { ...state, offset: delta.nextOffset } };
  if (state.anchorAt === undefined) {
    const outcome = anchorOf(delta.sightings, boundary);
    return {
      anchor: outcome.anchor,
      state: {
        ...state,
        offset: delta.nextOffset,
        anchorAt: outcome.anchorAt,
        changedAt: outcome.changedAt,
      },
    };
  }
  const org = credentialOrgAt(path, sessionId, state.anchorAt);
  if (org === undefined) return full();
  const changed = delta.sightings.find((sighting) => sighting.org !== org);
  if (changed !== undefined) {
    return {
      anchor: ORG_CHANGED,
      state: { ...state, offset: delta.nextOffset, changedAt: changed.pos },
    };
  }
  return {
    anchor: { kind: 'anchor', org, at: state.anchorAt },
    state: { ...state, offset: delta.nextOffset },
  };
}

const ClaudeVerdictMemo = z.object({
  bd: z.string(),
  h: z.string(),
  cfgMtime: z.number(),
  cfgSize: z.number(),
  envFp: z.string(),
  at: z.number(),
});
export type ClaudeVerdictMemo = z.infer<typeof ClaudeVerdictMemo>;

/**
 * Byte offsets into the host's transcript, the boundary they were read under
 * (with the binding hash its inheritance was read for), and a work memo.
 */
export const TranscriptScanCache = z.object({
  offset: z.number().int().nonnegative(),
  anchorAt: z.number().int().nonnegative().optional(),
  changedAt: z.number().int().nonnegative().optional(),
  lastBoundaryAt: z.number().optional(),
  boundaryKind: z.enum(['startup', 'clear', 'resume']).optional(),
  inherited: z.boolean().optional(),
  boundaryBd: z.string().optional(),
  memo: ClaudeVerdictMemo.optional(),
});
export type TranscriptScanCache = z.infer<typeof TranscriptScanCache>;

export function readScanCache(
  stateDir: string,
  sessionId: string,
): TranscriptScanCache | undefined {
  try {
    const parsed = TranscriptScanCache.safeParse(
      JSON.parse(readFileSync(sessionScanCachePath(stateDir, sessionId), 'utf8')),
    );
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

/** Replace the scan cache atomically, owner-only. Losing it only costs a rescan. */
export function writeScanCache(
  stateDir: string,
  sessionId: string,
  cache: TranscriptScanCache,
): void {
  const path = sessionScanCachePath(stateDir, sessionId);
  const tmp = `${path}.${String(process.pid)}.tmp`;
  try {
    mkdirSync(stateDir, { recursive: true, mode: DATA_DIR_MODE });
    rmSync(tmp, { force: true });
    writeFileSync(tmp, JSON.stringify(TranscriptScanCache.parse(cache)), {
      mode: DATA_FILE_MODE,
      flag: 'wx',
    });
    renameSync(tmp, path);
  } catch {
    try {
      rmSync(tmp, { force: true });
    } catch {
      // nothing left to remove
    }
  }
}
