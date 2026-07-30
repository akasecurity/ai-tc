// Display-side pointer rendering for the MessageDisplay hook. The hook fires
// once per streaming delta, so a pointer token can arrive split across process
// invocations; `transformDelta` rewrites each delta and threads a carry — the
// possibly-open pointer/marker tail plus the markdown-region state — between
// calls. The transform's I/O is injected through DisplayDeps, so it is
// synchronously testable; the carry store at the bottom of this file persists
// the carry between hook processes in one per-session file, and the hook entry
// (message-display.ts) owns stdin and settings.
import {
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join } from 'node:path';

import { DetectionCategory, pointerTokenScanner } from '@akasecurity/schema';

// An open fenced-code region: the opening marker's character and run length.
// A fence closes only on a line-start run of the SAME character at least as
// long as the opener, so a ``` inside a ````-opened fence is content, and a
// tilde fence is never closed by backticks.
export interface FenceState {
  char: '`' | '~';
  len: number;
}

// State threaded between deltas of one content block.
export interface DisplayCarry {
  // A buffer suffix that may be the opening of a pointer token, or a trailing
  // backtick/tilde run that could still grow into a fence marker, held back
  // and re-scanned with the next delta.
  tail: string;
  // Markdown-region state of the emitted stream so far: inside a fenced code
  // block, inside an inline `code` span, on a '>'-quoted line.
  fence: FenceState | null;
  tickOpen: boolean;
  lineQuoted: boolean;
  // Position within the current line: whether non-whitespace content has been
  // seen yet, and how many columns of leading whitespace precede it. Both
  // persist across deltas so a marker resuming at a delta boundary is judged
  // against its true line position — a fence only opens or closes at line
  // start with at most 3 columns of indent.
  lineSeen: boolean;
  lineIndent: number;
  // Raw values revealed so far in this MESSAGE (full mode's cap). The carry
  // store persists this per message — it survives block finals and resets
  // only when the message id changes.
  revealedCount: number;
}

export const EMPTY_CARRY: DisplayCarry = Object.freeze({
  tail: '',
  fence: null,
  tickOpen: false,
  lineQuoted: false,
  lineSeen: false,
  lineIndent: 0,
  revealedCount: 0,
});

export interface DisplayDeps {
  mode: 'masked' | 'full' | 'off';
  maxRevealsPerMessage: number;
  // Descriptor lookup for the masked badge. Null when the pointer is unknown.
  describe(
    token: string,
  ): Promise<{ category: string; provider?: string | undefined; maskedMatch: string } | null>;
  // Full-mode resolve to the raw value. Null when unavailable or refused.
  reveal(token: string): Promise<string | null>;
}

export interface TransformResult {
  // The replacement for this delta; null means emit nothing (the delta is
  // unchanged and no held-back tail was pending).
  display: string | null;
  carry: DisplayCarry;
}

const POINTER_HEAD = '[[aka:';
const BASE32_CHARS = /^[A-Z2-7]*$/;
const CATEGORIES: readonly string[] = DetectionCategory.options;

// Upper bound on a held tail. The longest well-formed pointer is ~72 chars
// (longest category + maximal key-version segment); anything longer being held
// would mean the prefix check has gone wrong, so flush instead of buffering.
export const MAX_POINTER_LEN = 96;

// Upper bound on a held trailing backtick/tilde run. A longer run flushes —
// it has already opened whatever fence it can open.
const MAX_MARKER_HOLD = 8;

// Whether `s` is a prefix of some string the pointer grammar accepts:
// `[[aka:<category>:<b32{2,7}>.<b32{26}>.<b32{16}>]]`. Checked segment by
// segment so a lookalike (unknown category, oversized segment) stops being
// held the moment it diverges from the grammar.
function isPointerPrefix(s: string): boolean {
  if (s.length <= POINTER_HEAD.length) return POINTER_HEAD.startsWith(s);
  if (!s.startsWith(POINTER_HEAD)) return false;
  const rest = s.slice(POINTER_HEAD.length);
  const colon = rest.indexOf(':');
  if (colon === -1) return CATEGORIES.some((c) => c.startsWith(rest));
  if (!CATEGORIES.includes(rest.slice(0, colon))) return false;

  const body = rest.slice(colon + 1);
  const parts = body.split('.');
  const keyVersion = parts[0] ?? '';
  if (parts.length === 1) return keyVersion.length <= 7 && BASE32_CHARS.test(keyVersion);
  if (parts.length > 3) return false;
  if (keyVersion.length < 2 || keyVersion.length > 7 || !BASE32_CHARS.test(keyVersion)) {
    return false;
  }
  const pointerId = parts[1] ?? '';
  if (parts.length === 2) return pointerId.length <= 26 && BASE32_CHARS.test(pointerId);
  if (pointerId.length !== 26 || !BASE32_CHARS.test(pointerId)) return false;

  // The tag segment may already carry one or both closing brackets.
  let tag = parts[2] ?? '';
  let brackets = 0;
  while (tag.endsWith(']')) {
    tag = tag.slice(0, -1);
    brackets += 1;
  }
  if (brackets > 2 || !BASE32_CHARS.test(tag)) return false;
  return brackets === 0 ? tag.length <= 16 : tag.length === 16;
}

// The category segment of a well-formed pointer token, read from the token
// text itself so a badge can be built even when the descriptor lookup fails.
function tokenCategory(token: string): string {
  const colon = token.indexOf(':', POINTER_HEAD.length);
  return colon === -1 ? 'unknown' : token.slice(POINTER_HEAD.length, colon);
}

// Markdown-region walker over the emitted stream. Deliberately conservative:
// where a delta boundary leaves the state ambiguous, the walk errs toward
// "protected", which only ever masks a pointer that full mode might have
// revealed — never the reverse.
interface RegionState {
  fence: FenceState | null;
  tickOpen: boolean;
  lineQuoted: boolean;
  lineSeen: boolean;
  lineIndent: number;
}

// Whether the rest of the current line, as far as this segment shows it, is
// blank up to a newline. Without a visible newline the answer is false: a
// closing fence is only honored once the whole closing line has been seen
// (keeping the fence open masks longer, never reveals early).
function restOfLineIsBlank(text: string, from: number): boolean {
  for (let k = from; k < text.length; k += 1) {
    const c = text[k];
    if (c === '\n') return true;
    if (c !== ' ' && c !== '\t' && c !== '\r') return false;
  }
  return false;
}

function advanceRegions(state: RegionState, text: string): void {
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '\n') {
      state.lineQuoted = false;
      state.lineSeen = false;
      state.lineIndent = 0;
      i += 1;
      continue;
    }
    if (ch === '`' || ch === '~') {
      let end = i + 1;
      while (end < text.length && text[end] === ch) end += 1;
      const runLen = end - i;
      const atLineStart = !state.lineSeen && state.lineIndent <= 3;
      if (state.fence !== null) {
        // Inside a fence every marker is content except a matching closer: a
        // line-start run of the opening character, at least as long as the
        // opener, with nothing else on its line.
        if (
          atLineStart &&
          ch === state.fence.char &&
          runLen >= state.fence.len &&
          restOfLineIsBlank(text, end)
        ) {
          state.fence = null;
        }
      } else if (atLineStart && runLen >= 3) {
        state.fence = { char: ch, len: runLen };
        state.tickOpen = false;
      } else if (ch === '`' && runLen % 2 === 1) {
        // Mid-line backtick runs pair off as inline code delimiters; an odd
        // run flips the span state. Mid-line runs never touch fence state.
        state.tickOpen = !state.tickOpen;
      }
      state.lineSeen = true;
      i = end;
      continue;
    }
    if (!state.lineSeen) {
      if (ch === ' ') {
        state.lineIndent += 1;
        i += 1;
        continue;
      }
      if (ch === '\t') {
        state.lineIndent += 4;
        i += 1;
        continue;
      }
      state.lineSeen = true;
      if (ch === '>') state.lineQuoted = true;
    }
    i += 1;
  }
}

// The masked badge: descriptor data only — no raw value, no de-reference.
async function maskedBadge(token: string, deps: DisplayDeps): Promise<string> {
  let descriptor: Awaited<ReturnType<DisplayDeps['describe']>>;
  try {
    descriptor = await deps.describe(token);
  } catch {
    descriptor = null;
  }
  if (descriptor === null) return `[scrubbed:${tokenCategory(token)}]`;
  const label = descriptor.provider
    ? `${descriptor.category}/${descriptor.provider}`
    : descriptor.category;
  return `[scrubbed:${label} ${descriptor.maskedMatch}]`;
}

/**
 * Rewrite one streaming delta. `carry` is the state returned by the previous
 * call for the same content block (EMPTY_CARRY for the first delta); `final`
 * marks the block's last delta, which flushes any held tail verbatim.
 */
export async function transformDelta(
  delta: string,
  carry: DisplayCarry,
  final: boolean,
  deps: DisplayDeps,
): Promise<TransformResult> {
  if (deps.mode === 'off') return { display: null, carry: EMPTY_CARRY };

  const buf = carry.tail + delta;
  const hadTail = carry.tail.length > 0;
  const matches = [...buf.matchAll(pointerTokenScanner())];

  // Hold back a buffer suffix that may be the opening of a pointer, so the
  // next delta can complete it. Never held past the block end, past
  // MAX_POINTER_LEN, or once the suffix diverges from the pointer grammar.
  let tailStart = buf.length;
  if (!final) {
    const last = matches[matches.length - 1];
    const searchFrom = last === undefined ? 0 : last.index + last[0].length;
    for (let j = buf.indexOf('[', searchFrom); j !== -1; j = buf.indexOf('[', j + 1)) {
      const suffix = buf.slice(j);
      if (suffix.length <= MAX_POINTER_LEN && isPointerPrefix(suffix)) {
        tailStart = j;
        break;
      }
    }
    // A trailing backtick/tilde run could still grow into (or extend) a fence
    // marker in the next delta — an opener split as '``' + '`\n' must not be
    // walked as two short runs. Hold it exactly like a pointer prefix; a run
    // past MAX_MARKER_HOLD flushes.
    if (tailStart === buf.length && buf.length > 0) {
      const lastCh = buf[buf.length - 1];
      if (lastCh === '`' || lastCh === '~') {
        let start = buf.length - 1;
        while (start > 0 && buf[start - 1] === lastCh) start -= 1;
        if (buf.length - start <= MAX_MARKER_HOLD) tailStart = start;
      }
    }
  }

  const state: RegionState = {
    fence: carry.fence,
    tickOpen: carry.tickOpen,
    lineQuoted: carry.lineQuoted,
    lineSeen: carry.lineSeen,
    lineIndent: carry.lineIndent,
  };
  let out = '';
  let pos = 0;
  let replaced = 0;
  let revealedCount = carry.revealedCount;

  for (const match of matches) {
    const token = match[0];
    const literal = buf.slice(pos, match.index);
    advanceRegions(state, literal);
    out += literal;

    // Fenced, inline-code, and quoted regions render masked even in full
    // mode — they are exactly what users copy elsewhere — and the per-message
    // cap bounds an injected "echo every pointer" to a couple of values.
    const shielded = state.fence !== null || state.tickOpen || state.lineQuoted;
    let replacement: string;
    if (deps.mode === 'full' && !shielded && revealedCount < deps.maxRevealsPerMessage) {
      let value: string | null;
      try {
        value = await deps.reveal(token);
      } catch {
        value = null;
      }
      if (value === null) {
        replacement = await maskedBadge(token, deps);
      } else {
        revealedCount += 1;
        replacement = `${value} [scrubbed:${tokenCategory(token)}]`;
      }
    } else {
      replacement = await maskedBadge(token, deps);
    }
    // Region state advances over what is EMITTED (a revealed value could
    // itself contain backticks), not over the pointer text it replaced.
    advanceRegions(state, replacement);
    out += replacement;
    replaced += 1;
    pos = match.index + token.length;
  }

  const trailing = buf.slice(pos, tailStart);
  advanceRegions(state, trailing);
  out += trailing;

  const nextCarry: DisplayCarry = {
    tail: buf.slice(tailStart),
    fence: state.fence,
    tickOpen: state.tickOpen,
    lineQuoted: state.lineQuoted,
    lineSeen: state.lineSeen,
    lineIndent: state.lineIndent,
    revealedCount,
  };

  // Fast path: the delta is exactly what would be emitted and nothing is
  // held, so emitting nothing lets the original render. The carry still
  // updates — region toggles in a clean delta matter to later pointers.
  if (replaced === 0 && !hadTail && nextCarry.tail === '') {
    return { display: null, carry: nextCarry };
  }
  return { display: out, carry: nextCarry };
}

// ─── Carry persistence ──────────────────────────────────────────────────────
//
// One carry file PER SESSION under the data dir, so concurrent sessions never
// clobber each other's held text. Inside the file the state is split by key:
// the tail and region state belong to one content block
// (session/message/index) and die with it, while the reveal count belongs to
// the whole message (session/message) so an N-block message still gets one
// shared cap. Only counts, region flags, and pointer-prefix text are ever
// written — never a revealed value. Everything here degrades silently: a
// lost carry means raw pointer display, never a broken session.

const CARRY_FILE_PREFIX = 'display-carry';
const STALE_CARRY_MS = 15 * 60 * 1000;

export interface CarryKeys {
  // session/message/index — owns the tail and region state.
  blockKey: string;
  // session/message — owns the reveal count.
  messageKey: string;
}

export function carryFilePath(dataDir: string, sessionId: string): string {
  const safe = sessionId.replace(/[^A-Za-z0-9_-]/g, '_').slice(0, 80);
  return join(dataDir, `${CARRY_FILE_PREFIX}-${safe === '' ? 'session' : safe}.json`);
}

function parseFence(value: unknown): FenceState | null {
  if (typeof value !== 'object' || value === null) return null;
  const fence = value as Record<string, unknown>;
  if (fence.char !== '`' && fence.char !== '~') return null;
  if (typeof fence.len !== 'number' || !Number.isInteger(fence.len) || fence.len < 3) return null;
  return { char: fence.char, len: fence.len };
}

export function loadCarry(file: string, keys: CarryKeys): DisplayCarry {
  try {
    const parsed: unknown = JSON.parse(readFileSync(file, 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return EMPTY_CARRY;
    const record = parsed as Record<string, unknown>;
    const revealedCount =
      record.messageKey === keys.messageKey &&
      typeof record.revealedCount === 'number' &&
      Number.isFinite(record.revealedCount)
        ? record.revealedCount
        : 0;
    let block: Omit<DisplayCarry, 'revealedCount'> = EMPTY_CARRY;
    if (record.blockKey === keys.blockKey && typeof record.block === 'object') {
      const raw = (record.block ?? {}) as Record<string, unknown>;
      block = {
        tail: typeof raw.tail === 'string' ? raw.tail : '',
        fence: parseFence(raw.fence),
        tickOpen: raw.tickOpen === true,
        lineQuoted: raw.lineQuoted === true,
        lineSeen: raw.lineSeen === true,
        lineIndent:
          typeof raw.lineIndent === 'number' &&
          Number.isFinite(raw.lineIndent) &&
          raw.lineIndent >= 0
            ? raw.lineIndent
            : 0,
      };
    }
    return {
      tail: block.tail,
      fence: block.fence,
      tickOpen: block.tickOpen,
      lineQuoted: block.lineQuoted,
      lineSeen: block.lineSeen,
      lineIndent: block.lineIndent,
      revealedCount,
    };
  } catch {
    return EMPTY_CARRY;
  }
}

// Single-record overwrite, atomic via tmp+rename, owner-only mode. A null
// blockKey stores a message-only record (reveal count with no block state).
function writeCarryRecord(
  file: string,
  blockKey: string | null,
  messageKey: string,
  carry: DisplayCarry,
): void {
  const record = {
    blockKey,
    messageKey,
    block: {
      tail: carry.tail,
      fence: carry.fence,
      tickOpen: carry.tickOpen,
      lineQuoted: carry.lineQuoted,
      lineSeen: carry.lineSeen,
      lineIndent: carry.lineIndent,
    },
    revealedCount: carry.revealedCount,
    updatedAt: new Date().toISOString(),
  };
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, JSON.stringify(record), { mode: 0o600 });
  renameSync(tmp, file);
}

// Reap carry files no session has touched in a while — abandoned sessions
// must not accumulate files under the data dir.
function removeStaleCarryFiles(dir: string, keep: string): void {
  try {
    const cutoff = Date.now() - STALE_CARRY_MS;
    for (const name of readdirSync(dir)) {
      if (!name.startsWith(CARRY_FILE_PREFIX) || !name.endsWith('.json')) continue;
      const path = join(dir, name);
      if (path === keep) continue;
      try {
        if (statSync(path).mtimeMs < cutoff) rmSync(path, { force: true });
      } catch {
        // A vanished or unreadable entry is someone else's live file.
      }
    }
  } catch {
    // Cleanup is opportunistic; a failed listing changes nothing.
  }
}

export function saveCarry(file: string, keys: CarryKeys, carry: DisplayCarry): void {
  try {
    const dir = dirname(file);
    mkdirSync(dir, { recursive: true });
    removeStaleCarryFiles(dir, file);
    writeCarryRecord(file, keys.blockKey, keys.messageKey, carry);
  } catch {
    // Carry loss is a display degrade, never a crash.
  }
}

// Block end. The reveal count outlives the block — it caps the whole
// message — so a message that has revealed keeps a message-only record.
// Otherwise the file is removed, but only after confirming it still belongs
// to this block or message: a racing newer block's held text must never be
// destroyed by a stale final.
export function finalizeCarry(file: string, keys: CarryKeys, carry: DisplayCarry): void {
  try {
    if (carry.revealedCount > 0) {
      mkdirSync(dirname(file), { recursive: true });
      writeCarryRecord(file, null, keys.messageKey, {
        ...EMPTY_CARRY,
        revealedCount: carry.revealedCount,
      });
      return;
    }
    let owned = true;
    try {
      const parsed: unknown = JSON.parse(readFileSync(file, 'utf8'));
      if (typeof parsed === 'object' && parsed !== null) {
        const record = parsed as Record<string, unknown>;
        owned = record.blockKey === keys.blockKey || record.messageKey === keys.messageKey;
      }
    } catch {
      // Absent or unreadable: removing is a no-op or clears a corrupt file.
    }
    if (owned) rmSync(file, { force: true });
  } catch {
    // A leftover carry file is keyed and simply won't match the next block.
  }
}
