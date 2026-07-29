// Pure display-side pointer rendering for the MessageDisplay hook. The hook
// fires once per streaming delta, so a pointer token can arrive split across
// process invocations; this module rewrites each delta and threads a carry —
// the possibly-open pointer tail plus the markdown-region state — between
// calls. All I/O is injected through DisplayDeps, so the whole surface is
// synchronously testable; the hook entry (message-display.ts) owns stdin,
// settings, and carry persistence.
import { DetectionCategory, pointerTokenScanner } from '@akasecurity/schema';

// State threaded between deltas of one content block.
export interface DisplayCarry {
  // A buffer suffix that may be the opening of a pointer token, held back and
  // re-scanned with the next delta.
  tail: string;
  // Markdown-region state of the emitted stream so far: inside a ``` fence,
  // inside an inline `code` span, on a '>'-quoted line.
  fenceOpen: boolean;
  tickOpen: boolean;
  lineQuoted: boolean;
  // Raw values revealed so far in this block (full mode's per-message cap).
  revealedCount: number;
}

export const EMPTY_CARRY: DisplayCarry = Object.freeze({
  tail: '',
  fenceOpen: false,
  tickOpen: false,
  lineQuoted: false,
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
// when a delta boundary makes the state ambiguous (a quote marker arriving in
// a later delta than its line start), the walk errs toward "protected", which
// only ever masks a pointer that full mode might have revealed.
interface RegionState {
  fenceOpen: boolean;
  tickOpen: boolean;
  lineQuoted: boolean;
  // Whether the current line has non-whitespace content yet. Not persisted
  // across deltas; resuming with false lets a '>' at a delta boundary still
  // mark the line quoted (over-protecting, never under-protecting).
  lineSeen: boolean;
}

function advanceRegions(state: RegionState, text: string): void {
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '`') {
      if (text.startsWith('```', i)) {
        state.fenceOpen = !state.fenceOpen;
        state.tickOpen = false;
        state.lineSeen = true;
        i += 3;
        continue;
      }
      if (!state.fenceOpen) state.tickOpen = !state.tickOpen;
      state.lineSeen = true;
      i += 1;
      continue;
    }
    if (ch === '\n') {
      state.lineQuoted = false;
      state.lineSeen = false;
      i += 1;
      continue;
    }
    if (!state.lineSeen) {
      if (ch === ' ' || ch === '\t') {
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
  }

  const state: RegionState = {
    fenceOpen: carry.fenceOpen,
    tickOpen: carry.tickOpen,
    lineQuoted: carry.lineQuoted,
    lineSeen: false,
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
    const shielded = state.fenceOpen || state.tickOpen || state.lineQuoted;
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
    fenceOpen: state.fenceOpen,
    tickOpen: state.tickOpen,
    lineQuoted: state.lineQuoted,
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
