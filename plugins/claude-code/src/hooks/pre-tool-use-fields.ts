// Which tool_input fields carry text worth scanning before a tool runs, and
// how to address them for write-back. The PostToolUse mirror is
// tool-response.ts; the two share the path primitives in paths.ts.
//
// `executable` marks text the host acts on directly (a shell command, a URL to
// fetch): masking inside it doesn't remove the sensitive value from what
// happens — it CHANGES what happens, because the spliced-in `[REDACTED:…]`
// placeholder runs as a different command (a masked SQL predicate matches
// different rows, a masked URL requests a different resource; see the incident
// pinned in pre-tool-use-decision.test.ts). A redact decision on such a field
// escalates to deny rather than rewriting. Write/Edit content and the analysis
// prompts are data handed onward — the masked form IS the intended end state —
// so in-place redaction is correct there and only there.
//
// Kept free of I/O and hook wiring so it unit-tests without a hook process.
import type { EventKind, FindingContextBasis } from '@akasecurity/schema';

import { mayNameCredentialFile } from './credential-name-hints.ts';
import type { PathSegment } from './paths.ts';
import { stringAtPath } from './paths.ts';

export interface ScannableField {
  path: PathSegment[];
  executable: boolean;
  /**
   * Present only for a synthetic scan unit whose text was computed during
   * the MCP walk rather than addressable at `path` in the tool input — the
   * joined-keys chunks `mcpFields` appends (see below). Never resolve or
   * write one of these back through `path`: there is no such position in the
   * real payload. Use `fieldText`/`isSyntheticField` below rather than
   * checking `.text` directly, so every call site agrees on what "synthetic"
   * means. `decidePreToolUse` also refuses to rewrite one of these itself
   * (belt-and-braces beside `executable: true` below — see its own comment).
   */
  text?: string;
}

/** Whether `field` is a synthetic scan unit — see ScannableField.text. */
export function isSyntheticField(field: ScannableField): boolean {
  return field.text !== undefined;
}

/**
 * The text `field` addresses: its precomputed text for a synthetic unit, or
 * whatever string sits at `field.path` in `toolInput`. The one place this
 * resolution happens, so a future synthetic unit can't be handled at one
 * call site and missed at another.
 */
export function fieldText(field: ScannableField, toolInput: unknown): string | undefined {
  return field.text ?? stringAtPath(toolInput, field.path);
}

// Tools whose scannable text is durable content they author, recorded as
// 'code_change'. Everything else this hook scans is text a tool acts on and is
// recorded as 'tool_use'.
const CODE_CHANGE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);

const STATIC_FIELDS: Record<string, readonly ScannableField[]> = {
  Bash: [{ path: ['command'], executable: true }],
  Write: [{ path: ['content'], executable: false }],
  Edit: [{ path: ['new_string'], executable: false }],
  // WebFetch is the classic exfil channel: a secret spliced into the fetched
  // URL leaves the machine before any post-hook can see it. The URL executes
  // (it IS the request), so redact escalates to deny; the prompt is text
  // handed to the fetch-analysis model and redacts in place like Write/Edit.
  WebFetch: [
    { path: ['url'], executable: true },
    { path: ['prompt'], executable: false },
  ],
  // The replacement cell body. `old_string`'s NotebookEdit counterpart does not
  // exist — the cell is addressed by id — so there is no match text to protect
  // here the way MultiEdit needs.
  NotebookEdit: [{ path: ['new_source'], executable: false }],
  // A subagent prompt stays inside the model boundary rather than leaving the
  // machine, but it is still a channel a secret can ride into a context the
  // user never sees. Scanned as data: the masked prompt is a coherent
  // instruction, so redaction is the intended end state and block still blocks.
  //
  // BOTH spellings. The harness renamed this tool — older builds send `Task`,
  // current ones send `Agent` — and a table naming only the old one scans
  // nothing at all on a current build, silently, because an unknown tool yields
  // no fields and the hook returns before any decision.
  Task: [{ path: ['prompt'], executable: false }],
  Agent: [{ path: ['prompt'], executable: false }],
};

// Tools whose input names a file the tool will read, addressed by the field
// holding the path. The path is checked against the credential-file rules
// before the read happens; the content is PostToolUse's to scan. Executable:
// a masked path reads a different file, so a redact on it degrades to the
// workspace's redactFallback like any other executable field.
const PATH_FIELDS: Record<string, readonly ScannableField[]> = {
  Read: [{ path: ['file_path'], executable: true }],
  Grep: [{ path: ['path'], executable: true }],
};

// A Read or Grep path is captured only when it may name a credential file
// (credential-name-hints.ts), which keeps the common Read (source files, docs,
// logs) from paying a capture, and from recording a path finding, for a path no
// credential rule is about. The manifest's path gate filters on the same hints
// before node starts.

// Bounds on the MCP walk. A tool payload can be arbitrarily large and the hook
// has a 10s budget: past these limits it scans what fits and lets the rest
// through, which degrades to "some coverage" rather than a timeout — and a
// timed-out hook fails open, allowing the whole call unscanned, including the
// leaves that WERE flagged. Partial coverage beats none, so these err low.
//
// The leaf COUNT bound is the one that protects the budget. Cost is per leaf,
// not per byte: pre-tool-use.ts awaits one runtime.capture() per field, in
// sequence. The char bounds alone leave that unbounded — five million
// one-char leaves sit exactly at MCP_MAX_TOTAL_CHARS while costing five
// million detection passes. That is both a robustness gap (a legitimate bulk
// payload) and an evasion path (pad the arguments with cheap leaves until the
// hook times out and everything is allowed).
//
// 2000 is measured, not guessed: a capture of a benign leaf costs ~0.04ms and
// one carrying a finding ~0.19ms (the full mask + event + ledger write), so
// the worst case is ~0.4s of scanning — an order of magnitude of headroom on
// slower hardware. Real payloads sit far below it (a chat post is tens of
// leaves; a 100-record bulk write with 5 fields each is 500).
const MCP_MAX_DEPTH = 6;
const MCP_MAX_LEAF_CHARS = 1_000_000;
const MCP_MAX_TOTAL_CHARS = 5_000_000;
const MCP_MAX_LEAF_COUNT = 2_000;

// The most DEDICATED (one-object-per-chunk) joined-keys scan units one MCP
// call ever produces. Unlike MCP_MAX_LEAF_COUNT this bounds a COUNT of
// chunks, not of captures avoided: each dedicated chunk is one capture(), and
// each is scoped to a single object's own keys (see MCP_KEY_JOIN's comment on
// why), so a payload shaped as many small sibling objects — an array of 1,000
// two-key records — would otherwise cost close to one capture per object. 200
// keeps that worst case at a few tens of milliseconds (measured ~0.19ms per
// capture, so 200 * 0.19ms ≈ 38ms), far under the leaf budget's own ~0.4s
// headroom, while realistic payloads (a handful of nested objects) never come
// close to it. mcpKeyChunks also dedupes identical chunk TEXT before counting
// against this, so the common shape of that array — every record sharing the
// same key names — collapses to one chunk rather than 1,000.
//
// Past this cap, mcpKeyChunks does NOT drop the remaining groups' keys — an
// earlier version did, and 200 single-key objects (about 1.4 KB) was cheap
// enough to bury a secret key placed after them, far cheaper than the
// 2,000-leaf padding the value walk itself requires. Instead their keys are
// packed together into shared OVERFLOW chunks, still bounded (by the shared
// char budget, not by count — see mcpKeyChunks), so coverage is kept and the
// capture count stays predictable. The cost is the one-object-per-chunk
// separation MCP_MAX_KEY_GROUPS exists to preserve (see mcpFields' own
// comment on cross-object corroboration): two unrelated objects' keys CAN
// share an overflow chunk, so a `requiresNearby` rule could corroborate
// across them for the overflow tail specifically. Real payloads this wide
// are already rare enough that reaching overflow at all is uncommon.
const MCP_MAX_KEY_GROUPS = 200;

// Separates keys inside a joined-keys chunk. Two requirements, not one:
//
// 1. Not `\s`-matched. A key requires no separator wider than one non-`\s`
//    character to defeat, but several bundled rules match keyword+value with
//    `\s*`/`[:\s]*` in the pattern itself — `\s` matches `\n` — so 'member' +
//    'id' + 'status', joined by '\n' alone, reads as "member\nid\nstatus" to
//    such a pattern and core-phi/member-id fires on three ordinary sibling
//    keys that individually match nothing.
// 2. A `\n`. `.` (without the `s`/dotall flag) and `[^\n]` both stop at a
//    line terminator, so a lone non-`\s` character would still let a
//    `.`-spanning or `[^\n]`-spanning pattern read across it.
//
// '\n' alone satisfies (2) but not (1); a lone control character satisfies
// (1) but not (2). Together, '\n\u0000' (a U+0000 NUL immediately after the
// newline) satisfies both — verified against every bundled rule's `examples`
// plus the three fusions above (see pre-tool-use-fields.test.ts).
//
// Exported so a test builds its expected joined text from this constant
// rather than a duplicated literal that can drift from it unnoticed; a test
// asserting the separator's SECURITY property (which characters it must
// defeat) still spells the raw bytes, since that property has to hold
// against the actual bytes rather than against whatever this constant says.
export const MCP_KEY_JOIN = '\n\u0000';

// The path segment every joined-keys chunk is addressed under. Never
// dereferenced — see ScannableField.text — so it only has to be stable and
// legible in a debugger, never resolvable against the real tool input.
const MCP_KEYS_PATH_SEGMENT = '<mcp-object-keys>';

/**
 * Every string leaf of an MCP tool's arguments, bounded by depth and size —
 * PLUS every string object key encountered along the way, packed into a few
 * combined scan units per originating object (see mcpKeyChunks below).
 *
 * All of them are marked executable, i.e. a redact decision denies instead of
 * rewriting. An MCP tool's schema is defined by whatever server is on the other
 * end, so a string could be a message body (safe to mask) or a query, an id, or
 * a path (masking changes what happens). We can't tell which, and guessing
 * wrong silently changes semantics — the exact failure the executable rule
 * exists to prevent. Deny is visible and at least as strong as the policy's
 * redact, and the runtime has already ledgered the values, so the
 * `aka exception approve` escape hatch stays available. A key is no
 * different: there is no schema telling us a key can never itself be the
 * secret (a bearer token used as a map key, a credential as an idempotency
 * key), and unlike a value there is no way to rewrite a key in place at all —
 * so a resolved redact on a joined-keys chunk degrades to the workspace's
 * `redactFallback` exactly like any other unrewritable field, rather than
 * silently allowing the call through.
 *
 * Keys are grouped by their OWN parent object, never pooled across the whole
 * payload: a `requiresNearby` rule corroborates any match within a fixed
 * character window of another, and pooling every key into one string put an
 * unrelated part of the payload's key (`billing`) inside a completely
 * different part's proximity window (an `orders` id keyed `12345`, which
 * alone matches nothing), flagging it as a ZIP code. Two sibling keys of the
 * SAME object are still joined into one unit — see mcpKeyChunks — since they
 * already describe one coherent piece of the payload the way a value never
 * spans two unrelated fields either.
 *
 * Keys are charged against the shared MCP_MAX_TOTAL_CHARS budget only AFTER
 * the whole value walk finishes (see the call to mcpKeyChunks below), from
 * whatever the values left: a key can add coverage past what values already
 * claimed, but can never evict a value the walk would otherwise have scanned.
 */
function mcpFields(toolInput: Record<string, unknown>): ScannableField[] {
  const fields: ScannableField[] = [];
  // One entry per object visited, each holding that object's own string
  // keys in encounter order — never merged with another object's.
  const groups: string[][] = [];
  let remaining = MCP_MAX_TOTAL_CHARS;

  const walk = (node: unknown, path: PathSegment[], depth: number): void => {
    if (remaining <= 0 || depth > MCP_MAX_DEPTH || fields.length >= MCP_MAX_LEAF_COUNT) return;
    if (typeof node === 'string') {
      if (node === '' || node.length > MCP_MAX_LEAF_CHARS) return;
      remaining -= node.length;
      if (remaining < 0) return;
      fields.push({ path, executable: true });
      return;
    }
    if (Array.isArray(node)) {
      for (const [index, item] of node.entries()) walk(item, [...path, index], depth + 1);
      return;
    }
    if (typeof node === 'object' && node !== null) {
      // Symbols and array indices never reach here — only a real object's
      // own string keys do, at every depth the walk still visits an object
      // AT ALL. That is not exactly the set of positions whose values are
      // visited: once a sibling entry's own recursion exhausts
      // MCP_MAX_LEAF_COUNT, this for-loop still finishes collecting every
      // REMAINING sibling key at THIS level (only descending into each
      // one's value is what the top-of-walk guard then skips), and a key of
      // an object reached at MCP_MAX_DEPTH is collected while that same
      // object's own values (one level deeper) are not.
      //
      // Pushed in WALK order — this object's own group, THEN its children's,
      // never the reverse. mcpKeyChunks spends its dedicated per-object
      // chunks (MCP_MAX_KEY_GROUPS) on `groups` in array order, so pushing a
      // parent's group only after recursing into every child would make the
      // outermost, most likely to matter keys the LAST group recorded — and
      // therefore the first one a limit further down drops or shares a chunk.
      const entries = Object.entries(node);
      const keys = entries.filter(([key]) => key.length > 0).map(([key]) => key);
      if (keys.length > 0) groups.push(keys);
      for (const [key, value] of entries) walk(value, [...path, key], depth + 1);
    }
  };

  walk(toolInput, [], 0);
  fields.push(...mcpKeyChunks(groups, Math.max(remaining, 0)));
  return fields;
}

/**
 * Bin-packs each object's own collected keys into as few combined scan units
 * as fit under the per-unit size cap, each addressed by a synthetic path
 * (never dereferenced — see ScannableField.text). WHILE UNDER THE
 * MCP_MAX_KEY_GROUPS CAP, a chunk never mixes keys from two different
 * objects — see mcpFields' own comment on why — so a large object's keys may
 * still span more than one chunk, but never two objects' keys share one. Past
 * the cap, that separation is what gives way (see MCP_MAX_KEY_GROUPS's own
 * comment): a group's keys are appended to whatever chunk is already open
 * instead of starting a fresh one, so they are still scanned and still
 * charged, just no longer isolated from a different object's.
 *
 * NOT one unit per key: that would roughly double the unit count for a
 * typical payload and can trip MCP_MAX_LEAF_COUNT on its own, a bound whose
 * whole point is capping the number of capture() calls a call this hook sees
 * pays for. A few chunks cost only a few more — bounded overall by
 * MCP_MAX_KEY_GROUPS for the dedicated ones, and by the shared char budget
 * alone for whatever overflow follows.
 *
 * Two chunks that end up with the exact same text (two different objects
 * carrying the same set of keys — a paginated array of identically-shaped
 * records; or, past the cap, two overflow chunks that happened to fill
 * identically) produce an identical verdict every time — the repeat is
 * deduped rather than captured again, which is what keeps a long array of
 * uniformly-shaped objects from costing one chunk per record.
 *
 * Each key is packed WHOLE into its chunk — never split at a fixed offset —
 * because a fixed cut lets an attacker pad a key so the split falls in the
 * middle of the next one, letting a secret key straddle a chunk boundary
 * unscanned on either side. Bin-packing instead starts a fresh chunk the
 * moment a key would no longer fit.
 */
function mcpKeyChunks(groups: readonly string[][], budget: number): ScannableField[] {
  const chunks: ScannableField[] = [];
  const seenChunkText = new Set<string>();
  let remaining = budget;
  let current: string[] = [];
  let currentLen = 0;
  // How many DEDICATED (one-object-per-chunk) chunks exist so far. Once this
  // reaches MCP_MAX_KEY_GROUPS, a later group no longer opens its own fresh
  // chunk — see the per-group boundary below.
  let dedicatedChunks = 0;

  // The joined length `current` would have with `key` appended — the one
  // formula both the size-cap check and the budget charge read, so the two
  // can never drift apart the way recomputing each separately once did.
  const lengthWith = (key: string): number =>
    current.length === 0 ? key.length : currentLen + MCP_KEY_JOIN.length + key.length;

  const flush = (): void => {
    if (current.length === 0) return;
    const text = current.join(MCP_KEY_JOIN);
    current = [];
    currentLen = 0;
    if (seenChunkText.has(text)) return;
    seenChunkText.add(text);
    chunks.push({ path: [MCP_KEYS_PATH_SEGMENT, chunks.length], executable: true, text });
  };

  outer: for (const group of groups) {
    // A fresh chunk boundary per object, while under the dedicated-chunk
    // cap — see mcpFields' own comment on why two objects' keys must never
    // share one scan unit there. Past the cap, this group's keys fall
    // through into whatever chunk `current` already holds instead: still
    // scanned, still charged, just no longer isolated from another
    // object's — see MCP_MAX_KEY_GROUPS's own comment.
    if (dedicatedChunks < MCP_MAX_KEY_GROUPS) {
      flush();
      dedicatedChunks = chunks.length;
    }
    for (const key of group) {
      // Over-long key: dropped uncharged, like an over-long value leaf.
      if (key.length > MCP_MAX_LEAF_CHARS) continue;
      if (current.length > 0 && lengthWith(key) > MCP_MAX_LEAF_CHARS) flush();
      const grown = lengthWith(key);
      const cost = grown - currentLen;
      // Budget exhausted: halt entirely, like the value walk does at
      // `remaining <= 0` — a later, smaller key fitting what's left would
      // scan out of the encounter order every other bound in this file
      // respects.
      if (remaining <= 0 || cost > remaining) break outer;
      remaining -= cost;
      current.push(key);
      currentLen = grown;
    }
  }
  flush();

  return chunks;
}

/** One field per edit's replacement text. `old_string` is deliberately absent:
 * it is existing file content used as an exact-match anchor, so masking inside
 * it makes the edit match nothing and the tool call fail — breaking the session
 * the plugin promises never to break. It is not text the agent authored, so it
 * carries no secret the agent is introducing. */
function multiEditFields(toolInput: Record<string, unknown>): ScannableField[] {
  const edits = toolInput.edits;
  if (!Array.isArray(edits)) return [];
  return edits.map((_, index) => ({
    path: ['edits', index, 'new_string'],
    executable: false,
  }));
}

/**
 * The tools whose scannable fields come from the STATIC and PATH tables above.
 *
 * Not every tool this hook covers: `MultiEdit` and the `mcp__*` family are
 * handled by the dynamic branches below and appear here in neither case. So a
 * manifest check derived from this catches a tool added to the table and
 * forgotten in the matcher, and nothing about a dynamic handler — which is why
 * the tools reached that way are named in the manifest test directly.
 *
 * Exported for that check: a tool named here that the matcher does not select
 * is a tool the hook is never spawned for, which looks exactly like a tool with
 * nothing to scan.
 */
export const SCANNED_TOOL_NAMES: readonly string[] = [
  ...Object.keys(STATIC_FIELDS),
  ...Object.keys(PATH_FIELDS),
];

/**
 * The scannable fields of a tool's input, each addressing a non-empty string.
 * Empty for a tool this hook has no coverage for, which the caller treats as
 * "no opinion" before opening the store — a cost pre-tool-use.ts's own
 * comment used to describe as free for every MCP call whose values were all
 * non-string. That is no longer most MCP calls: an object key is scannable
 * content too now, so `{ limit: 10 }` or `{ page: 2, archived: false }` — no
 * scannable VALUE, but real keys — yields a joined-keys chunk and pays the
 * full store-open cost the empty-fields path used to skip. The alternative
 * (only emit a key chunk when the payload also has a scannable value) would
 * silently reopen the exact gap this hook exists to close for a payload
 * shaped `{ "<secret>": 123 }` or `{ "<secret>": true }` — a non-string
 * value beside the secret key, with nothing else in the call to save it —
 * so full coverage was kept and the free path narrows to a tool_input with
 * no string keys at all (`{}`, or every key empty).
 */
export function scannableInputFields(
  toolName: string,
  toolInput: Record<string, unknown>,
): ScannableField[] {
  if (Object.hasOwn(PATH_FIELDS, toolName)) {
    return (PATH_FIELDS[toolName] ?? []).filter((field) => {
      const text = fieldText(field, toolInput);
      return text !== undefined && mayNameCredentialFile(text);
    });
  }
  const candidates = toolName.startsWith('mcp__')
    ? mcpFields(toolInput)
    : toolName === 'MultiEdit'
      ? multiEditFields(toolInput)
      : // hasOwn guard: a bare index would resolve Object.prototype members for
        // tool names like 'constructor' (non-nullish, so ?? does not catch them).
        ((Object.hasOwn(STATIC_FIELDS, toolName) ? STATIC_FIELDS[toolName] : undefined) ?? []);

  // Empty and absent leaves are dropped here rather than at each call site, so
  // every returned field is known to resolve to text worth scanning.
  return candidates.filter((field) => {
    const text = fieldText(field, toolInput);
    return text !== undefined && text !== '';
  });
}

/** The event kind a tool's scanned text is recorded under. */
export function inputEventKind(toolName: string): EventKind {
  return CODE_CHANGE_TOOLS.has(toolName) ? 'code_change' : 'tool_use';
}

/** What a finding's line counts in for this tool's scanned field: a Write's
 * `content` is the whole file, so its lines are the file's own; every other
 * field (an edit's replacement text, a command) is a fragment. */
export function inputLineBasis(toolName: string): FindingContextBasis {
  return toolName === 'Write' ? 'file' : 'excerpt';
}

/** The file a tool's input targets, for metadata attribution. NotebookEdit
 * names it notebook_path; without this its findings would carry no file and
 * extension-scoped rules would never apply to them. */
export function inputFilePath(toolInput: Record<string, unknown>): string | undefined {
  return stringAtPath(toolInput, ['file_path']) ?? stringAtPath(toolInput, ['notebook_path']);
}
