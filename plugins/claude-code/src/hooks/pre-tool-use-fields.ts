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
import type { EventKind } from '@akasecurity/schema';

import type { PathSegment } from './paths.ts';
import { stringAtPath } from './paths.ts';

export interface ScannableField {
  path: PathSegment[];
  executable: boolean;
  /**
   * Present only for a synthetic scan unit whose text was computed during
   * the MCP walk rather than addressable at `path` in the tool input — the
   * joined-keys chunks `mcpFields` appends (see below). A caller resolves a
   * field's text with `spec.text ?? stringAtPath(toolInput, spec.path)`, and
   * must never attempt to rewrite one of these back through `path`: there is
   * no such position in the real payload, and `executable: true` (below)
   * already keeps a redact on one from ever reaching a rewrite attempt.
   */
  text?: string;
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

// Separates keys inside a joined-keys chunk (see mcpKeyChunks): 'ab' + 'cd'
// packed raw would read 'abcd', a string neither key is; joined with this
// separator it reads 'ab\ncd', so a rule matching only the contiguous form
// cannot fire across a key boundary that was never there in the payload.
const MCP_KEY_JOIN = '\n';

// The path segment every joined-keys chunk is addressed under. Never
// dereferenced — see ScannableField.text — so it only has to be stable and
// legible in a debugger, never resolvable against the real tool input.
const MCP_KEYS_PATH_SEGMENT = '<mcp-object-keys>';

/**
 * Every string leaf of an MCP tool's arguments, bounded by depth and size —
 * PLUS every string object key encountered along the way, packed into a few
 * combined scan units (see mcpKeyChunks below).
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
 * so a resolved redact on the joined-keys chunk degrades to the workspace's
 * `redactFallback` exactly like any other unrewritable field, rather than
 * silently allowing the call through.
 */
function mcpFields(toolInput: Record<string, unknown>): ScannableField[] {
  const fields: ScannableField[] = [];
  const keys: string[] = [];
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
      for (const [key, value] of Object.entries(node)) {
        // Charged against the SAME shared budget a value leaf draws from,
        // and dropped under the same rule an over-long value leaf is: a key
        // this large costs its own capture even alone, so scanning it is no
        // cheaper than scanning an equivalently sized value would be.
        // Symbols and array indices never reach here — only a real object's
        // own string keys do, at every depth the walk still visits, which is
        // exactly the set of positions whose VALUES are also still visited.
        if (remaining > 0 && key.length > 0 && key.length <= MCP_MAX_LEAF_CHARS) {
          remaining -= key.length;
          if (remaining >= 0) keys.push(key);
        }
        walk(value, [...path, key], depth + 1);
      }
    }
  };

  walk(toolInput, [], 0);
  fields.push(...mcpKeyChunks(keys));
  return fields;
}

/**
 * Bin-packs collected object keys into as few combined scan units as fit
 * under the per-unit size cap, each addressed by a synthetic path (never
 * dereferenced — see ScannableField.text).
 *
 * NOT one unit per key: that would roughly double the unit count for a
 * typical payload and can trip MCP_MAX_LEAF_COUNT on its own, a bound whose
 * whole point is capping the number of capture() calls a call this hook sees
 * pays for. A few chunks cost only a few more.
 *
 * Each key is packed WHOLE into its chunk — never split at a fixed offset —
 * because a fixed cut lets an attacker pad a key so the split falls in the
 * middle of the next one, letting a secret key straddle a chunk boundary
 * unscanned on either side. Bin-packing instead starts a fresh chunk the
 * moment a key would no longer fit.
 */
function mcpKeyChunks(keys: readonly string[]): ScannableField[] {
  const chunks: ScannableField[] = [];
  let current: string[] = [];
  let currentLen = 0;

  const flush = (): void => {
    if (current.length === 0) return;
    chunks.push({
      path: [MCP_KEYS_PATH_SEGMENT, chunks.length],
      executable: true,
      text: current.join(MCP_KEY_JOIN),
    });
    current = [];
    currentLen = 0;
  };

  for (const key of keys) {
    const joinChar = current.length > 0 ? MCP_KEY_JOIN.length : 0;
    if (current.length > 0 && currentLen + joinChar + key.length > MCP_MAX_LEAF_CHARS) flush();
    current.push(key);
    currentLen += key.length + (current.length > 1 ? MCP_KEY_JOIN.length : 0);
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
 * The tools whose scannable fields come from the STATIC table above.
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
export const SCANNED_TOOL_NAMES: readonly string[] = Object.keys(STATIC_FIELDS);

/**
 * The scannable fields of a tool's input, each addressing a non-empty string.
 * Empty for a tool this hook has no coverage for, which the caller treats as
 * "no opinion" before opening the store.
 */
export function scannableInputFields(
  toolName: string,
  toolInput: Record<string, unknown>,
): ScannableField[] {
  const candidates = toolName.startsWith('mcp__')
    ? mcpFields(toolInput)
    : toolName === 'MultiEdit'
      ? multiEditFields(toolInput)
      : // hasOwn guard: a bare index would resolve Object.prototype members for
        // tool names like 'constructor' (non-nullish, so ?? does not catch them).
        ((Object.hasOwn(STATIC_FIELDS, toolName) ? STATIC_FIELDS[toolName] : undefined) ?? []);

  // Empty and absent leaves are dropped here rather than at each call site, so
  // every returned field is known to resolve to text worth scanning. A
  // joined-keys chunk carries its own precomputed `text` (mcpKeyChunks never
  // emits an empty one) rather than one resolvable via stringAtPath — see
  // ScannableField.text.
  return candidates.filter((field) => {
    const text = field.text ?? stringAtPath(toolInput, field.path);
    return text !== undefined && text !== '';
  });
}

/** The event kind a tool's scanned text is recorded under. */
export function inputEventKind(toolName: string): EventKind {
  return CODE_CHANGE_TOOLS.has(toolName) ? 'code_change' : 'tool_use';
}

/** The file a tool's input targets, for metadata attribution. NotebookEdit
 * names it notebook_path; without this its findings would carry no file and
 * extension-scoped rules would never apply to them. */
export function inputFilePath(toolInput: Record<string, unknown>): string | undefined {
  return stringAtPath(toolInput, ['file_path']) ?? stringAtPath(toolInput, ['notebook_path']);
}
