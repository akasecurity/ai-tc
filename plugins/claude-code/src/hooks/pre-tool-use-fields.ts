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
  Task: [{ path: ['prompt'], executable: false }],
};

// Bounds on the MCP walk. A tool result can be arbitrarily large and the hook
// has a 10s budget: past these limits it scans what fits and lets the rest
// through, which degrades to "some coverage" rather than a timeout — and a
// timed-out hook fails open, allowing everything unscanned.
const MCP_MAX_DEPTH = 6;
const MCP_MAX_LEAF_CHARS = 1_000_000;
const MCP_MAX_TOTAL_CHARS = 5_000_000;

/**
 * Every string leaf of an MCP tool's arguments, bounded by depth and size.
 *
 * All of them are marked executable, i.e. a redact decision denies instead of
 * rewriting. An MCP tool's schema is defined by whatever server is on the other
 * end, so a string could be a message body (safe to mask) or a query, an id, or
 * a path (masking changes what happens). We can't tell which, and guessing
 * wrong silently changes semantics — the exact failure the executable rule
 * exists to prevent. Deny is visible and at least as strong as the policy's
 * redact, and the runtime has already ledgered the values, so the
 * `aka exception approve` escape hatch stays available.
 */
function mcpFields(toolInput: Record<string, unknown>): ScannableField[] {
  const fields: ScannableField[] = [];
  let remaining = MCP_MAX_TOTAL_CHARS;

  const walk = (node: unknown, path: PathSegment[], depth: number): void => {
    if (remaining <= 0 || depth > MCP_MAX_DEPTH) return;
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
      for (const [key, value] of Object.entries(node)) walk(value, [...path, key], depth + 1);
    }
  };

  walk(toolInput, [], 0);
  return fields;
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
  // every returned path is known to resolve to text worth scanning.
  return candidates.filter((field) => {
    const text = stringAtPath(toolInput, field.path);
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
