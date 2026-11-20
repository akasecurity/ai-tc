// The text fields of a Cursor value worth scanning: a postToolUse
// `tool_output`, or the arguments of an MCP call on preToolUse.
//
// Cursor documents `tool_output` as a STRING, so the whole value is the text.
// When a value arrives as an OBJECT or ARRAY instead — an MCP call's arguments
// always do, and a host that changed its result envelope might — its string
// leaves are collected by a bounded walk (`leafFields`) rather than dropped, so
// a secret in a structured value is still scanned.
//
// The walk is held to depth, leaf-count and character bounds, and anything
// those bounds leave out is reported as `truncated` so the hook says part of
// the value went unscanned. It reads values only, never object keys.
//
// NOTHING HERE WRITES. Cursor's postToolUse offers a rewrite only for an MCP
// tool's output (`updated_mcp_tool_output`), and it has never been driven
// against a live host. Emitting a rewrite the host ignores would let the audit
// trail record a redaction that did not happen, so the `path` each field
// carries identifies it in a message and is never a cursor for a write.
//
// Kept free of I/O and hook wiring so it unit-tests without a hook process
// (hook entry modules run their body on import and hang vitest collection).

export interface ScannableResponseField {
  /**
   * Key path into the result object; `[]` means the result itself. An array
   * index is spelled as its decimal string.
   */
  path: string[];
  text: string;
}

/** The fields to scan, and whether the walk bounds left any text out of them. */
export interface ResponseFields {
  fields: ScannableResponseField[];
  /**
   * True when a bound below cut some string out of `fields`, so part of the
   * result reached the model without being scanned. Never true on a result
   * this module read whole.
   */
  truncated: boolean;
}

/**
 * Bounds on the walk over an object-shaped result: how deep it goes,
 * how many string leaves it collects, how long one leaf may be, and how many
 * characters all of them add up to. Each collected leaf is one sequential
 * capture, so these bound the work one result can cost the hook. The values
 * are the Claude Code plugin's MCP argument walk's, where a capture of a
 * benign leaf was measured at ~0.04 ms and one carrying a finding at ~0.19 ms,
 * putting the leaf-count ceiling at well under a second of scanning.
 *
 * These caps are the only bound on a leaf under the large-input threshold
 * (`LARGE_INPUT_THRESHOLD_CHARS`): such a leaf is scanned in-process, with no
 * deadline, one capture after another. Only a leaf at or above the threshold
 * is scanned in a worker under the hook's deadline.
 */
export const RESULT_WALK_MAX_DEPTH = 6;
export const RESULT_WALK_MAX_LEAVES = 2_000;
export const RESULT_WALK_MAX_LEAF_CHARS = 1_000_000;
export const RESULT_WALK_MAX_TOTAL_CHARS = 5_000_000;

// Whether a node the walk does not enter could have held text: a non-empty
// string, or a container with anything in it. An empty container, a number or
// an empty string left nothing unscanned.
function couldCarryText(node: unknown): boolean {
  return (
    (typeof node === 'string' && node !== '') ||
    (typeof node === 'object' && node !== null && Object.keys(node).length > 0)
  );
}

/**
 * Every non-empty string leaf of a structured result, under the walk bounds.
 *
 * A leaf the bounds refuse — too deep, too long, past the leaf count or past
 * the character total — marks the collection truncated rather than vanishing,
 * because a structured result read only in part and reported as clean is the
 * failure this adapter is shaped against.
 *
 * The bounds are the Claude Code plugin's MCP argument walk's, but the key
 * handling is not: that walk also scans object keys (in `MCP_MAX_KEY_GROUPS`
 * chunks), while this one scans string VALUES only. A key reaches the model
 * unscanned, and is not counted as truncated either.
 */
function leafFields(response: object): ResponseFields {
  const fields: ScannableResponseField[] = [];
  let truncated = false;
  let remaining = RESULT_WALK_MAX_TOTAL_CHARS;

  const walk = (node: unknown, path: string[], depth: number): void => {
    // Past the depth bound, or once the leaf count is reached, nothing below
    // this node is read — so the walk stops HERE rather than visiting every
    // remaining node to refuse each leaf one at a time. The depth test is the
    // sibling walk's (`depth > MCP_MAX_DEPTH`): a string leaf at depth
    // RESULT_WALK_MAX_DEPTH is read, one below it is not. Only a node that
    // could have carried text marks the result truncated — an empty container
    // or a number left nothing unscanned.
    if (depth > RESULT_WALK_MAX_DEPTH || fields.length >= RESULT_WALK_MAX_LEAVES) {
      if (couldCarryText(node)) truncated = true;
      return;
    }
    if (typeof node === 'string') {
      if (node === '') return;
      if (node.length > RESULT_WALK_MAX_LEAF_CHARS || node.length > remaining) {
        truncated = true;
        return;
      }
      remaining -= node.length;
      fields.push({ path, text: node });
      return;
    }
    if (typeof node !== 'object' || node === null) return;
    const entries: [string, unknown][] = Array.isArray(node)
      ? node.map((item, index): [string, unknown] => [String(index), item])
      : Object.entries(node);
    for (const [index, [key, value]] of entries.entries()) {
      walk(value, [...path, key], depth + 1);
      if (fields.length >= RESULT_WALK_MAX_LEAVES) {
        // The leaf count is reached: no later sibling is entered. One that
        // could have carried text is reported as left out, read without
        // descending into it.
        if (entries.slice(index + 1).some(([, rest]) => couldCarryText(rest))) truncated = true;
        break;
      }
    }
  };

  walk(response, [], 0);
  return { fields, truncated };
}

/**
 * The text fields of a value worth scanning, plus whether the walk bounds left
 * any of it out — the one entry point, so a caller cannot take the fields and
 * drop the flag that says they are not the whole value. Empty strings are
 * skipped: there is nothing in one to find.
 */
export function scannableFields(value: unknown): ResponseFields {
  if (typeof value === 'string') {
    return { fields: value === '' ? [] : [{ path: [], text: value }], truncated: false };
  }
  return typeof value === 'object' && value !== null
    ? leafFields(value)
    : { fields: [], truncated: false };
}
