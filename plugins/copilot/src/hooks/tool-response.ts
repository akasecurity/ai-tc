// PostToolUse tool-result shapes for the two hosts this package covers.
// Structurally the Claude Code / Codex sibling's reader, with two differences:
// there are TWO result envelopes, one of them carries a trap, and NOTHING HERE
// WRITES.
//
// ─── THE TRAP ────────────────────────────────────────────────────────────────
//
// `toolResult.resultType` IS NOT AN EXIT STATUS. It reports whether the TOOL
// INVOCATION succeeded, not whether the command the tool ran exited zero. The
// recorded fixture is the proof and is the reason this is written down rather
// than remembered: `test/fixtures/cli/postToolUse.json` is a `bash` call whose
// command is literally `false`, and its `resultType` is `"success"`. The exit
// code appears only as free text inside `textResultForLlm`:
//
//     "\n<shellId: 0 completed with exit code 1>"
//
// So anything here that branched on `resultType` to decide whether a command
// worked would be wrong on every failing command, and would LOOK right — a
// failing command would be scanned exactly as a succeeding one is, which is
// what this module wants anyway. The defect would surface somewhere else
// entirely. Nothing in this module reads `resultType` at all, and
// `test/hooks/tool-response.test.ts` pins that against the recorded fixture,
// over a comment-stripped read of this file.
//
// ─── THE TWO ENVELOPES ───────────────────────────────────────────────────────
//
//  - Copilot CLI (and cloud): `toolResult` is an OBJECT — `{ resultType,
//    textResultForLlm }` in the one recording. The model-visible text is
//    `textResultForLlm`.
//  - VS Code agent mode: `tool_response` is documented as a STRING, so the
//    whole value is the text. When it arrives as an OBJECT or ARRAY instead —
//    a tool whose result is structured — its string leaves are collected by a
//    bounded walk (`leafFields`) rather than dropped, so a secret in a
//    structured result is still scanned. The walk is held to the same depth,
//    leaf-count and character bounds the Claude Code sibling holds an MCP
//    tool's arguments to, and anything those bounds leave out is reported as
//    `truncated` so the hook says part of the result went unscanned. Unlike
//    that walk, which also scans object keys, this one reads values only.
//
// ─── WHY THERE IS NO WRITER ──────────────────────────────────────────────────
//
// The sibling adapters pair this reader with a path-based REPLACE, because
// their hosts carry a confirmed result-rewrite channel. This one does not:
// `postToolUse.modifiedResult` is listed under "Not measured" in
// `test/fixtures/cli/README.md`, and VS Code's counterpart has never been
// driven. Emitting a rewrite the host ignores would let the audit trail record
// a redaction that did not happen — the exact failure `rewritable: false`
// exists to prevent — so the `path` each field carries is what identifies it in
// a message, not a cursor for a write that never occurs. Adding a writer here
// means first recording that the channel works.
//
// Kept free of I/O and hook wiring so it unit-tests without a hook process
// (hook entry modules run their body on import and hang vitest collection).

import type { Dialect } from './dialect.ts';

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
 * Bounds on the walk over an object-shaped VS Code result: how deep it goes,
 * how many string leaves it collects, how long one leaf may be, and how many
 * characters all of them add up to. Each collected leaf is one sequential
 * capture, so these bound the work one result can cost the hook. The values
 * are the Claude Code sibling's MCP argument walk's, where a capture of a
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

/**
 * Where each dialect's model-visible result text lives.
 *
 * The CLI's is RECORDED (`postToolUse.json`). VS Code's is doc-derived: the
 * response arrives as a bare string, so the empty path — "the value itself" —
 * is the whole of its table and a per-tool map would have nothing to hold. An
 * object-shaped VS Code result is read by `leafFields` instead of this table.
 *
 * Two tables, never merged, for the reason `pre-tool-use-decision.ts` gives
 * about its own pair: a merged one would let one host's envelope resolve
 * against the other's key and scan a field that is not there — silently,
 * because a missing field is simply skipped.
 */
const RESULT_ENVELOPE = {
  cli: { key: 'toolResult', paths: [['textResultForLlm']] },
  vscode: { key: 'tool_response', paths: [[]] },
} as const satisfies Record<Dialect, { key: string; paths: readonly (readonly string[])[] }>;

/** The payload key this dialect's tool result arrives under. */
export function responseKey(dialect: Dialect): string {
  return RESULT_ENVELOPE[dialect].key;
}

function stringAt(response: unknown, path: readonly string[]): string | undefined {
  let current: unknown = response;
  for (const key of path) {
    if (typeof current !== 'object' || current === null) return undefined;
    if (!Object.hasOwn(current, key)) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === 'string' ? current : undefined;
}

/**
 * Every non-empty string leaf of a structured result, under the walk bounds.
 *
 * A leaf the bounds refuse — too deep, too long, past the leaf count or past
 * the character total — marks the collection truncated rather than vanishing,
 * because a structured result read only in part and reported as clean is the
 * failure this adapter is shaped against.
 *
 * The bounds are the Claude Code sibling's MCP argument walk's, but the key
 * handling is not: that walk also scans object keys (in `MCP_MAX_KEY_GROUPS`
 * chunks), while this one scans string VALUES only. A key reaches the model
 * unscanned, and is not counted as truncated either.
 */
function leafFields(response: object): ResponseFields {
  const fields: ScannableResponseField[] = [];
  let truncated = false;
  let remaining = RESULT_WALK_MAX_TOTAL_CHARS;

  const walk = (node: unknown, path: string[], depth: number): void => {
    // The same depth test as the sibling's walk (`depth > MCP_MAX_DEPTH`): a
    // string leaf at depth RESULT_WALK_MAX_DEPTH is read, one below it is not.
    // Only a node that could have carried text marks the result truncated — an
    // empty container or a number past the bound left nothing unscanned.
    if (depth > RESULT_WALK_MAX_DEPTH) {
      if (
        (typeof node === 'string' && node !== '') ||
        (typeof node === 'object' && node !== null && Object.keys(node).length > 0)
      ) {
        truncated = true;
      }
      return;
    }
    if (typeof node === 'string') {
      if (node === '') return;
      if (
        fields.length >= RESULT_WALK_MAX_LEAVES ||
        node.length > RESULT_WALK_MAX_LEAF_CHARS ||
        node.length > remaining
      ) {
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
    for (const [key, value] of entries) walk(value, [...path, key], depth + 1);
  };

  walk(response, [], 0);
  return { fields, truncated };
}

/**
 * The text fields of a tool result worth scanning, plus whether the walk
 * bounds left any of it out — the one entry point, so a caller cannot take the
 * fields and drop the flag that says they are not the whole result.
 *
 * A bare string result is handled whatever the dialect says, because a host
 * that simplified its envelope would otherwise silently scan nothing — and
 * "scanned nothing, reported success" is the failure mode this whole adapter is
 * shaped to avoid. Empty strings are skipped: there is nothing in one to find.
 */
export function scannableResponseFields(dialect: Dialect, response: unknown): ResponseFields {
  if (typeof response === 'string') {
    return { fields: response === '' ? [] : [{ path: [], text: response }], truncated: false };
  }
  if (dialect === 'vscode') {
    return typeof response === 'object' && response !== null
      ? leafFields(response)
      : { fields: [], truncated: false };
  }
  const fields: ScannableResponseField[] = [];
  for (const path of RESULT_ENVELOPE[dialect].paths) {
    const text = stringAt(response, path);
    if (text !== undefined && text !== '') fields.push({ path: [...path], text });
  }
  return { fields, truncated: false };
}
