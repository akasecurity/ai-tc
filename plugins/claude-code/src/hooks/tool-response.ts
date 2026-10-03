// PostToolUse tool_response shapes. Claude Code hands hooks the tool's native
// result object, not a flat string — Read wraps the file under file.content,
// Bash splits stdout/stderr, WebFetch carries the page under result, Grep
// carries matching lines under content, and an MCP tool returns its content
// blocks ([{ type: 'text', text }, …]) or a plain string. Redaction
// must rewrite those fields *in place*: Claude Code validates a hook's
// updatedToolOutput against the tool's own output shape and silently falls back
// to the original output when it doesn't match, so replacing an object response
// with a string would leave the sensitive output visible to the model.
//
// Kept free of I/O and hook wiring so it can be unit-tested (hook entry modules
// run main() on import and hang vitest collection).
import type { PathSegment } from './paths.ts';
import { replaceAtPath, stringAtPath } from './paths.ts';

export interface ScannableResponseField {
  /** Key path into the response object; [] means the response itself. */
  path: PathSegment[];
  text: string;
}

// Which fields of each tool's structured response carry text the model will
// see. Mirrors the PreToolUse input map in pre-tool-use-fields.ts
// (scannableInputFields / STATIC_FIELDS); extend per-tool as the PostToolUse
// matcher grows. The mcp__* family has no fixed shape and is handled by
// mcpResponseFields below instead.
const RESPONSE_TEXT_PATHS: Record<string, PathSegment[][]> = {
  Read: [['file', 'content']],
  Bash: [['stdout'], ['stderr']],
  WebFetch: [['result']],
  // `content` is present in the content and count output modes; the
  // files_with_matches mode carries only `filenames`, which is not scanned.
  Grep: [['content']],
};

/**
 * The tools whose response fields come from the static table above. The
 * mcp__* family is handled dynamically and is not listed. Exported so the
 * manifest test can check the PostToolUse matcher selects every one of them.
 */
export const SCANNED_RESPONSE_TOOL_NAMES: readonly string[] = Object.keys(RESPONSE_TEXT_PATHS);

// Bounds on the MCP content-block walk, so an oversized result degrades to
// partial coverage instead of outrunning the hook timeout (a timed-out hook
// passes the whole output through unscanned). Each scanned block costs one
// sequential capture, so the block COUNT is the bound that protects the
// budget; the char bounds keep a single huge block from dominating it. A
// block longer than the per-block cap is skipped, and the walk stops once
// the total budget is spent — the same policy as the PreToolUse MCP walk in
// pre-tool-use-fields.ts.
export const MCP_RESPONSE_MAX_BLOCKS = 2_000;
export const MCP_RESPONSE_MAX_BLOCK_CHARS = 1_000_000;
export const MCP_RESPONSE_MAX_TOTAL_CHARS = 5_000_000;

/**
 * The text blocks of an MCP tool result: either the bare content-block array
 * or an object wrapping it under `content`. Only `{ type: 'text', text }`
 * blocks are scanned; image, resource and other block types are left alone.
 * Each field addresses the block's `text` in place, so a rewrite keeps the
 * array, its length and every sibling block intact.
 */
function mcpResponseFields(response: unknown): ScannableResponseField[] {
  let blocks: unknown[];
  let base: PathSegment[];
  if (Array.isArray(response)) {
    blocks = response;
    base = [];
  } else if (
    typeof response === 'object' &&
    response !== null &&
    Object.hasOwn(response, 'content') &&
    Array.isArray((response as { content: unknown }).content)
  ) {
    blocks = (response as { content: unknown[] }).content;
    base = ['content'];
  } else {
    return [];
  }

  const fields: ScannableResponseField[] = [];
  let remaining = MCP_RESPONSE_MAX_TOTAL_CHARS;
  for (const [index, block] of blocks.entries()) {
    if (fields.length >= MCP_RESPONSE_MAX_BLOCKS) break;
    if (typeof block !== 'object' || block === null || Array.isArray(block)) continue;
    if (!Object.hasOwn(block, 'type') || (block as { type: unknown }).type !== 'text') continue;
    const path: PathSegment[] = [...base, index, 'text'];
    const text = stringAtPath(response, path);
    if (text === undefined || text === '' || text.length > MCP_RESPONSE_MAX_BLOCK_CHARS) continue;
    remaining -= text.length;
    if (remaining < 0) break;
    fields.push({ path, text });
  }
  return fields;
}

/**
 * The text fields of a tool response worth scanning, with the path needed to
 * write a redacted replacement back. Empty strings are skipped — nothing to
 * scan, and rewriting them would be a pointless output replacement.
 */
export function scannableResponseFields(
  toolName: string,
  response: unknown,
): ScannableResponseField[] {
  if (typeof response === 'string') {
    return response === '' ? [] : [{ path: [], text: response }];
  }
  if (toolName.startsWith('mcp__')) return mcpResponseFields(response);
  // hasOwn guard: a bare index would resolve Object.prototype members for
  // tool names like 'constructor' (non-nullish, so ?? does not catch them).
  const paths = Object.hasOwn(RESPONSE_TEXT_PATHS, toolName)
    ? RESPONSE_TEXT_PATHS[toolName]
    : undefined;
  const fields: ScannableResponseField[] = [];
  for (const path of paths ?? []) {
    const text = stringAtPath(response, path);
    if (text !== undefined && text !== '') fields.push({ path, text });
  }
  return fields;
}

/**
 * Copy of `response` with the string at `path` replaced, leaving the original
 * untouched. Only the spine along `path` is cloned; sibling values are shared.
 */
export function replaceResponseField(
  response: unknown,
  path: readonly PathSegment[],
  text: string,
): unknown {
  return replaceAtPath(response, path, text);
}
