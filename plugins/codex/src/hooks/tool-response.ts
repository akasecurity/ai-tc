// PostToolUse tool_response shapes for Codex CLI. Structurally identical to
// plugins/claude-code/src/hooks/tool-response.ts (path-based read/rewrite over
// a structured response object) — only RESPONSE_TEXT_PATHS differs, because
// Codex's built-in tools differ from Claude Code's.
//
// IMPORTANT — Codex-specific caveat, unlike Claude Code: Codex's PostToolUse
// hook has no `updatedToolOutput` field (confirmed: the Agent Guard plugin's
// own README states Codex "does not expose that Claude field" and instead
// injects a warning via `additionalContext`). `replaceResponseField` below is
// therefore used only to compute what WOULD be redacted for the systemMessage/
// additionalContext text — never to actually rewrite what the model sees. See
// post-tool-use.ts for how the emit payload degrades accordingly.
//
// Shapes observed live (codex-cli 0.160.0, 2026-10-03), including calls nested
// in a code-mode `exec`: `Bash` returns its output as a plain string; the
// built-in web tool fires as `webrun` and returns a bare array of
// `{ type: 'input_text', text }` blocks; an MCP tool fires as
// `mcp__<server>__<tool>` and returns `{ content: [{ type: 'text', text }] }`.
// `apply_patch` output is not scanned: it reports the patch result, and the
// patch body itself is scanned at PreToolUse.
//
// Kept free of I/O and hook wiring so it can be unit-tested (hook entry modules
// run main() on import and hang vitest collection).

export type PathSegment = string | number;

export interface ScannableResponseField {
  /** Key path into the response object; [] means the response itself. */
  path: PathSegment[];
  text: string;
}

// Which fields of each tool's structured response carry text the model will
// see. `stdout`/`stderr` mirrors Claude Code's own Bash mapping — Codex's
// rollout `exec_command_end` event carries the same field names
// (codex-rs/protocol/src/protocol.rs — ExecCommandEndEvent).
const RESPONSE_TEXT_PATHS: Record<string, string[][]> = {
  Bash: [['stdout'], ['stderr']],
};

// The block types that carry text, per tool family. The web tool labels its
// result blocks `input_text`; MCP uses the protocol's `text`.
const WEB_TOOL_NAME = 'webrun';
const WEB_TEXT_BLOCK_TYPES: ReadonlySet<string> = new Set(['input_text', 'text']);
const MCP_TEXT_BLOCK_TYPES: ReadonlySet<string> = new Set(['text']);

// Bounds on the content-block walk, so an oversized result degrades to
// partial coverage instead of outrunning the hook timeout (a timed-out hook
// passes the whole output through unscanned). The same bounds as the Claude
// Code plugin's MCP walk: each scanned block costs one sequential capture, so
// the block COUNT protects the budget; the char bounds keep one huge block
// from dominating it.
export const BLOCK_RESPONSE_MAX_BLOCKS = 2_000;
export const BLOCK_RESPONSE_MAX_BLOCK_CHARS = 1_000_000;
export const BLOCK_RESPONSE_MAX_TOTAL_CHARS = 5_000_000;

function stringAt(response: unknown, path: readonly PathSegment[]): string | undefined {
  let current: unknown = response;
  for (const key of path) {
    if (typeof current !== 'object' || current === null) return undefined;
    if (!Object.hasOwn(current, key)) return undefined;
    current = (current as Record<PathSegment, unknown>)[key];
  }
  return typeof current === 'string' ? current : undefined;
}

/**
 * The text blocks of a content-block result: either the bare block array or
 * an object wrapping it under `content`. Only blocks whose `type` is in
 * `textTypes` are scanned; image, resource and other blocks are left alone.
 */
function contentBlockFields(
  response: unknown,
  textTypes: ReadonlySet<string>,
): ScannableResponseField[] {
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
  let remaining = BLOCK_RESPONSE_MAX_TOTAL_CHARS;
  for (const [index, block] of blocks.entries()) {
    if (fields.length >= BLOCK_RESPONSE_MAX_BLOCKS) break;
    if (typeof block !== 'object' || block === null || Array.isArray(block)) continue;
    const type = Object.hasOwn(block, 'type') ? (block as { type: unknown }).type : undefined;
    if (typeof type !== 'string' || !textTypes.has(type)) continue;
    const path: PathSegment[] = [...base, index, 'text'];
    const text = stringAt(response, path);
    if (text === undefined || text === '' || text.length > BLOCK_RESPONSE_MAX_BLOCK_CHARS) continue;
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
  if (toolName === WEB_TOOL_NAME) return contentBlockFields(response, WEB_TEXT_BLOCK_TYPES);
  if (toolName.startsWith('mcp__')) return contentBlockFields(response, MCP_TEXT_BLOCK_TYPES);
  const paths = Object.hasOwn(RESPONSE_TEXT_PATHS, toolName)
    ? RESPONSE_TEXT_PATHS[toolName]
    : undefined;
  const fields: ScannableResponseField[] = [];
  for (const path of paths ?? []) {
    const text = stringAt(response, path);
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
  const head = path[0];
  if (head === undefined) return text;
  if (typeof response !== 'object' || response === null) return response;
  if (Array.isArray(response)) {
    if (typeof head !== 'number') return response;
    const copy: unknown[] = [...(response as unknown[])];
    copy[head] = replaceResponseField(copy[head], path.slice(1), text);
    return copy;
  }
  const record = response as Record<PathSegment, unknown>;
  return { ...record, [head]: replaceResponseField(record[head], path.slice(1), text) };
}
