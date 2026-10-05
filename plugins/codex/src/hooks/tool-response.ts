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
// `apply_patch` returns a plain string reporting the patch result (exit code
// and the changed paths), which is scanned whole like any plain-string
// response; the patch body itself is scanned at PreToolUse. Recorded
// payloads: test/fixtures/hooks/.
//
// Kept free of I/O and hook wiring so it can be unit-tested (hook entry modules
// run main() on import and hang vitest collection).

export type PathSegment = string | number;

export interface ScannableResponseField {
  /** Key path into the response object; [] means the response itself. */
  path: PathSegment[];
  text: string;
  /**
   * Where `text` sits in the string at `path`, when it is one chunk of a
   * longer string (see RESPONSE_CHUNK_CHARS). Absent means the whole string.
   */
  range?: { start: number; end: number };
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

/**
 * The fixed tool names whose results this module maps: the static table plus
 * the web tool. The mcp__* family is matched by prefix and is not listed, and
 * any tool's plain-string result is scanned whole. Exported so the manifest
 * test can check the PostToolUse matcher selects every one of them.
 */
export const SCANNED_RESPONSE_TOOL_NAMES: readonly string[] = [
  ...Object.keys(RESPONSE_TEXT_PATHS),
  WEB_TOOL_NAME,
];

// Bounds on what one response costs to scan, so an oversized result degrades
// to partial coverage instead of outrunning the hook timeout (a timed-out hook
// passes the whole output through unscanned). The same bounds as the Claude
// Code plugin's response walk, applied to every tool's response.
//
// A string longer than RESPONSE_CHUNK_CHARS is scanned as consecutive chunks,
// cut after a newline where one falls inside the chunk. The size matches the
// detector's own window: each regex rule runs over at most the first 200,000
// characters of the text it is given (MAX_REGEX_INPUT_LENGTH in the detections
// package), so a longer string handed over whole is scanned only up to there.
// A value that straddles a cut with no newline near it can be missed.
//
// Every chunk or block costs one sequential capture. The walk stops at
// RESPONSE_MAX_CAPTURES captures or RESPONSE_MAX_TOTAL_CHARS characters,
// whichever comes first, and the text past that point reaches the model
// unscanned. Wall time is bounded separately, by the scan deadline in
// scan-response.ts.
export const RESPONSE_CHUNK_CHARS = 200_000;
export const RESPONSE_MAX_CAPTURES = 2_000;
export const RESPONSE_MAX_TOTAL_CHARS = 5_000_000;

/**
 * Chunk boundaries for `text`, each at most `max` characters: a chunk ends
 * after the last newline inside it when there is one, otherwise at `max`
 * (moved back one so a surrogate pair is never split).
 */
export function chunkRanges(text: string, max: number): { start: number; end: number }[] {
  const ranges: { start: number; end: number }[] = [];
  let start = 0;
  while (start < text.length) {
    let end = Math.min(start + max, text.length);
    if (end < text.length) {
      const newline = text.lastIndexOf('\n', end - 1);
      if (newline >= start) {
        end = newline + 1;
      } else if (end - start > 1) {
        const code = text.charCodeAt(end - 1);
        if (code >= 0xd800 && code <= 0xdbff) end -= 1;
      }
    }
    ranges.push({ start, end });
    start = end;
  }
  return ranges;
}

/** Collects fields under the response bounds above. */
class BoundedFields {
  readonly fields: ScannableResponseField[] = [];
  private remaining = RESPONSE_MAX_TOTAL_CHARS;

  /** True once no further field can be added. */
  get full(): boolean {
    return this.fields.length >= RESPONSE_MAX_CAPTURES || this.remaining <= 0;
  }

  /** Adds the string at `path`, chunked; returns false once the bounds are hit. */
  add(path: PathSegment[], text: string): boolean {
    if (text.length <= RESPONSE_CHUNK_CHARS && text.length <= this.remaining) {
      if (this.full) return false;
      this.fields.push({ path, text });
      this.remaining -= text.length;
      return true;
    }
    const scanned = text.slice(0, Math.max(0, this.remaining));
    for (const range of chunkRanges(scanned, RESPONSE_CHUNK_CHARS)) {
      if (this.full) return false;
      this.fields.push({ path, text: text.slice(range.start, range.end), range });
      this.remaining -= range.end - range.start;
    }
    return !this.full;
  }
}

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

  const bounded = new BoundedFields();
  for (const [index, block] of blocks.entries()) {
    if (typeof block !== 'object' || block === null || Array.isArray(block)) continue;
    const type = Object.hasOwn(block, 'type') ? (block as { type: unknown }).type : undefined;
    if (typeof type !== 'string' || !textTypes.has(type)) continue;
    const path: PathSegment[] = [...base, index, 'text'];
    const text = stringAt(response, path);
    if (text === undefined || text === '') continue;
    if (!bounded.add(path, text)) break;
  }
  return bounded.fields;
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
    const bounded = new BoundedFields();
    if (response !== '') bounded.add([], response);
    return bounded.fields;
  }
  if (toolName === WEB_TOOL_NAME) return contentBlockFields(response, WEB_TEXT_BLOCK_TYPES);
  if (toolName.startsWith('mcp__')) return contentBlockFields(response, MCP_TEXT_BLOCK_TYPES);
  const paths = Object.hasOwn(RESPONSE_TEXT_PATHS, toolName)
    ? RESPONSE_TEXT_PATHS[toolName]
    : undefined;
  const bounded = new BoundedFields();
  for (const path of paths ?? []) {
    const text = stringAt(response, path);
    if (text === undefined || text === '') continue;
    if (!bounded.add(path, text)) break;
  }
  return bounded.fields;
}

/**
 * Copy of `response` with the string at `path` replaced, leaving the original
 * untouched. Only the spine along `path` is cloned; sibling values are shared.
 * Returns `response` unchanged when the path doesn't resolve, so a stale path
 * degrades to "no rewrite" rather than grafting new keys or slots on.
 */
export function replaceResponseField(
  response: unknown,
  path: readonly PathSegment[],
  text: string,
): unknown {
  const head = path[0];
  if (head === undefined) return text;
  if (typeof response !== 'object' || response === null) return response;
  const rest = path.slice(1);
  if (Array.isArray(response)) {
    if (typeof head !== 'number' || !Number.isInteger(head) || head < 0) return response;
    if (head >= response.length) return response;
    const copy: unknown[] = [...(response as unknown[])];
    copy[head] = replaceResponseField(copy[head], rest, text);
    return copy;
  }
  const record = response as Record<PathSegment, unknown>;
  // Same guard as the Claude Code twin (plugins/claude-code/src/hooks/paths.ts):
  // a key the payload does not own would be grafted on, and a payload carrying
  // a key the tool's schema does not declare is a shape mismatch. Also keeps a
  // '__proto__' segment from reaching the prototype.
  if (!Object.hasOwn(record, head)) return response;
  return { ...record, [head]: replaceResponseField(record[head], rest, text) };
}
