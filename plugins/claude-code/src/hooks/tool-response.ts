// PostToolUse tool_response shapes. Claude Code hands hooks the tool's native
// result object, not a flat string — Read wraps the file under file.content,
// Bash splits stdout/stderr, WebFetch carries the page under result, Grep
// carries matching lines under content, WebSearch carries link lists and
// summary text under results, a subagent (Agent, formerly Task) returns its
// final message as content blocks, and an MCP tool returns its content
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
  /**
   * Where `text` sits in the string at `path`, when it is one chunk of a
   * longer string (see RESPONSE_CHUNK_CHARS). Absent means the whole string.
   */
  range?: { start: number; end: number };
}

// Which fields of each tool's structured response carry text the model will
// see. Mirrors the PreToolUse input map in pre-tool-use-fields.ts
// (scannableInputFields / STATIC_FIELDS); extend per-tool as the PostToolUse
// matcher grows. The tools whose text sits in arrays of varying length are
// handled by the walks below instead: content blocks for mcp__* and the
// subagent tools, and the results list for WebSearch.
const RESPONSE_TEXT_PATHS: Record<string, PathSegment[][]> = {
  Read: [['file', 'content']],
  Bash: [['stdout'], ['stderr']],
  WebFetch: [['result']],
  // Grep returns an object in every output mode (recorded shapes:
  // test/fixtures/grep-tool-response.json). `content` holds the matching
  // lines in the content mode and the per-file counts in the count mode; the
  // files_with_matches mode leaves it out and lists only `filenames`, which
  // is not scanned. A plain-string response would be scanned whole, like any
  // tool's (see scannableResponseFields), but Grep has not been seen to send
  // one. Content-mode output is unbounded by the host (a broad pattern can
  // return megabytes), so it is held to the response bounds below.
  Grep: [['content']],
};

/**
 * Subagent tools, whose result carries the subagent's final message as text
 * content blocks under `content`. `Task` is the earlier name of `Agent`.
 */
const CONTENT_BLOCK_TOOLS: ReadonlySet<string> = new Set(['Agent', 'Task']);

const WEB_SEARCH_TOOL = 'WebSearch';

/**
 * Every tool, by exact name, whose response this module reads. The mcp__*
 * family is matched by prefix and is not listed. Exported so the manifest test
 * can check the PostToolUse matcher selects every one of them.
 */
export const SCANNED_RESPONSE_TOOL_NAMES: readonly string[] = [
  ...Object.keys(RESPONSE_TEXT_PATHS),
  WEB_SEARCH_TOOL,
  ...CONTENT_BLOCK_TOOLS,
];

// Bounds on what one response costs to scan, so an oversized result degrades
// to partial coverage instead of outrunning the hook timeout (a timed-out hook
// passes the whole output through unscanned). They apply to every tool's
// response, the static fields and the MCP text blocks alike.
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
// scan-response.ts, since a capture's cost depends on the machine and the
// store, not only on its size.
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

/** The value of an own array property, or undefined. */
function ownArray(value: unknown, key: string): unknown[] | undefined {
  if (typeof value !== 'object' || value === null || !Object.hasOwn(value, key)) return undefined;
  const property = (value as Record<string, unknown>)[key];
  return Array.isArray(property) ? property : undefined;
}

/**
 * The text blocks of an MCP or subagent tool result: either the bare
 * content-block array or an object wrapping it under `content`. Only
 * `{ type: 'text', text }` blocks are scanned; image, resource and other block
 * types are left alone. Each field addresses the block's `text` in place, so a
 * rewrite keeps the array, its length and every sibling block intact.
 */
function contentBlockFields(response: unknown): ScannableResponseField[] {
  let blocks: unknown[];
  let base: PathSegment[];
  if (Array.isArray(response)) {
    blocks = response;
    base = [];
  } else {
    const wrapped = ownArray(response, 'content');
    if (wrapped === undefined) return [];
    blocks = wrapped;
    base = ['content'];
  }

  const bounded = new BoundedFields();
  for (const [index, block] of blocks.entries()) {
    if (typeof block !== 'object' || block === null || Array.isArray(block)) continue;
    if (!Object.hasOwn(block, 'type') || (block as { type: unknown }).type !== 'text') continue;
    const path: PathSegment[] = [...base, index, 'text'];
    const text = stringAtPath(response, path);
    if (text === undefined || text === '') continue;
    if (!bounded.add(path, text)) break;
  }
  return bounded.fields;
}

/**
 * The text of a WebSearch result. `results` mixes link lists
 * (`{ content: [{ title, url }, …] }`) with plain-string summary text; the
 * summaries and the link titles are scanned. URLs are left alone, and so is
 * the echoed `query`, which is the tool's own input. Each field addresses its
 * string in place, so a rewrite keeps the list and its entries intact.
 */
function webSearchResponseFields(response: unknown): ScannableResponseField[] {
  const results = ownArray(response, 'results');
  if (results === undefined) return [];

  const bounded = new BoundedFields();
  for (const [index, entry] of results.entries()) {
    if (typeof entry === 'string') {
      if (entry !== '' && !bounded.add(['results', index], entry)) break;
      continue;
    }
    const links = ownArray(entry, 'content');
    if (links === undefined) continue;
    for (const linkIndex of links.keys()) {
      const path: PathSegment[] = ['results', index, 'content', linkIndex, 'title'];
      const title = stringAtPath(response, path);
      if (title === undefined || title === '') continue;
      if (!bounded.add(path, title)) return bounded.fields;
    }
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
  if (toolName.startsWith('mcp__') || CONTENT_BLOCK_TOOLS.has(toolName)) {
    return contentBlockFields(response);
  }
  if (toolName === WEB_SEARCH_TOOL) return webSearchResponseFields(response);
  // hasOwn guard: a bare index would resolve Object.prototype members for
  // tool names like 'constructor' (non-nullish, so ?? does not catch them).
  const paths = Object.hasOwn(RESPONSE_TEXT_PATHS, toolName)
    ? RESPONSE_TEXT_PATHS[toolName]
    : undefined;
  const bounded = new BoundedFields();
  for (const path of paths ?? []) {
    const text = stringAtPath(response, path);
    if (text === undefined || text === '') continue;
    if (!bounded.add(path, text)) break;
  }
  return bounded.fields;
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

/**
 * Copy of `response` with chunk replacements spliced into the string at
 * `path`. `parts` are ranges of that string as it was scanned; text outside
 * every range is kept. Returns `response` unchanged when `path` no longer
 * holds a string.
 */
export function spliceResponseField(
  response: unknown,
  path: readonly PathSegment[],
  parts: readonly { start: number; end: number; text: string }[],
): unknown {
  const original = stringAtPath(response, path);
  if (original === undefined) return response;
  let out = '';
  let cursor = 0;
  for (const part of [...parts].sort((a, b) => a.start - b.start)) {
    if (part.start < cursor || part.end > original.length) return response;
    out += original.slice(cursor, part.start) + part.text;
    cursor = part.end;
  }
  out += original.slice(cursor);
  return replaceAtPath(response, path, out);
}
