// PostToolUse tool_response shapes. Claude Code hands hooks the tool's native
// result object, not a flat string — Read wraps the file under file.content,
// Bash splits stdout/stderr, WebFetch carries the page under result. Redaction
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
// see. Mirrors SCANNABLE_FIELDS in pre-tool-use; extend per-tool as the
// PostToolUse matcher grows.
const RESPONSE_TEXT_PATHS: Record<string, PathSegment[][]> = {
  Read: [['file', 'content']],
  Bash: [['stdout'], ['stderr']],
  WebFetch: [['result']],
};

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
