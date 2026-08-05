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
// Only `Bash` is mapped today: PostToolUse does not fire for `apply_patch`
// calls yet (see pre-tool-use-decision.ts's module comment), so there is no
// live tool_response shape for it to verify against.
//
// Kept free of I/O and hook wiring so it can be unit-tested (hook entry modules
// run main() on import and hang vitest collection).

export interface ScannableResponseField {
  /** Key path into the response object; [] means the response itself. */
  path: string[];
  text: string;
}

// Which fields of each tool's structured response carry text the model will
// see. `stdout`/`stderr` mirrors Claude Code's own Bash mapping — Codex's
// rollout `exec_command_end` event carries the same field names
// (codex-rs/protocol/src/protocol.rs — ExecCommandEndEvent).
const RESPONSE_TEXT_PATHS: Record<string, string[][]> = {
  Bash: [['stdout'], ['stderr']],
};

function stringAt(response: unknown, path: string[]): string | undefined {
  let current: unknown = response;
  for (const key of path) {
    if (typeof current !== 'object' || current === null) return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === 'string' ? current : undefined;
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
export function replaceResponseField(response: unknown, path: string[], text: string): unknown {
  const head = path[0];
  if (head === undefined) return text;
  if (typeof response !== 'object' || response === null) return response;
  const record = response as Record<string, unknown>;
  return { ...record, [head]: replaceResponseField(record[head], path.slice(1), text) };
}
