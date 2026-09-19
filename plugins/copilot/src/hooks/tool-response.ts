// PostToolUse tool-result shapes for the two hosts this package covers.
// Structurally the Claude Code / Codex sibling (path-based read and rewrite over
// a structured result object); what differs is that there are TWO result
// envelopes, and one of them carries a trap.
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
// `test/hooks/tool-response.test.ts` pins that against the recorded fixture.
//
// ─── THE TWO ENVELOPES ───────────────────────────────────────────────────────
//
//  - Copilot CLI (and cloud): `toolResult` is an OBJECT — `{ resultType,
//    textResultForLlm }` in the one recording. The model-visible text is
//    `textResultForLlm`.
//  - VS Code agent mode: `tool_response` is documented as a STRING, so the
//    whole value is the text.
//
// Kept free of I/O and hook wiring so it unit-tests without a hook process
// (hook entry modules run main() on import and hang vitest collection).

import type { Dialect } from './dialect.ts';

export interface ScannableResponseField {
  /** Key path into the result object; `[]` means the result itself. */
  path: string[];
  text: string;
}

/**
 * Where each dialect's model-visible result text lives.
 *
 * The CLI's is RECORDED (`postToolUse.json`). VS Code's is doc-derived: the
 * response arrives as a bare string, so the empty path — "the value itself" —
 * is the whole of its table and a per-tool map would have nothing to hold.
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
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === 'string' ? current : undefined;
}

/**
 * The text fields of a tool result worth scanning, with the path needed to
 * write a redacted replacement back.
 *
 * A bare string result is handled whatever the dialect says, because a host
 * that simplified its envelope would otherwise silently scan nothing — and
 * "scanned nothing, reported success" is the failure mode this whole adapter is
 * shaped to avoid. Empty strings are skipped: nothing to scan, and rewriting
 * one would be a pointless replacement.
 */
export function scannableResponseFields(
  dialect: Dialect,
  response: unknown,
): ScannableResponseField[] {
  if (typeof response === 'string') {
    return response === '' ? [] : [{ path: [], text: response }];
  }
  const fields: ScannableResponseField[] = [];
  for (const path of RESULT_ENVELOPE[dialect].paths) {
    const text = stringAt(response, path);
    if (text !== undefined && text !== '') fields.push({ path: [...path], text });
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
