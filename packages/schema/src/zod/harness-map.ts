// The canonical harness vocabulary and the single source of truth for mapping a
// harness inventory *tool* id (the value the plugin hashes its harness identity
// on, e.g. 'claude-code') onto the `Harness` / `FindingProvider` enum value the
// read surfaces render ('claudecode'). One table, so consumers (`harnessFromTool`
// on the capture writers, `toApiProvider` in findings-group-build.ts on the
// findings read side) can never silently drift.
import { z } from 'zod';

/**
 * Instrumented coding assistant. The open-ended harness vocabulary shared by
 * the Activity surfaces and the capture writers. Do NOT mint a second
 * `Harness` export; extend this one (single canonical registry).
 */
export const Harness = z
  .enum(['claudecode', 'cursor', 'copilot', 'codex', 'windsurf', 'claudedesktop', 'chatgpt', 'api'])
  .meta({ id: 'Harness' });
export type Harness = z.infer<typeof Harness>;

export const TOOL_TO_HARNESS: Record<string, string> = {
  'claude-code': 'claudecode',
  'claude-desktop': 'claudedesktop',
  'github-copilot': 'copilot',
  cursor: 'cursor',
  chatgpt: 'chatgpt',
};

// Map a harness inventory *tool* id — the value the plugin hashes its harness
// identity on, e.g. 'claude-code' — onto the `Harness` enum value ('claudecode')
// the Activity surfaces render. The capture path stamps the mapped value onto
// the session root's `harness` attribute so the read side needs no per-tool
// mapping. Unknown tools pass through unchanged (the read side validates
// against the enum and defaults to 'claudecode' on a miss).
export function harnessFromTool(tool: string): string {
  return TOOL_TO_HARNESS[tool] ?? tool;
}
