// The canonical harness vocabulary and the single source of truth for mapping a
// harness inventory *tool* id (the value the plugin hashes its harness identity
// on, e.g. 'claude-code') onto the `Harness` / `FindingProvider` enum value the
// read surfaces render ('claudecode'). One table, so the *mapped* rows cannot
// drift between consumers (`harnessFromTool` on the capture writers,
// `toApiProvider` in findings-group-build.ts on the findings read side).
//
// The miss path is not shared, and the two consumers answer differently: an
// unmapped tool id passes through `harnessFromTool` and the read side coalesces
// an unrecognised value to 'claudecode', while `toApiProvider` falls back to
// 'api'. One uninstrumented tool's events therefore read as Claude Code on the
// Activity surfaces and as API on the findings surfaces.
import { z } from 'zod';

import type { FindingProvider } from './finding.ts';

/**
 * Instrumented coding assistant. The open-ended harness vocabulary shared by
 * the Activity surfaces and the capture writers. Do NOT mint a second
 * `Harness` export; extend this one (single canonical registry). A consumer
 * that only needs a SUBSET of these ids (`HarnessId`, `FindingProvider`,
 * `Provider`) derives it with `Harness.extract([...])` rather than re-typing
 * the member list — the subset can then never drift from this array.
 */
export const Harness = z
  .enum([
    'claudecode',
    'cursor',
    'copilot',
    'codex',
    'antigravity',
    'windsurf',
    'claudedesktop',
    'chatgpt',
    'claudeai',
    'api',
  ])
  .meta({ id: 'Harness' });
export type Harness = z.infer<typeof Harness>;

// Values are typed to the intersection of both consumer enums, so a row whose
// target is a `Harness` but not a `FindingProvider` (e.g. 'windsurf') fails to
// compile rather than reaching `toApiProvider` as an unchecked `undefined`.
export const TOOL_TO_HARNESS: Record<string, Harness & FindingProvider> = {
  'claude-code': 'claudecode',
  'claude-desktop': 'claudedesktop',
  'github-copilot': 'copilot',
  cursor: 'cursor',
  chatgpt: 'chatgpt',
  codex: 'codex',
  antigravity: 'antigravity',
  'claude-ai': 'claudeai',
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
