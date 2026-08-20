// The agent vocabulary — the single source of truth for every id this product
// uses to name a coding assistant, and the mapping between the two spellings.
//
// There are TWO vocabularies because the capture side and the read side name
// the same tool differently, and merging them would be wrong rather than tidy:
//
//   - SOURCE_TOOL is the WIRE id a plugin stamps on a capture ('claude-code').
//   - HARNESS is the DISPLAY id the dashboard renders ('claudecode').
//
// They are joined by MEMBER NAME, not by string: `ClaudeCode` appears in both,
// so TOOL_TO_HARNESS below pairs them without either spelling being retyped.
// A member in only one vocabulary is deliberate and carries meaning — 'Cli' and
// 'Unknown' are captures with no harness to render, 'Windsurf' and 'Api' are
// rendered harnesses nothing captures under — so the join is exactly the
// intersection of the two member-name sets.
//
// Every narrower enum in this package (`Provider`, `HarnessId`,
// `FindingProvider`) is `Harness.extract([...])` over these member names, so a
// subset can never carry an id this file does not define. It does NOT follow
// that a member added here reaches them: `.extract()` takes an explicit list of
// member names, so a new id joins no subset on its own. Adding one is this edit
// plus a deliberate decision per subset — whether it is filtered on, scanned
// for, or bucketed as a findings provider. A subset it never joins renders
// nowhere and buckets to the miss path, with nothing failing to say so.
//
// The miss path is not shared, and the two consumers answer differently: an
// unmapped tool id passes through `harnessFromTool` and the read side coalesces
// an unrecognised value to 'claudecode', while `toApiProvider` falls back to
// 'api'. One uninstrumented tool's events therefore read as Claude Code on the
// Activity surfaces and as API on the findings surfaces.
import { z } from 'zod';

import type { FindingProvider } from './finding.ts';

/**
 * Instrumented coding assistant — the DISPLAY id the Activity surfaces render.
 * Do NOT mint a second harness vocabulary; extend this one.
 *
 * Members are named so call sites spell `HARNESS.ClaudeCode` rather than a bare
 * `'claudecode'`: a literal that is merely equal to a member is invisible to a
 * rename.
 *
 * These values are PERSISTED, exactly as `SOURCE_TOOL`'s are — the capture path
 * stamps one onto a session root's `harness` attribute, the Activity queries
 * compare against them in SQL, and `HarnessId` is what a stored inventory
 * `provider` is validated against. So a member's VALUE is a storage contract
 * here too and may not be respelled without a migration, while its NAME is free
 * to change. A respell compiles and passes the whole suite, because every call
 * site spells the member — and every row an earlier version wrote stops matching.
 *
 * Declared as a const object rather than a TypeScript `enum` on purpose —
 * `packages/plugin-sdk/src/scan-worker.ts` is loaded by raw Node under type
 * STRIPPING and reaches this module through `@akasecurity/detections`, so
 * anything here that needs a real compile rather than an erase fails at load.
 */
export const HARNESS = {
  ClaudeCode: 'claudecode',
  Cursor: 'cursor',
  Copilot: 'copilot',
  Codex: 'codex',
  Antigravity: 'antigravity',
  Windsurf: 'windsurf',
  ClaudeDesktop: 'claudedesktop',
  ChatGpt: 'chatgpt',
  ClaudeAi: 'claudeai',
  Api: 'api',
} as const;

export const Harness = z.enum(HARNESS).meta({ id: 'Harness' });
export type Harness = z.infer<typeof Harness>;

/**
 * The tool whose input/output was scanned — the WIRE id a plugin stamps on a
 * capture, and the value stored in the events table's `source_tool` column.
 * Spelled differently from `HARNESS` (`claude-code` vs `claudecode`) because the
 * capture and read sides name the same tool differently — NOT because only one
 * of them is persisted. Both are: a member's VALUE here is a storage contract
 * and may not be respelled without a migration, while its NAME is free to
 * change.
 */
export const SOURCE_TOOL = {
  ClaudeCode: 'claude-code',
  ClaudeDesktop: 'claude-desktop',
  Cursor: 'cursor',
  ChatGpt: 'chatgpt',
  ClaudeAi: 'claude-ai',
  Copilot: 'github-copilot',
  Codex: 'codex',
  Antigravity: 'antigravity',
  // No harness counterpart, deliberately: the CLI's own captures and a capture
  // whose tool could not be identified both render through the read side's
  // miss path rather than as a harness of their own.
  Cli: 'cli',
  Unknown: 'unknown',
} as const;

export const SourceTool = z.enum(SOURCE_TOOL).meta({ id: 'SourceTool' });
export type SourceTool = z.infer<typeof SourceTool>;

// The wire id → display id join, one row per member name both vocabularies
// carry. Spelled through the members rather than as literal strings, so a
// renamed member is a compile error here instead of a row that silently stops
// matching. Values are typed to the intersection of both consumer enums, so a
// row whose target is a `Harness` but not a `FindingProvider` (e.g. 'windsurf')
// fails to compile rather than reaching `toApiProvider` as an unchecked
// `undefined`. The annotation (rather than `satisfies`) is what gives the
// string index signature `harnessFromTool` needs — this map is PARTIAL by
// design, since a tool-only member has nothing to map onto.
export const TOOL_TO_HARNESS: Record<string, Harness & FindingProvider> = {
  [SOURCE_TOOL.ClaudeCode]: HARNESS.ClaudeCode,
  [SOURCE_TOOL.ClaudeDesktop]: HARNESS.ClaudeDesktop,
  [SOURCE_TOOL.Copilot]: HARNESS.Copilot,
  [SOURCE_TOOL.Cursor]: HARNESS.Cursor,
  [SOURCE_TOOL.ChatGpt]: HARNESS.ChatGpt,
  [SOURCE_TOOL.Codex]: HARNESS.Codex,
  [SOURCE_TOOL.Antigravity]: HARNESS.Antigravity,
  [SOURCE_TOOL.ClaudeAi]: HARNESS.ClaudeAi,
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
