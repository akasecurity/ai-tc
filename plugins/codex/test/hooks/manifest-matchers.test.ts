// The tool hooks only see what their `hooks.json` matcher selects, and nothing
// else in the suite reads the matcher: a tool mapped in SCANNABLE_FIELDS or
// tool-response.ts but missing from the matcher is never scanned, with no error
// anywhere. The expected sets below are DERIVED from those mappings, as in the
// Claude Code twin, so a tool added to a mapping and forgotten in the manifest
// fails here without anyone extending a list.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { SCANNABLE_FIELDS } from '../../src/hooks/pre-tool-use-decision.ts';
import {
  scannableResponseFields,
  SCANNED_RESPONSE_TOOL_NAMES,
} from '../../src/hooks/tool-response.ts';

interface Manifest {
  hooks: Record<string, { matcher?: string }[]>;
}

const manifest = JSON.parse(
  readFileSync(
    join(fileURLToPath(new URL('.', import.meta.url)), '..', '..', 'hooks', 'hooks.json'),
    'utf8',
  ),
) as Manifest;

// Codex matches the matcher as a regex against the WHOLE tool name. Checked
// live on codex-cli 0.160.0 with three PreToolUse entries on one apply_patch
// call: `Bash|apply_patch` and `^apply_patch$` fired, the substring
// `pply_patc` did not. Recheck this if a Codex release changes matching.
function selects(event: string, toolName: string): boolean {
  return (manifest.hooks[event] ?? []).some(
    (entry) => entry.matcher === undefined || new RegExp(`^(?:${entry.matcher})$`).test(toolName),
  );
}

describe('hooks.json tool matchers', () => {
  it('PreToolUse selects every tool with scannable input fields', () => {
    const missed = Object.keys(SCANNABLE_FIELDS).filter((tool) => !selects('PreToolUse', tool));
    expect(missed, 'tools whose input is never scanned').toEqual([]);
  });

  it('PostToolUse selects every tool named in the response mapping', () => {
    const missed = SCANNED_RESPONSE_TOOL_NAMES.filter((tool) => !selects('PostToolUse', tool));
    expect(missed, 'tools whose output is never scanned').toEqual([]);
    expect(SCANNED_RESPONSE_TOOL_NAMES).toEqual(expect.arrayContaining(['Bash', 'webrun']));
  });

  it('PostToolUse also selects every tool whose input is scanned', () => {
    // Their results are plain strings or mapped shapes, scanned on the way
    // back (apply_patch's result names the changed paths).
    const missed = Object.keys(SCANNABLE_FIELDS).filter((tool) => !selects('PostToolUse', tool));
    expect(missed, 'tools scanned on the way in but not on the way out').toEqual([]);
  });

  it('PostToolUse selects the mcp__* family, which the mapping matches by prefix', () => {
    const mcp = { content: [{ type: 'text', text: 'x' }] };
    expect(scannableResponseFields('mcp__everything__echo', mcp)).not.toEqual([]);
    expect(selects('PostToolUse', 'mcp__everything__echo')).toBe(true);
  });

  it('does not select tools it has no mapping for', () => {
    // The control: a matcher widened to `.*` would pass everything above.
    expect(selects('PostToolUse', 'view_image')).toBe(false);
    expect(selects('PostToolUse', 'xmcp__a__b')).toBe(false);
    expect(selects('PreToolUse', 'webrun')).toBe(false);
    expect(selects('PreToolUse', 'mcp__everything__echo')).toBe(false);
  });
});
