// The tool hooks only see what their `hooks.json` matcher selects, and nothing
// else in the suite reads the matcher: a tool mapped in SCANNABLE_FIELDS or
// tool-response.ts but missing from the matcher is never scanned, with no error
// anywhere. The tool names below are the ones a live codex-cli 0.160.0 sends,
// including for calls nested in a code-mode `exec`.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { SCANNABLE_FIELDS } from '../../src/hooks/pre-tool-use-decision.ts';
import { scannableResponseFields } from '../../src/hooks/tool-response.ts';

interface Manifest {
  hooks: Record<string, { matcher?: string }[]>;
}

const manifest = JSON.parse(
  readFileSync(
    join(fileURLToPath(new URL('.', import.meta.url)), '..', '..', 'hooks', 'hooks.json'),
    'utf8',
  ),
) as Manifest;

// Codex matches the matcher as a regex against the whole tool name.
function selects(event: string, toolName: string): boolean {
  return (manifest.hooks[event] ?? []).some(
    (entry) => entry.matcher === undefined || new RegExp(`^(?:${entry.matcher})$`).test(toolName),
  );
}

describe('hooks.json tool matchers', () => {
  it('PreToolUse selects every tool with scannable input fields', () => {
    for (const tool of Object.keys(SCANNABLE_FIELDS)) {
      expect(selects('PreToolUse', tool), tool).toBe(true);
    }
  });

  it('PostToolUse selects every tool whose output is scanned', () => {
    const block = [{ type: 'input_text', text: 'x' }];
    const mcp = { content: [{ type: 'text', text: 'x' }] };
    expect(scannableResponseFields('webrun', block)).not.toEqual([]);
    expect(scannableResponseFields('mcp__everything__echo', mcp)).not.toEqual([]);
    for (const tool of ['Bash', 'webrun', 'mcp__everything__echo']) {
      expect(selects('PostToolUse', tool), tool).toBe(true);
    }
  });

  it('does not select tools it has no mapping for', () => {
    expect(selects('PostToolUse', 'view_image')).toBe(false);
    expect(selects('PostToolUse', 'xmcp__a__b')).toBe(false);
  });
});
