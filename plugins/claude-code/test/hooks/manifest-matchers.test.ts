// The manifest decides which tool calls the hook is spawned for at all, and
// nothing else in the suite reads it. That is not a small gap: a matcher naming
// a tool the harness no longer sends produces a hook that never runs, and a
// hook that never runs is indistinguishable from one that ran and allowed —
// same empty stdout, same exit 0, no warning anywhere.
//
// It is how the subagent boundary went unguarded. The harness renamed that tool
// from `Task` to `Agent`; the matcher kept saying `Task`, so PreToolUse stopped
// firing on subagent spawns entirely and both the prompt scan and the model
// guard inside it became dead code, silently, on every current build.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { SCANNED_TOOL_NAMES } from '../../src/hooks/pre-tool-use-fields.ts';

interface HooksManifest {
  hooks: Record<string, { matcher?: string }[]>;
}

const manifest = JSON.parse(
  readFileSync(
    join(fileURLToPath(new URL('../../', import.meta.url)), 'hooks', 'hooks.json'),
    'utf8',
  ),
) as HooksManifest;

/** The matcher a hook event declares, as the regex the harness applies. */
function matcherFor(event: string): RegExp {
  const entry = manifest.hooks[event]?.[0];
  expect(entry, `${event} is registered`).toBeDefined();
  const matcher = entry?.matcher;
  expect(matcher, `${event} declares a matcher`).toBeTypeOf('string');
  return new RegExp(`^(?:${matcher ?? ''})$`);
}

describe('the PreToolUse matcher selects every tool the hook can act on', () => {
  it('matches each tool that has scannable fields', () => {
    // DERIVED from the field table rather than listed here, which is the whole
    // point: a tool added there and forgotten in the manifest fails this
    // without anyone remembering to extend a list.
    const matcher = matcherFor('PreToolUse');
    const missed = SCANNED_TOOL_NAMES.filter((tool) => !matcher.test(tool));
    expect(missed, 'tools the hook is never spawned for').toEqual([]);
  });

  it('matches the subagent spawn tool under both of its names', () => {
    // Pinned by name as well as through the table above, because the model
    // guard reads `Agent` whether or not it has scannable fields — the two
    // reasons this tool must be matched are independent, and the table only
    // covers one of them.
    const matcher = matcherFor('PreToolUse');
    expect(matcher.test('Agent'), 'the current spelling').toBe(true);
    expect(matcher.test('Task'), 'the spelling older harnesses send').toBe(true);
  });

  it('still matches an MCP tool, and does not match an unrelated one', () => {
    // The control: a matcher rewritten to `.*` would pass every assertion above
    // while removing the bound the hook's own cost argument rests on.
    const matcher = matcherFor('PreToolUse');
    expect(matcher.test('mcp__server__tool')).toBe(true);
    expect(matcher.test('Read')).toBe(false);
    expect(matcher.test('Glob')).toBe(false);
  });
});

describe('the model-switch hooks stay registered', () => {
  it.each(['PreModelSwitch', 'PostModelSwitch', 'UserPromptSubmit'])(
    '%s is present in the manifest',
    (event) => {
      // The prohibited-model feature is three seams and each rides a different
      // event. Losing one from the manifest silently removes a third of the
      // control with every test on its logic still green.
      expect(manifest.hooks[event], `${event} registered`).toBeDefined();
    },
  );
});
