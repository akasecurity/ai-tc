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

import { isParseableBinaryVersion } from '@akasecurity/persistence';
import { BASELINE_HOOK_EVENTS, HOST_FLOORS } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { SUBAGENT_TOOLS } from '../../src/hooks/model-guard.ts';
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
  it('matches each tool in the static field table', () => {
    // DERIVED rather than listed here, which is the whole point: a tool added
    // to that table and forgotten in the manifest fails this without anyone
    // remembering to extend a list. It speaks only for the STATIC table —
    // MultiEdit and the mcp__* family are dynamic handlers and are named
    // explicitly below instead.
    const matcher = matcherFor('PreToolUse');
    const missed = SCANNED_TOOL_NAMES.filter((tool) => !matcher.test(tool));
    expect(missed, 'tools the hook is never spawned for').toEqual([]);
  });

  it('matches every tool the model guard treats as a subagent spawn', () => {
    // DERIVED from the guard's own set, not restated. A rename has to reach
    // three places — that set, the field table and this matcher — and a test
    // cross-checking only two of them leaves the third for a human to notice,
    // which is exactly how `Task` outlived the rename.
    const matcher = matcherFor('PreToolUse');
    const missed = [...SUBAGENT_TOOLS].filter((tool) => !matcher.test(tool));
    expect(missed, 'spawn tools the guard can never see').toEqual([]);
    expect(SUBAGENT_TOOLS.has('Agent'), 'the current spelling is in the set').toBe(true);
  });

  it('matches the dynamic handlers the static table cannot speak for', () => {
    // MultiEdit and mcp__* reach fields through their own branches, so they are
    // absent from SCANNED_TOOL_NAMES and the derivation above says nothing
    // about them.
    const matcher = matcherFor('PreToolUse');
    expect(matcher.test('MultiEdit')).toBe(true);
    expect(matcher.test('mcp__server__tool')).toBe(true);
  });

  it('does not match an unrelated tool', () => {
    // The control: a matcher rewritten to `.*` would pass every assertion above
    // while removing the bound the hook's own cost argument rests on.
    const matcher = matcherFor('PreToolUse');
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

describe('every registered hook event has a decided host floor', () => {
  // A host that does not recognise an event DROPS THAT ENTRY and loads the rest
  // ("unknown hook event; entry ignored"), so registering a newly-introduced
  // event silently gives users on older hosts a plugin that looks healthy with
  // that protection missing. That is what happened with the model-switch pair.
  //
  // The floor table is TypeScript and this manifest is JSON, so no compile error
  // can bind them. This partition is the binding: every event is either old
  // enough that no supported host lacks it, or named by a row that knows which
  // version introduced it. Both directions, because a row naming an event the
  // manifest no longer registers is a floor nobody is being warned about.
  const registered = Object.keys(manifest.hooks);
  const gated = Object.values(HOST_FLOORS).flatMap((row) => [...row.hookEvents]);

  it('classifies every manifest event as baseline or floor-gated', () => {
    const unclassified = registered.filter(
      (event) => !BASELINE_HOOK_EVENTS.includes(event) && !gated.includes(event),
    );
    expect(unclassified, 'events with no decided floor').toEqual([]);
  });

  it('names no event the manifest does not register', () => {
    const stranded = [...BASELINE_HOOK_EVENTS, ...gated].filter(
      (event) => !registered.includes(event),
    );
    expect(stranded, 'floors for events that are not registered').toEqual([]);
  });

  it('puts no event in both halves', () => {
    const both = registered.filter(
      (event) => BASELINE_HOOK_EVENTS.includes(event) && gated.includes(event),
    );
    expect(both, 'events counted as both baseline and gated').toEqual([]);
  });

  it('gives every floor a version the comparator can actually read', () => {
    // `compareBinaryVersions` answers 0 for an unparseable input and 0 is not
    // < 0, so a typo here makes the row silently never fire — reintroducing the
    // exact silent absence the table exists to report.
    for (const [feature, row] of Object.entries(HOST_FLOORS)) {
      expect(isParseableBinaryVersion(row.since), `${feature} since=${row.since}`).toBe(true);
    }
  });

  it('actually gates something', () => {
    // The positive control: an empty table satisfies all three partitions above.
    expect(gated.length).toBeGreaterThan(0);
    expect(registered.length).toBeGreaterThan(BASELINE_HOOK_EVENTS.length);
  });
});
