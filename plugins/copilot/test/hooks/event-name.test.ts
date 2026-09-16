import { readdirSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import { CLI_EVENTS, readEventName, VSCODE_EVENTS } from '../../src/hooks/event-name.ts';

// The event a hook was started for comes from argv and from nowhere else. The
// reason is in the recordings: seven of the eight CLI payloads carry no event
// name at all, so a dispatcher keyed on the payload cannot tell them apart —
// and one keyed on the payload SHAPE would be a second source of truth for a
// fact argv already carries.
describe('readEventName', () => {
  it('reads the token at argv[2]', () => {
    expect(readEventName(['node', 'pre-tool-use.js', 'preToolUse'])).toBe('preToolUse');
  });

  it('reads a VS Code PascalCase token at the same index', () => {
    expect(readEventName(['node', 'pre-tool-use.js', 'PreToolUse'])).toBe('PreToolUse');
  });

  it('accepts the manifest path that follows it without confusing the two', () => {
    // The real argv a hook command builds: event token, then the plugin
    // manifest. See MANIFEST_ARGV_INDEX in ../src/build-info.ts.
    expect(readEventName(['node', 'session-start.js', 'sessionStart', '/p/plugin.json'])).toBe(
      'sessionStart',
    );
  });

  it('answers undefined for a token this build does not know', () => {
    expect(readEventName(['node', 'x.js', 'postResult'])).toBeUndefined();
    expect(readEventName(['node', 'x.js', 'prePRDescription'])).toBeUndefined();
  });

  it('answers undefined when argv carries no token at all', () => {
    expect(readEventName(['node', 'x.js'])).toBeUndefined();
  });

  it('does not accept the empty string', () => {
    expect(readEventName(['node', 'x.js', ''])).toBeUndefined();
  });

  it('is case-sensitive across the two vocabularies', () => {
    // The two hosts spell the same event differently and this build keeps them
    // apart, because the payload dialect differs too: reading a PascalCase
    // token as its camelCase twin would place a VS Code payload on the CLI's
    // field table.
    expect(readEventName(['node', 'x.js', 'pretooluse'])).toBeUndefined();
    expect(readEventName(['node', 'x.js', 'SessionEnd'])).toBeUndefined();
  });
});

describe('the accepted vocabularies', () => {
  it('carries the fifteen event names the CLI loader accepted', () => {
    // Recorded on 1.0.83, not documented — and the count is the claim: the
    // schema lists seventeen, and the two the loader logged as unknown
    // (postResult, prePRDescription) are deliberately absent.
    expect(CLI_EVENTS).toHaveLength(15);
    expect(CLI_EVENTS).not.toContain('postResult');
    expect(CLI_EVENTS).not.toContain('prePRDescription');
  });

  it('carries the eight event names VS Code agent mode fires', () => {
    expect(VSCODE_EVENTS).toHaveLength(8);
  });

  it('keeps the two vocabularies disjoint', () => {
    // Not cosmetic. The dialect is sniffed from the payload, but the token is
    // an independent signal, and an overlap would make one token ambiguous.
    const cli = new Set<string>(CLI_EVENTS);
    expect(VSCODE_EVENTS.filter((name) => cli.has(name))).toEqual([]);
  });

  it('names every event a recorded fixture exists for', () => {
    // The recordings are the evidence this vocabulary rests on, so the
    // vocabulary is held to them rather than the other way round: a fixture
    // whose event this module does not accept would be a payload the adapter
    // could never dispatch.
    const recorded = readdirSync(new URL('../fixtures/cli/', import.meta.url))
      .filter((name) => name.endsWith('.json'))
      .map((name) => name.replace(/\.json$/, ''));
    expect(recorded.length).toBeGreaterThan(0);
    for (const event of recorded) expect(CLI_EVENTS).toContain(event);
  });
});
