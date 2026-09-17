// `readEventName` is the whole of how this package knows which event it is
// handling, so it is worth pinning on its own.
//
// The reason it reads argv rather than the payload is recorded rather than
// stylistic: seven of the eight live CLI recordings carry no event name at all.
// That fact is asserted here against the fixtures themselves, so a future
// recording that DID carry one could not quietly make the payload look like a
// viable second source.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  CLI_EVENTS,
  isHookEventName,
  readEventName,
  VSCODE_EVENTS,
} from '../../src/hooks/event-name.ts';

const FIXTURES = fileURLToPath(new URL('../fixtures/cli/', import.meta.url));

/** argv as node builds it: [execPath, scriptPath, ...args]. */
const argv = (...args: string[]): string[] => ['/usr/bin/node', '/plugin/scripts/x.js', ...args];

describe('readEventName', () => {
  it('accepts every CLI event name the host was observed loading', () => {
    // 15, recorded: a hooks file naming exactly these was loaded by CLI 1.0.83
    // without complaint. The count is asserted so a name dropped from the array
    // is a failure rather than a silently narrower dispatcher.
    expect(CLI_EVENTS).toHaveLength(15);
    for (const name of CLI_EVENTS) expect(readEventName(argv(name))).toBe(name);
  });

  it('accepts every VS Code event name', () => {
    expect(VSCODE_EVENTS).toHaveLength(8);
    for (const name of VSCODE_EVENTS) expect(readEventName(argv(name))).toBe(name);
  });

  it('refuses the two schema-only names the host logs as unknown', () => {
    // postResult and prePRDescription are in the CLI's own schema and are NOT
    // file-configurable in this build — the host logs them as unknown hook
    // events. Dispatching on one would be dispatching on something that never
    // arrives.
    expect(readEventName(argv('postResult'))).toBeUndefined();
    expect(readEventName(argv('prePRDescription'))).toBeUndefined();
  });

  it('returns undefined for an unknown token, a missing token and a near miss', () => {
    expect(readEventName(argv('notAnEvent'))).toBeUndefined();
    expect(readEventName(argv())).toBeUndefined();
    expect(readEventName([])).toBeUndefined();
    // Casing is the whole of what separates the two vocabularies, so a CLI name
    // spelled PascalCase (or the reverse) must not resolve.
    expect(readEventName(argv('PreToolUse'))).toBe('PreToolUse');
    expect(readEventName(argv('pretooluse'))).toBeUndefined();
    expect(readEventName(argv('SessionEnd'))).toBeUndefined();
  });

  it('reads argv[2] and not argv[3], which build-info.ts owns', () => {
    // The offset is load-bearing: the sibling plugins put their plugin manifest
    // path in argv[2], and here that slot is the event token, so the manifest
    // moves down one. A dispatcher reading the wrong slot would resolve the
    // manifest path as an event name and answer undefined for every event.
    expect(readEventName(argv('preToolUse', '/plugin/plugin.json'))).toBe('preToolUse');
    expect(readEventName(argv('/plugin/plugin.json', 'preToolUse'))).toBeUndefined();
  });

  it('isHookEventName narrows a plain string', () => {
    expect(isHookEventName('preToolUse')).toBe(true);
    expect(isHookEventName(undefined)).toBe(false);
    expect(isHookEventName('')).toBe(false);
  });
});

describe('the payload is not a second source for the event name', () => {
  it('leaves all but one recording with no event name in it at all', () => {
    // The premise of the argv design, asserted against the recordings rather
    // than restated from their README. `permissionRequest` is the one exception
    // and is named here so its arrival is deliberate: a dispatcher keyed on
    // `hookName` would work for exactly this one event, which is the worst
    // possible coverage — it looks implemented.
    const files = readdirSync(FIXTURES).filter((n) => n.endsWith('.json'));
    expect(files.length).toBeGreaterThan(1);

    const carrying = files.filter((name) => {
      const payload = JSON.parse(readFileSync(join(FIXTURES, name), 'utf8')) as Record<
        string,
        unknown
      >;
      return typeof payload.hookName === 'string';
    });
    expect(carrying).toEqual(['permissionRequest.json']);
  });
});
