import { randomUUID } from 'node:crypto';
import { mkdirSync, utimesSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

import { readClaudeAccountEnv } from '@akasecurity/plugin-sdk/account';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { locateSessionTranscript } from '../../src/hooks/account-stamp.ts';
import type * as SessionTranscript from '../../src/hooks/session-transcript.ts';
import { findSessionTranscript } from '../../src/hooks/session-transcript.ts';
import type * as Shared from '../../src/hooks/shared.ts';
import type { Device } from '../helpers/account-fixture.ts';
import { device } from '../helpers/account-fixture.ts';

const failOpen = vi.hoisted(() => ({ count: vi.fn() }));
vi.mock('../../src/hooks/shared.ts', async (importOriginal) => ({
  ...(await importOriginal<typeof Shared>()),
  countFailOpen: failOpen.count,
}));

// The directory walk, made to fault on request; otherwise the real one.
const walk = vi.hoisted(() => ({ faults: false }));
vi.mock('../../src/hooks/session-transcript.ts', async (importOriginal) => {
  const real = await importOriginal<typeof SessionTranscript>();
  return {
    ...real,
    findSessionTranscript: (sessionId: string | undefined) => {
      if (walk.faults) throw new Error('refused by the test');
      return real.findSessionTranscript(sessionId);
    },
  };
});

let dev: Device;
beforeEach(() => {
  failOpen.count.mockClear();
  walk.faults = false;
  dev = device({ captures: [], audit: [], inventory: [] });
});
afterEach(() => {
  dev.dispose();
});

/** A transcript file for `sessionId` under `root`, in a project directory called `project`. */
function plant(root: string, project: string, sessionId: string, mtimeSeconds?: number): string {
  const dir = join(root, project);
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${sessionId}.jsonl`);
  writeFileSync(path, '');
  if (mtimeSeconds !== undefined) utimesSync(path, mtimeSeconds, mtimeSeconds);
  return path;
}

describe('findSessionTranscript', () => {
  it('finds the session file under the default projects directory', () => {
    const t = dev.transcript(randomUUID());
    expect(findSessionTranscript(t.sessionId)).toBe(t.path);
  });

  it('finds the session file under the projects directory of CLAUDE_CONFIG_DIR', () => {
    const configDir = join(dev.root, 'elsewhere');
    vi.stubEnv('CLAUDE_CONFIG_DIR', configDir);
    const sessionId = randomUUID();
    const path = plant(join(configDir, 'projects'), 'some-project', sessionId);
    expect(findSessionTranscript(sessionId)).toBe(path);
  });

  it('finds the session file under ~/.claude when CLAUDE_CONFIG_DIR is unset', () => {
    const home = join(dev.root, 'another-home');
    vi.stubEnv('HOME', home);
    vi.stubEnv('USERPROFILE', home);
    vi.stubEnv('CLAUDE_CONFIG_DIR', undefined);
    expect(readClaudeAccountEnv().configDir).toBeUndefined();
    const sessionId = randomUUID();
    const path = plant(join(home, '.claude', 'projects'), 'some-project', sessionId);
    expect(findSessionTranscript(sessionId)).toBe(path);
  });

  it.each([
    ['the first listed', 'a-project', 'b-project'],
    ['the last listed', 'b-project', 'a-project'],
  ])('of two copies answers the one written most recently, which is %s', (_which, newer, older) => {
    const sessionId = randomUUID();
    const root = join(dev.home, '.claude', 'projects');
    const stale = plant(root, older, sessionId, 1_000);
    const fresh = plant(root, newer, sessionId, 2_000);
    expect(stale).not.toBe(fresh);
    expect(findSessionTranscript(sessionId)).toBe(fresh);
  });

  it('answers nothing for a session that has no file, and for no session', () => {
    dev.transcript(randomUUID());
    expect(findSessionTranscript(randomUUID())).toBeUndefined();
    expect(findSessionTranscript(undefined)).toBeUndefined();
  });

  it.each([
    ['a path that climbs out of the projects directory', '../../outside'],
    ['a path with a separator', 'example/other'],
    ['an empty id', ''],
    ['a parent directory', '..'],
    ['an id longer than a session id can be', 'a'.repeat(129)],
  ])('answers nothing for %s, though the file it would name exists', (_what, sessionId) => {
    dev.transcript(randomUUID());
    const named = join(dev.home, '.claude', 'projects', 'example', `${sessionId}.jsonl`);
    mkdirSync(dirname(named), { recursive: true });
    writeFileSync(named, '');
    expect(findSessionTranscript(sessionId)).toBeUndefined();
  });
});

describe('locateSessionTranscript', () => {
  it('finds the file on a scoped attachment whose work-subscription setting is on', () => {
    dev.attach();
    const t = dev.transcript(randomUUID());
    expect(locateSessionTranscript(dev.config(), t.sessionId)).toBe(t.path);
  });

  it.each<[string, () => void]>([
    ['no attachment', () => undefined],
    [
      'a machine-wide attachment',
      () => {
        dev.attach({ mode: 'machine' });
      },
    ],
    [
      'work subscriptions switched off',
      () => {
        dev.attach({ workSubscriptions: 'off' });
      },
    ],
  ])('looks nowhere with %s', (_what, setUp) => {
    setUp();
    const t = dev.transcript(randomUUID());
    expect(locateSessionTranscript(dev.config(), t.sessionId)).toBeUndefined();
  });

  it('looks nowhere for a call with no session', () => {
    dev.attach();
    dev.transcript(randomUUID());
    expect(locateSessionTranscript(dev.config(), undefined)).toBeUndefined();
  });

  it('answers nothing and counts one fail-open when looking faults', () => {
    dev.attach();
    const t = dev.transcript(randomUUID());
    walk.faults = true;
    expect(locateSessionTranscript(dev.config(), t.sessionId)).toBeUndefined();
    expect(failOpen.count).toHaveBeenCalledTimes(1);
  });
});
