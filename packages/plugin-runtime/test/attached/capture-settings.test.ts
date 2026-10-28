import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { ATTACHED_CAPTURE_SETTINGS_FILENAME } from '@akasecurity/persistence';
import type { PolicyBundle } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  readHookCaptureSettings,
  toolOutputForwardFor,
  writeHookCaptureSettings,
} from '../../src/attached/capture-settings.ts';
import { createPolicyStore } from '../../src/attached/policy-store.ts';

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-capture-settings-'));
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const file = (): string => join(dir, ATTACHED_CAPTURE_SETTINGS_FILENAME);

const bundle = (capture?: PolicyBundle['capture']): PolicyBundle => ({
  version: 'v1',
  policies: [],
  customKeywords: [],
  fetchedAt: '2026-10-28T10:00:00.000Z',
  ...(capture === undefined ? {} : { capture }),
});

describe('the hook capture settings file', () => {
  it('reads nothing when there is no file', () => {
    expect(readHookCaptureSettings(dir)).toEqual({});
  });

  it('round-trips the members a hook reads, and leaves the repository list out', async () => {
    await writeHookCaptureSettings(dir, {
      toolOutput: { maxChars: 4096 },
      sessionHold: true,
      reviewValueRepos: ['github.com/acme/app'],
    });
    expect(readHookCaptureSettings(dir)).toEqual({
      toolOutput: { maxChars: 4096 },
      sessionHold: true,
    });
    expect(readFileSync(file(), 'utf8')).not.toContain('github.com');
  });

  it('removes the file when nothing a hook reads is set', async () => {
    await writeHookCaptureSettings(dir, { sessionHold: true });
    expect(existsSync(file())).toBe(true);
    await writeHookCaptureSettings(dir, { reviewValueRepos: ['github.com/acme/app'] });
    expect(existsSync(file())).toBe(false);
    await writeHookCaptureSettings(dir, undefined);
    expect(existsSync(file())).toBe(false);
  });

  it('reads a malformed, out-of-range or unversioned file as nothing set', () => {
    for (const body of [
      'not json',
      '[]',
      JSON.stringify({ toolOutput: { maxChars: 10 } }),
      JSON.stringify({ v: 1, toolOutput: { maxChars: 0 } }),
      JSON.stringify({ v: 1, sessionHold: 'yes' }),
    ]) {
      writeFileSync(file(), body);
      expect(readHookCaptureSettings(dir), body).toEqual({});
    }
  });

  it('is written with the policy cache, and removed when a later bundle drops the block', async () => {
    const store = createPolicyStore(dir);
    await store.write(bundle({ toolOutput: { maxChars: 100 }, sessionHold: true }));
    expect(readHookCaptureSettings(dir)).toEqual({
      toolOutput: { maxChars: 100 },
      sessionHold: true,
    });
    await store.write({ ...bundle(), version: 'v2' });
    expect(existsSync(file())).toBe(false);
  });
});

describe('toolOutputForwardFor', () => {
  it('marks nothing without a tool output setting', () => {
    expect(toolOutputForwardFor({}, 'github.com/acme/app')).toBeUndefined();
  });

  it('marks every capture when the setting names no repositories', () => {
    expect(toolOutputForwardFor({ toolOutput: { maxChars: 9 } }, undefined)).toEqual({
      maxChars: 9,
    });
  });

  it('marks only a capture keyed to a named repository', () => {
    const settings = { toolOutput: { maxChars: 9, repos: ['github.com/acme/app'] } };
    expect(toolOutputForwardFor(settings, 'github.com/acme/app')).toEqual({ maxChars: 9 });
    expect(toolOutputForwardFor(settings, 'github.com/acme/other')).toBeUndefined();
    expect(toolOutputForwardFor(settings, undefined)).toBeUndefined();
  });
});
