/**
 * The body-expiry trigger.
 *
 * What it has to get right is not "does it spawn" but WHEN IT DOES NOT. Expiry
 * is off by default, so on almost every machine the correct behaviour is to do
 * nothing at all — and to leave no trace of having considered it, because a
 * marker file appearing on disk is a feature nobody switched on announcing
 * itself.
 */
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import {
  CONTENT_RETENTION_MARKER_NAME,
  CONTENT_RETENTION_SCRIPT_NAME,
  CONTENT_RETENTION_THROTTLE_MS,
  triggerContentRetention,
} from '../src/content-retention-trigger.ts';

let dir: string;

function config(enabled: boolean): PluginConfig {
  return {
    dataDir: dir,
    settingsDir: dir,
    settings: {
      specVersion: 8,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
      bodyRetention: { enabled, retainDays: 30 },
    },
  } as unknown as PluginConfig;
}

describe('triggerContentRetention', () => {
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'aka-retention-trigger-'));
  });
  afterEach(() => {
    removeTree(dir);
  });

  it('spawns the sibling child when expiry is on', () => {
    const spawned: string[] = [];
    triggerContentRetention(config(true), {
      spawnChild: (p) => spawned.push(p),
      isThrottled: () => false,
    });

    expect(spawned).toHaveLength(1);
    expect(spawned[0]).toContain(CONTENT_RETENTION_SCRIPT_NAME);
  });

  it('does nothing while expiry is off', () => {
    const spawned: string[] = [];
    triggerContentRetention(config(false), { spawnChild: (p) => spawned.push(p) });
    expect(spawned).toHaveLength(0);
  });

  it('writes no marker while expiry is off', () => {
    // The ordering assertion, and the reason the setting is checked before the
    // throttle. Probing the throttle writes the marker as a side effect, so a
    // trigger that asked in the other order would leave this file on the disk
    // of every machine that never switched expiry on.
    triggerContentRetention(config(false), { spawnChild: () => undefined });
    expect(readdirSync(dir)).not.toContain(CONTENT_RETENTION_MARKER_NAME);
  });

  it('obeys the throttle', () => {
    const spawned: string[] = [];
    triggerContentRetention(config(true), {
      spawnChild: (p) => spawned.push(p),
      isThrottled: () => true,
    });
    expect(spawned).toHaveLength(0);
  });

  it('throttles itself across calls through the real marker', () => {
    const spawned: string[] = [];
    const deps = { spawnChild: (p: string) => spawned.push(p) };
    triggerContentRetention(config(true), deps);
    triggerContentRetention(config(true), deps);

    // The real `throttled` helper, not an injected stub — the second call must
    // be suppressed by the marker the first one wrote.
    expect(spawned).toHaveLength(1);
    expect(readdirSync(dir)).toContain(CONTENT_RETENTION_MARKER_NAME);
  });

  it('never throws when the spawn fails', () => {
    // It runs inside SessionStart. A failure here must cost a pass, never a
    // session.
    expect(() => {
      triggerContentRetention(config(true), {
        isThrottled: () => false,
        spawnChild: () => {
          throw new Error('EAGAIN');
        },
      });
    }).not.toThrow();
  });

  it('waits hours rather than minutes', () => {
    // Not a magic-number restatement: it pins the CLASS. This bounds nothing a
    // user or a deployment is waiting on, so a window in minutes would be a
    // child spawned all day for local disk hygiene.
    expect(CONTENT_RETENTION_THROTTLE_MS).toBeGreaterThanOrEqual(60 * 60 * 1000);
  });
});
