import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  readWorkspaceSettings,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { dbPath as dbPathOf } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { triggerPolicySync } from '../../src/attached/sync-trigger.ts';

// What forks a child, and — much more importantly — what does not.
//
// The spawn is the expensive half of this mechanism: a machine that forks a
// node process every fifteen minutes for the life of the install, only for that
// process to read its configuration and exit, is the failure this ordering
// exists to prevent. Almost every machine is unattached, so that is the common
// case rather than an edge one.

const ENDPOINT = 'https://aka.example-org.internal';
const ATTACHED_AT = '2026-08-24T10:00:00.000Z';
const KEY = 'not-a-real-key-5e2c8a4f7b19';

let home: string;
let spawned: string[];

const configFor = (base: string): PluginConfig => ({
  settings: readWorkspaceSettings(base),
  dataDir: dataDirOf(base),
  dbPath: dbPathOf(base),
  settingsDir: settingsDirOf(base),
  onboarded: true,
  provider: { provider: 'anthropic' },
});

const deps = (throttledResult = false) => ({
  // Built from a path rather than written as a `file:///` literal: a
  // hand-written absolute-path URL is POSIX-only, and this one is turned back
  // into a path by the code under test, so on Windows the literal form would
  // produce something no platform can resolve.
  scriptUrl: pathToFileURL(join(tmpdir(), 'aka-sync-fixture', 'sync.js')),
  spawnChild: (path: string) => spawned.push(path),
  isThrottled: () => throttledResult,
});

const attach = (base: string): void => {
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: ATTACHED_AT } },
    base,
  );
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: KEY,
  });
};

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-sync-trigger-'));
  spawned = [];
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

describe('what does not fork a child', () => {
  it('a machine that has never attached', () => {
    triggerPolicySync(configFor(home), deps());
    expect(spawned).toEqual([]);
  });

  it('a machine whose settings name a plane but which holds no credential', () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: ATTACHED_AT } },
      home,
    );
    triggerPolicySync(configFor(home), deps());
    expect(spawned).toEqual([]);
  });

  it('a machine holding a credential for a different deployment', () => {
    attach(home);
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: 'https://aka.elsewhere.internal', attachedAt: ATTACHED_AT },
      },
      home,
    );
    triggerPolicySync(configFor(home), deps());
    expect(spawned).toEqual([]);
  });

  it('an attached machine inside the throttle window', () => {
    attach(home);
    triggerPolicySync(configFor(home), deps(true));
    expect(spawned).toEqual([]);
  });
});

describe('what does', () => {
  it('an attached machine outside the window', () => {
    attach(home);
    triggerPolicySync(configFor(home), deps());
    expect(spawned).toHaveLength(1);
    expect(spawned[0]).toContain('sync.js');
  });
});

describe('the ordering between the attachment check and the throttle', () => {
  it('never consults the throttle for an unattached machine', () => {
    // Checking attachment FIRST is what keeps an unattached machine from
    // touching the marker file at all — and the marker lives in the data dir,
    // which a machine that never attached has no reason to have written to.
    let consulted = false;
    triggerPolicySync(configFor(home), {
      ...deps(),
      isThrottled: () => {
        consulted = true;
        return false;
      },
    });
    expect(consulted).toBe(false);
    expect(spawned).toEqual([]);
  });

  it('consults it for an attached one', () => {
    // The positive control: without it, the assertion above would pass just as
    // well against a trigger that never consults the throttle at all.
    attach(home);
    let consulted = false;
    triggerPolicySync(configFor(home), {
      ...deps(),
      isThrottled: () => {
        consulted = true;
        return true;
      },
    });
    expect(consulted).toBe(true);
  });
});

describe('failure', () => {
  it('never throws, whatever the spawn does', () => {
    // It runs inside SessionStart, where a failure must cost a policy refresh
    // and never a session.
    attach(home);
    expect(() => {
      triggerPolicySync(configFor(home), {
        ...deps(),
        spawnChild: () => {
          throw new Error('fork failed');
        },
      });
    }).not.toThrow();
  });
});
