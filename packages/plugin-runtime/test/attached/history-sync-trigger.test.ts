import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  openLocalDatabase,
  readWorkspaceSettings,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { dbPath as dbPathOf } from '@akasecurity/plugin-sdk';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import {
  HISTORY_SYNC_MARKER_NAME,
  triggerHistorySync,
} from '../../src/attached/history-sync-trigger.ts';
import { SYNC_MARKER_NAME } from '../../src/attached/sync-trigger.ts';

// What forks a child, and — much more importantly — what does not.
//
// This job has one gate the policy pull does not: a GRANT for history. Without
// it a pass only delivers what the live path owes, so a machine that owes
// nothing must not pay a process spawn or write a throttle marker.

const ENDPOINT = 'https://plane.example.test';
const OTHER_ENDPOINT = 'https://other.example.test';
const ATTACHED_AT = '2026-08-24T10:00:00.000Z';
// Deliberately bland: what the write path needs is a non-empty string, not
// something that looks like a real credential.
const FIXTURE = 'placeholder';

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
  scriptUrl: pathToFileURL(join(home, 'history-sync.js')),
  spawnChild: (path: string) => spawned.push(path),
  isThrottled: () => throttledResult,
});

/** Attach the machine, optionally granting the history share. */
function setup(opts: { grantFor?: string; credential?: boolean } = {}): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: ATTACHED_AT },
      ...(opts.grantFor === undefined
        ? {}
        : {
            historySyncConsent: {
              acknowledgedAt: ATTACHED_AT,
              payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
              endpoint: opts.grantFor,
            },
          }),
    },
    home,
  );
  if (opts.credential !== false) {
    writeControlPlaneCredential(settingsDirOf(home), {
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: FIXTURE,
      mintedAt: ATTACHED_AT,
    });
  }
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-history-trigger-'));
  spawned = [];
});

afterEach(() => {
  removeTree(home);
});

describe('triggerHistorySync — what it refuses to fork', () => {
  it('does nothing on a machine that was never attached', () => {
    triggerHistorySync(configFor(home), deps());
    expect(spawned).toEqual([]);
  });

  // Without a grant only the live path's own debt can start a pass, so a
  // machine that owes nothing pays no spawn and writes no marker.
  it('does nothing without a grant when the live path owes nothing', () => {
    setup();
    triggerHistorySync(configFor(home), deps());
    expect(spawned).toEqual([]);
  });

  // A grant travels with the deployment it named. Re-pointing a fleet must not
  // start sending old activity to the new destination on an old answer.
  it('does nothing when the grant names a different deployment', () => {
    setup({ grantFor: OTHER_ENDPOINT });
    triggerHistorySync(configFor(home), deps());
    expect(spawned).toEqual([]);
  });

  it('does nothing without a usable credential', () => {
    setup({ grantFor: ENDPOINT, credential: false });
    triggerHistorySync(configFor(home), deps());
    expect(spawned).toEqual([]);
  });

  // Checked LAST, so the cases above never write the marker at all.
  it('does nothing while throttled', () => {
    setup({ grantFor: ENDPOINT });
    triggerHistorySync(configFor(home), deps(true));
    expect(spawned).toEqual([]);
  });
});

describe('triggerHistorySync — when it does fork', () => {
  it('forks without a grant when the live path owes a capture', () => {
    setup();
    const asked: number[] = [];
    triggerHistorySync(configFor(home), {
      ...deps(),
      hasOwedLiveCaptures: (_dir: string, sinceMs: number) => {
        asked.push(sinceMs);
        return true;
      },
    });
    expect(spawned).toHaveLength(1);
    expect(asked).toEqual([Date.parse(ATTACHED_AT)]);
  });

  it('does not open the store without a grant while a pass ran inside the window', () => {
    setup();
    mkdirSync(dataDirOf(home), { recursive: true });
    writeFileSync(join(dataDirOf(home), HISTORY_SYNC_MARKER_NAME), String(Date.now()));
    let asked = 0;
    triggerHistorySync(configFor(home), {
      ...deps(),
      hasOwedLiveCaptures: () => {
        asked += 1;
        return true;
      },
    });
    expect(asked).toBe(0);
    expect(spawned).toEqual([]);
  });

  it('reads the live debt from the store itself', () => {
    setup();
    const db = openLocalDatabase(dataDirOf(home));
    try {
      db.auditEvents.ensureSessionRoot('s', ATTACHED_AT);
      db.auditEvents.insertAuditEvent({
        id: 's-prompt',
        eventType: 'prompt',
        rootSessionId: 's',
        parentId: 's',
        startedAt: new Date(Date.parse(ATTACHED_AT) + 60_000).toISOString(),
        content: 'owed text',
      });
      db.historySync.markCaptureOwed('s-prompt');
    } finally {
      db.close();
    }
    triggerHistorySync(configFor(home), deps());
    expect(spawned).toHaveLength(1);
  });

  it('forks the sibling script once every gate has passed', () => {
    setup({ grantFor: ENDPOINT });
    triggerHistorySync(configFor(home), deps());
    expect(spawned).toHaveLength(1);
    expect(spawned[0]).toContain('history-sync.js');
  });

  // It runs inside SessionStart. A failure here must cost a pass, never a
  // session.
  it('never throws, whatever the spawn does', () => {
    setup({ grantFor: ENDPOINT });
    expect(() => {
      triggerHistorySync(configFor(home), {
        ...deps(),
        spawnChild: () => {
          throw new Error('fork failed');
        },
      });
    }).not.toThrow();
  });
});

describe('triggerHistorySync — pacing', () => {
  // A marker name IS the gate's identity. Sharing one with the policy pull would
  // let whichever job ran first suppress the other for the whole window, and
  // neither would look wrong.
  it('paces itself on a marker no other job uses', () => {
    expect(HISTORY_SYNC_MARKER_NAME).not.toBe(SYNC_MARKER_NAME);
  });

  it('asks the throttle about the data dir it was configured with', () => {
    setup({ grantFor: ENDPOINT });
    const asked: string[] = [];
    triggerHistorySync(configFor(home), {
      ...deps(),
      isThrottled: (dir) => {
        asked.push(dir);
        return false;
      },
    });
    expect(asked).toEqual([dataDirOf(home)]);
  });
});
