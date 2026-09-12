import { mkdirSync, writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import type * as LocalOps from '@akasecurity/local-ops';
import {
  applyOnboarding,
  ATTACHED_FORWARD_STATE_FILENAME,
  BREAKER_COOLDOWN_MS,
  dataDir,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { syncNow } from '../../app/(app)/settings/actions.ts';
import {
  SYNC_KEY_UNUSABLE,
  SYNC_NO_CLI_ENTRY,
  SYNC_NOT_ATTACHED,
  SYNC_NOT_GRANTED,
  SYNC_PAUSED,
  SYNC_SPAWN_FAILED,
} from '../../app/lib/action-refusals.ts';
import { tempHomes } from '../helpers/temp-home.ts';

// `syncNow` is the only action on this surface that starts a PROCESS, and the
// three things worth asserting about it all follow from that: it must not start
// one on a machine that would send nothing, it must report a start that never
// happened, and it must aim at the real AKA home rather than whatever directory
// the dashboard happens to be running from.
//
// The spawn is injected, and that matters more here than elsewhere: without the
// seam this suite would fork a real history pass against the developer's own
// store on every case — a live network send, and a test that would pass whether
// or not the action called anything at all.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});
vi.mock('next/cache', () => ({ revalidatePath: () => undefined }));

const spawn = vi.hoisted((): { bases: string[]; result: LocalOps.SyncRunStart } => ({
  bases: [],
  result: { started: true },
}));
vi.mock('@akasecurity/local-ops', async (importActual) => {
  const actual = await importActual<typeof LocalOps>();
  return {
    ...actual,
    triggerHistorySyncRun: (base: string): LocalOps.SyncRunStart => {
      spawn.bases.push(base);
      return spawn.result;
    },
  };
});

// Homes are removed when this FILE finishes, not after each test: the store
// app/lib/db.ts opens under them stays open, and Windows will not delete a
// directory a handle still holds. See the helper.
const newHome = tempHomes('aka-web-sync-now-');

let home: string;

const ENDPOINT = 'https://plane.example.com';
const AT = '2026-09-12T00:00:00.000Z';
// One character. The shape asks only for a non-empty string, and nothing here
// authenticates against anything — a realistic-looking fixture would be a value
// that gets copied somewhere it matters.
const KEY = 'k';

const akaHome = (): string => join(home, '.aka');

/** A machine that is attached, holds a matching key, and has granted the sweep. */
function attachedAndSharing(): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
      historySyncConsent: {
        acknowledgedAt: AT,
        payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
        endpoint: ENDPOINT,
      },
    },
    akaHome(),
  );
  writeControlPlaneCredential(settingsDir(akaHome()), {
    specVersion: 1,
    endpoint: ENDPOINT,
    apiKey: KEY,
  });
}

/** Record a breaker that opened at `openedAtMs`, as the forward path would. */
function openBreaker(openedAtMs: number): void {
  const dir = dataDir(akaHome());
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, ATTACHED_FORWARD_STATE_FILENAME),
    JSON.stringify({ consecutiveFailures: 3, openedAtMs, lastFailure: 'unreachable' }),
  );
}

beforeEach(() => {
  home = newHome();
  osHome.dir = home;
  spawn.bases = [];
  spawn.result = { started: true };
});

describe('syncNow', () => {
  it('starts a pass on a machine that is attached, keyed and sharing', async () => {
    attachedAndSharing();

    await expect(syncNow()).resolves.toEqual({ ok: true });
    expect(spawn.bases).toHaveLength(1);
  });

  // The aim, not merely that something was aimed. This dashboard has no
  // `--home` concept, so the one base it can mean is the real AKA home — and a
  // pass started against any other one drains a store nobody is looking at
  // while the panel keeps showing the same backlog.
  it('aims the pass at this machine’s own AKA home', async () => {
    attachedAndSharing();
    await syncNow();

    expect(spawn.bases).toEqual([akaHome()]);
  });

  // ─── The gate, re-derived from disk ────────────────────────────────────────
  //
  // The panel offers no button in any of these states, so a request that
  // reaches here came from a page open since before the state changed. Each
  // must be a sentence rather than a pass that starts and dies, and — the part
  // nothing else can see — NOTHING may be spawned.

  it('refuses, and spawns nothing, on a standalone machine', async () => {
    await expect(syncNow()).resolves.toEqual({ ok: false, error: SYNC_NOT_ATTACHED });
    expect(spawn.bases).toEqual([]);
  });

  it('refuses, and spawns nothing, when the machine holds no key', async () => {
    applyOnboarding(
      {
        runMode: 'attached',
        controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
        historySyncConsent: {
          acknowledgedAt: AT,
          payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
          endpoint: ENDPOINT,
        },
      },
      akaHome(),
    );

    await expect(syncNow()).resolves.toEqual({ ok: false, error: SYNC_KEY_UNUSABLE });
    expect(spawn.bases).toEqual([]);
  });

  // A key that parses perfectly and names another deployment. The credential
  // read only catches this because it is given the descriptor to compare
  // against — without that it reads as usable, and the pass starts.
  it('refuses a key minted for a different deployment', async () => {
    attachedAndSharing();
    writeControlPlaneCredential(settingsDir(akaHome()), {
      specVersion: 1,
      endpoint: 'https://old.example.com',
      apiKey: KEY,
    });

    await expect(syncNow()).resolves.toEqual({ ok: false, error: SYNC_KEY_UNUSABLE });
    expect(spawn.bases).toEqual([]);
  });

  it('refuses, and spawns nothing, with no grant to send the backlog', async () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: AT } },
      akaHome(),
    );
    writeControlPlaneCredential(settingsDir(akaHome()), {
      specVersion: 1,
      endpoint: ENDPOINT,
      apiKey: KEY,
    });

    await expect(syncNow()).resolves.toEqual({ ok: false, error: SYNC_NOT_GRANTED });
    expect(spawn.bases).toEqual([]);
  });

  // A grant recorded against an older payload shape authorizes nothing today,
  // and the drain would refuse it anyway. Checked here so the refusal is a
  // sentence on the page rather than a pass that starts and does nothing.
  it('refuses a grant recorded against an older payload version', async () => {
    attachedAndSharing();
    applyOnboarding(
      {
        historySyncConsent: {
          acknowledgedAt: AT,
          payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1,
          endpoint: ENDPOINT,
        },
      },
      akaHome(),
    );

    await expect(syncNow()).resolves.toEqual({ ok: false, error: SYNC_NOT_GRANTED });
    expect(spawn.bases).toEqual([]);
  });

  // A grant that names another deployment must read as no grant at all — never
  // as a stale one to be resumed, which would send this machine's activity
  // somewhere the user never agreed to.
  it('refuses a grant given for a different deployment', async () => {
    attachedAndSharing();
    applyOnboarding(
      {
        historySyncConsent: {
          acknowledgedAt: AT,
          payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
          endpoint: 'https://elsewhere.example.com',
        },
      },
      akaHome(),
    );

    await expect(syncNow()).resolves.toEqual({ ok: false, error: SYNC_NOT_GRANTED });
    expect(spawn.bases).toEqual([]);
  });

  // ─── Held off after repeated failures ──────────────────────────────────────
  //
  // Checked here rather than left to the pass, because the pass is DETACHED: a
  // child that declines before opening the store says nothing back, so a button
  // that spawned one would appear to do nothing at all.

  it('refuses, and spawns nothing, while forwarding is paused', async () => {
    attachedAndSharing();
    openBreaker(Date.now());

    await expect(syncNow()).resolves.toEqual({ ok: false, error: SYNC_PAUSED });
    expect(spawn.bases).toEqual([]);
  });

  // The cooldown clears itself, and this gate is read at the moment of the
  // click rather than from the render that drew the button — so a panel drawn
  // seconds ago saying paused must not hold back a machine that is free again.
  it('starts a pass once the cooldown has elapsed', async () => {
    attachedAndSharing();
    openBreaker(Date.now() - BREAKER_COOLDOWN_MS - 1);

    await expect(syncNow()).resolves.toEqual({ ok: true });
    expect(spawn.bases).toHaveLength(1);
  });

  // ─── When the start itself fails ───────────────────────────────────────────
  //
  // Two reasons, two sentences, because they send the reader to different
  // places: one says a retry will never help on this install, the other says to
  // try again. Both say the queue is intact, which is the half a reader would
  // otherwise assume the worst about.

  it('reports an install with no aka command to re-invoke', async () => {
    attachedAndSharing();
    spawn.result = { started: false, reason: 'no-cli-entry' };

    await expect(syncNow()).resolves.toEqual({ ok: false, error: SYNC_NO_CLI_ENTRY });
  });

  it('reports a spawn that failed as worth retrying', async () => {
    attachedAndSharing();
    spawn.result = { started: false, reason: 'spawn-failed' };

    await expect(syncNow()).resolves.toEqual({ ok: false, error: SYNC_SPAWN_FAILED });
  });

  it('tells the reader nothing was lost, whichever way the start failed', () => {
    for (const message of [SYNC_NO_CLI_ENTRY, SYNC_SPAWN_FAILED]) {
      expect(message).toContain('Nothing was lost');
    }
  });
});
