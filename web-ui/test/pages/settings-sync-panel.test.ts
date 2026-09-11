import { mkdtempSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir,
  type LocalDatabase,
  openLocalDatabase,
  settingsDir,
  writeControlPlaneCredential,
  writeHistorySyncState,
} from '@akasecurity/persistence';
import { HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import type { ComponentProps, ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import SettingsPage from '../../app/(app)/settings/page.tsx';
import { SyncPanel } from '../../app/(app)/settings/SyncPanel.tsx';
import { emptyStore } from '../helpers/store-templates.ts';

// The sync panel's WIRING — the part no view test and no store test can see.
//
// `SyncPanelView` is pure and already pinned against its props; the ledger's
// per-kind partition is pinned against real rows and a real query plan. What
// sits between them is this route: it decides whether the panel is rendered at
// all, which of the mutually exclusive states the machine is in, and which
// numbers go in which bucket. Every one of those is a decision that compiles,
// lints and renders perfectly while being wrong — a panel of zeros on a machine
// that has never attached, bars on a machine that was never granted permission
// to send its backlog, claimed rows counted as delivered.
//
// An async Server Component is a plain function returning an element, so calling
// it and reading the props it hands down needs no renderer and no DOM. The store
// is real; only `homedir()` is redirected, since the page resolves ~/.aka from
// it and `n/no-process-env` rules out an env override.
const osHome = vi.hoisted(() => ({ dir: '' }));
vi.mock('node:os', async (importActual) => {
  const actual = await importActual<typeof NodeOs>();
  return { ...actual, homedir: () => osHome.dir };
});

let home: string;
let dir: string;

const ENDPOINT = 'https://plane.example.com';
const AT = '2026-09-12T00:00:00.000Z';
const T0 = Date.parse(AT);
// One character: the shape asks only for a non-empty string, and nothing here
// authenticates against anything.
const KEY = 'k';

const akaHome = (): string => join(home, '.aka');

// app/lib/db memoises its handle on globalThis across requests and HMR reloads,
// so a suite that does not drop it reads the PREVIOUS test's temp store.
function dropMemoisedDb(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-sync-panel-'));
  osHome.dir = home;
  dir = dataDir();
  emptyStore.seed(dir);
  dropMemoisedDb();
});

afterEach(() => {
  dropMemoisedDb();
  removeTree(home);
});

type PanelProps = ComponentProps<typeof SyncPanel>;

/** The panel's props, or null when the page rendered no panel at all. */
function renderPanel(): PanelProps | null {
  const element = SettingsPage() as ReactElement;
  const head = element.props as { children: unknown };
  const children = (Array.isArray(head.children) ? head.children : [head.children]).flat();
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    const node = child as ReactElement;
    // The panel is rendered inside a spacing wrapper, so look one level in too.
    if (node.type === SyncPanel) return node.props as PanelProps;
    const inner = (node.props as { children?: unknown } | undefined)?.children;
    if (inner !== undefined && (inner as ReactElement).type === SyncPanel) {
      return (inner as ReactElement).props as PanelProps;
    }
  }
  return null;
}

/** The panel's props, failing loudly rather than reading every field as undefined. */
function panel(): PanelProps['sync'] {
  const props = renderPanel();
  if (props === null) throw new Error('the page rendered no sync panel');
  return props.sync;
}

function attach(over: { endpoint?: string; label?: string } = {}): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: AT, ...over },
    },
    akaHome(),
  );
  writeControlPlaneCredential(settingsDir(akaHome()), {
    specVersion: 1,
    endpoint: over.endpoint ?? ENDPOINT,
    apiKey: KEY,
  });
}

function grant(over: { endpoint?: string; payloadVersion?: number } = {}): void {
  applyOnboarding(
    {
      historySyncConsent: {
        acknowledgedAt: AT,
        payloadVersion: over.payloadVersion ?? HISTORY_SYNC_PAYLOAD_VERSION,
        endpoint: over.endpoint ?? ENDPOINT,
      },
    },
    akaHome(),
  );
}

/** A session root with one structural leaf of each kind, and one capture. */
function seedSession(sessionId: string): void {
  const db = openLocalDatabase(dir);
  try {
    db.auditEvents.ensureSessionRoot(sessionId, AT);
    db.auditEvents.insertAuditEvent({
      id: `${sessionId}-llm`,
      eventType: 'llm_call',
      rootSessionId: sessionId,
      parentId: sessionId,
      startedAt: AT,
    });
    db.auditEvents.insertAuditEvent({
      id: `${sessionId}-tool`,
      eventType: 'tool_call',
      rootSessionId: sessionId,
      parentId: sessionId,
      startedAt: AT,
    });
    db.auditEvents.insertAuditEvent({
      id: `${sessionId}-prompt`,
      eventType: 'prompt',
      rootSessionId: sessionId,
      parentId: sessionId,
      startedAt: AT,
    });
  } finally {
    db.close();
  }
}

/** Run something against the store the page will read from. */
function withStore(fn: (db: LocalDatabase) => void): void {
  const db = openLocalDatabase(dir);
  try {
    fn(db);
  } finally {
    db.close();
  }
}

describe('the settings route — the sync panel', () => {
  // ─── Whether it appears at all ─────────────────────────────────────────────

  // A machine that has never attached is not a machine with nothing to sync —
  // it is one this panel has no business describing. Zeros in a bar and absence
  // look identical and mean different things, so the page renders neither.
  it('renders no panel at all on a standalone machine', () => {
    expect(renderPanel()).toBeNull();
  });

  // `runMode: 'attached'` alone is a stored answer, not an attachment: the
  // descriptor is what names a deployment, and without one there is nothing to
  // put in the panel's own header line.
  it('renders no panel for an attached run mode with no deployment named', () => {
    applyOnboarding({ runMode: 'attached' }, akaHome());
    expect(renderPanel()).toBeNull();
  });

  // The mirror, and the half a descriptor check alone would miss: a settings
  // file can carry a deployment descriptor while the run mode says standalone —
  // a hand-edit, or an administrator's overlay pinning the mode under a user
  // file that still names one. The machine sends nothing in that state, and a
  // panel describing a backlog to a deployment it does not talk to is the same
  // false claim as a panel of zeros.
  it('renders no panel when the run mode says standalone, whatever the file names', () => {
    applyOnboarding(
      { runMode: 'standalone', controlPlane: { endpoint: ENDPOINT, attachedAt: AT } },
      akaHome(),
    );
    expect(renderPanel()).toBeNull();
  });

  it('renders a panel once the machine is attached', () => {
    attach();
    expect(renderPanel()).not.toBeNull();
  });

  // ─── Which state it is in, and the order those questions are asked ──────────

  it('names the deployment’s label when it has one, and the endpoint otherwise', () => {
    attach({ label: 'Acme Prod' });
    expect(panel().deployment).toBe('Acme Prod');

    applyOnboarding({ controlPlane: { endpoint: ENDPOINT, attachedAt: AT } }, akaHome());
    dropMemoisedDb();
    expect(panel().deployment).toBe(ENDPOINT);
  });

  it('reports a machine holding no key as unable to use it, not as unshared', () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: AT } },
      akaHome(),
    );
    grant();

    const state = panel().state;
    expect(state.status).toBe('credential-unusable');
    if (state.status !== 'credential-unusable') throw new Error('unreachable');
    expect(state.detail).toContain('Re-attach');
  });

  // THE ORDER, which only shows itself when two things are wrong at once — and
  // that pairing is the ordinary one, because a re-attach elsewhere invalidates
  // the key and the grant together. "Not shared" describes a decision the user
  // made; on a machine whose key will not authenticate, they made no such
  // decision, and the sentence would send them to change a setting that is not
  // the problem.
  it('blames the key, not the sharing setting, when both are wrong', () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: AT } },
      akaHome(),
    );

    expect(panel().state.status).toBe('credential-unusable');
  });

  it('blames the key ahead of a grant that has merely gone stale', () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: AT } },
      akaHome(),
    );
    grant({ payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1 });

    expect(panel().state.status).toBe('credential-unusable');
  });

  // The one unusable reason a user can act on, and the only one whose fix
  // depends on which endpoint is which. Naming just one of them would send the
  // reader to undo the wrong half.
  it('names both endpoints when the key belongs to another deployment', () => {
    attach();
    grant();
    writeControlPlaneCredential(settingsDir(akaHome()), {
      specVersion: 1,
      endpoint: 'https://old.example.com',
      apiKey: KEY,
    });

    const state = panel().state;
    if (state.status !== 'credential-unusable') throw new Error('expected an unusable key');
    expect(state.detail).toContain('https://old.example.com');
    expect(state.detail).toContain(ENDPOINT);
  });

  // THE BRANCH THAT MATTERS MOST, and the one bars would lie about. The ledger
  // counts a backlog on every attached machine; without a grant, nothing has
  // been told it may send that backlog, so a progress bar would promise
  // delivery of rows that will sit for ever.
  it('shows no bars, and no backlog, on a machine that has not shared its history', () => {
    attach();
    seedSession('s-1');

    expect(panel().state).toEqual({ status: 'not-shared' });
  });

  // Stale and absent both fail the validity check and only one of them can be
  // resumed in place, so they must not collapse into one sentence.
  it('separates a grant that predates the payload from no grant at all', () => {
    attach();
    grant({ payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1 });

    expect(panel().state).toEqual({ status: 'consent-stale' });
  });

  // A grant naming another deployment must read as NO grant — never as a stale
  // one offering to resume, which would send this machine's activity somewhere
  // the user never agreed to.
  it('reads a grant for another deployment as no grant, not a stale one', () => {
    attach();
    grant({ endpoint: 'https://elsewhere.example.com' });

    expect(panel().state).toEqual({ status: 'not-shared' });
  });

  it('says nothing is recorded rather than showing empty bars', () => {
    attach();
    grant();

    expect(panel().state).toEqual({ status: 'nothing-recorded' });
  });

  // ─── The bars ──────────────────────────────────────────────────────────────

  it('gives every recorded kind a row, under a name a reader would use', () => {
    attach();
    grant();
    seedSession('s-1');

    const state = panel().state;
    if (state.status !== 'ready') throw new Error('expected ready');
    expect(state.kinds.map((k) => k.kind).sort()).toEqual(['llm_call', 'session', 'tool_call']);
    expect(state.kinds.map((k) => k.label)).not.toContain('llm_call');
    expect(state.kinds.find((k) => k.kind === 'llm_call')?.label).toBe('Model calls');
  });

  // The capture lane is entered by being OWED, not by existing: a prompt
  // recorded while nobody was forwarding was offered to nobody and is owed to
  // nobody. Counting it as queued would put most of a working machine's store
  // into a backlog nothing will ever send.
  it('leaves an unowed capture out entirely, and counts one that is owed', () => {
    attach();
    grant();
    seedSession('s-1');

    const before = panel().state;
    if (before.status !== 'ready') throw new Error('expected ready');
    expect(before.kinds.map((k) => k.kind)).not.toContain('prompt');

    withStore((db) => {
      db.historySync.markCaptureOwed('s-1-prompt');
    });
    dropMemoisedDb();

    const after = panel().state;
    if (after.status !== 'ready') throw new Error('expected ready');
    expect(after.kinds.find((k) => k.kind === 'prompt')).toMatchObject({
      label: 'Prompts',
      queued: 1,
      synced: 0,
      total: 1,
    });
  });

  it('counts a delivered row as sent and takes it out of the queue', () => {
    attach();
    grant();
    seedSession('s-1');
    withStore((db) => {
      db.historySync.markSynced(['s-1-llm'], T0);
    });
    dropMemoisedDb();

    const state = panel().state;
    if (state.status !== 'ready') throw new Error('expected ready');
    expect(state.kinds.find((k) => k.kind === 'llm_call')).toMatchObject({
      synced: 1,
      queued: 0,
      notSent: 0,
      total: 1,
    });
  });

  // A CLAIMED row is not a delivered one — something is working on it right
  // now. Counting it as sent would show a bar completing while the pass that
  // would complete it was still running, and then run backwards if it failed.
  it('counts a claimed row as still queued, never as sent', () => {
    attach();
    grant();
    seedSession('s-1');
    withStore((db) => {
      db.historySync.claimRows(['s-1-llm'], T0);
    });
    dropMemoisedDb();

    const state = panel().state;
    if (state.status !== 'ready') throw new Error('expected ready');
    expect(state.kinds.find((k) => k.kind === 'llm_call')).toMatchObject({
      synced: 0,
      queued: 1,
      total: 1,
    });
  });

  // One number, because a reader deciding what to do next is served by "these
  // will not go" — the store's own surfaces carry the breakdown.
  it('puts every terminal row in one not-sent figure', () => {
    attach();
    grant();
    seedSession('s-1');
    seedSession('s-2');
    withStore((db) => {
      db.historySync.markSkipped(['s-1-llm'], T0);
      db.historySync.markRefused(['s-2-llm'], T0);
    });
    dropMemoisedDb();

    const state = panel().state;
    if (state.status !== 'ready') throw new Error('expected ready');
    expect(state.kinds.find((k) => k.kind === 'llm_call')).toMatchObject({
      notSent: 2,
      queued: 0,
      synced: 0,
      total: 2,
    });
  });

  // ─── Whether a pass is running ─────────────────────────────────────────────

  it('reports no pass running on a store nothing has claimed', () => {
    attach();
    grant();
    expect(panel().running).toBe(false);
  });

  it('reports a pass running while a live claim is held', () => {
    attach();
    grant();
    withStore((db) => {
      db.historySync.claim(4321, 'host-a', Date.now(), 60_000);
    });
    dropMemoisedDb();

    expect(panel().running).toBe(true);
  });

  // The claim of a process that died without releasing it. Anyone may take it,
  // so calling it running would show "Sending…" for ever on a machine where
  // nothing is.
  it('reports no pass running for an abandoned claim', () => {
    attach();
    grant();
    withStore((db) => {
      db.historySync.claim(4321, 'host-a', Date.now() - 10 * 60_000, 60_000);
    });
    dropMemoisedDb();

    expect(panel().running).toBe(false);
  });

  // ─── The last pass, and what is not sent as rows at all ────────────────────

  it('carries the last pass’s outcome and instant through from the progress file', () => {
    attach();
    grant();
    writeHistorySyncState(dir, {
      phase: 'filling',
      lastOutcome: 'unreachable',
      lastPassAtMs: T0,
      sentTotal: 3,
      pendingTotal: 4,
      skippedTotal: 0,
      startedAtMs: T0,
      completedAtMs: null,
    });

    const props = panel();
    expect(props.lastOutcome).toBe('unreachable');
    expect(props.lastPassAt).toBe(AT);
  });

  it('says nothing about a last pass when none has been recorded', () => {
    attach();
    grant();

    const props = panel();
    expect(props.lastOutcome).toBeUndefined();
    expect(props.lastPassAt).toBeUndefined();
  });

  // These are the entities a reader asks about in the same breath as activity,
  // and none of them is a row this drain sends. Saying so beside the button is
  // what stops the button implying otherwise.
  it('names what the deployment does not receive as rows, with no count to imply a backlog', () => {
    attach();
    grant();

    const lines = panel().localOnly ?? [];
    expect(lines.map((line) => line.id)).toEqual(['findings', 'shares', 'inventory']);
    for (const line of lines) {
      expect(line.count).toBeUndefined();
      expect(line.detail.length).toBeGreaterThan(0);
    }
  });

  // Every relative label on the page has to be computed against ONE instant, or
  // the server render and the hydration disagree whenever a rounding boundary
  // falls between them and React discards the markup.
  it('hands the panel the instant this render is measured against', () => {
    attach();
    grant();

    const before = Date.now();
    const renderedAt = panel().renderedAt;
    expect(renderedAt).toBeGreaterThanOrEqual(before);
    expect(renderedAt).toBeLessThanOrEqual(Date.now());
  });
});
