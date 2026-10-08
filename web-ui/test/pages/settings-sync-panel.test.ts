import { writeFileSync } from 'node:fs';
import type * as NodeOs from 'node:os';
import { join } from 'node:path';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  ATTACHED_FORWARD_STATE_FILENAME,
  BREAKER_COOLDOWN_MS,
  dataDir,
  type LocalDatabase,
  openLocalDatabase,
  readEffectiveSettings,
  settingsDir,
  writeControlPlaneCredential,
  writeHistorySyncState,
} from '@akasecurity/persistence';
import { type AttachmentScope, HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import type { ComponentProps, ReactElement } from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import SettingsPage from '../../app/(app)/settings/page.tsx';
import { readSyncPanel } from '../../app/(app)/settings/sync-panel-data.ts';
import { SyncPanel } from '../../app/(app)/settings/SyncPanel.tsx';
import { emptyStore } from '../helpers/store-templates.ts';
import { tempHomes } from '../helpers/temp-home.ts';

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

// The page reads the credential's mode on its own, apart from the credential's
// state, and hands the panel whatever that read answers. One file cannot make
// the two reads disagree, and the disagreement is the case the page must not
// paper over, so this seam lets a case make ONLY the mode read answer
// `undefined`. Everything else, the state read included, stays the real one.
const modeRead = vi.hoisted(() => ({ unread: false }));
vi.mock('@akasecurity/persistence', async (importActual) => {
  const actual = await importActual<typeof Persistence>();
  return {
    ...actual,
    readControlPlaneAttachmentMode: (
      ...args: Parameters<typeof actual.readControlPlaneAttachmentMode>
    ): ReturnType<typeof actual.readControlPlaneAttachmentMode> =>
      modeRead.unread ? undefined : actual.readControlPlaneAttachmentMode(...args),
  };
});

const newHome = tempHomes('aka-sync-panel-');

let home: string;
let dir: string;

const ENDPOINT = 'https://plane.example.com';
const AT = '2026-09-12T00:00:00.000Z';
const T0 = Date.parse(AT);
// One character: the shape asks only for a non-empty string, and nothing here
// authenticates against anything.
const KEY = 'k';

// Two repositories' keys, in the canonical form a producer stamps: one a scoped
// attachment enrolls, one it does not.
const WORK = 'github.com/acme/payments-api';
const PERSONAL = 'github.com/someone/dotfiles';

const akaHome = (): string => join(home, '.aka');

// app/lib/db memoises its handle on globalThis across requests and HMR reloads,
// so a suite that does not drop it reads the PREVIOUS test's temp store.
function dropMemoisedDb(): void {
  const store = globalThis as unknown as { __akaDb?: LocalDatabase };
  store.__akaDb?.close();
  delete store.__akaDb;
}

beforeEach(() => {
  home = newHome();
  osHome.dir = home;
  dir = dataDir();
  emptyStore.seed(dir);
  dropMemoisedDb();
});

afterEach(() => {
  modeRead.unread = false;
  dropMemoisedDb();
});

type PanelProps = ComponentProps<typeof SyncPanel>;

/** The panel's props, or null when the page rendered no panel at all. */
async function renderPanel(): Promise<PanelProps | null> {
  const element = (await SettingsPage()) as ReactElement;
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
async function panel(): Promise<PanelProps['sync']> {
  const props = await renderPanel();
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

/** A scope record for `endpoint` that enrolls `identities` as repositories. */
function scopeRecord(identities: readonly string[], endpoint = ENDPOINT): AttachmentScope {
  return {
    endpoint,
    entries: identities.map((identity) => ({ kind: 'repo', identity, enrolledAt: AT })),
  };
}

/**
 * Attach as a personal device: a version-2 credential, which names the scoped
 * mode, with `scope` stored as the settings' scope record (none when undefined).
 */
function attachScoped(scope?: unknown): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
      ...(scope === undefined ? {} : { attachmentScope: scope }),
    },
    akaHome(),
  );
  writeControlPlaneCredential(settingsDir(akaHome()), {
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
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

/**
 * A session root with one structural leaf of each kind and one capture, every
 * row stamped with `scopeKey`: the key a producer derives from the repository
 * the activity was recorded in.
 */
function seedKeyedSession(sessionId: string, scopeKey: string): void {
  const attributes = { scope_key: scopeKey };
  const db = openLocalDatabase(dir);
  try {
    db.auditEvents.insertAuditEvent({
      id: sessionId,
      eventType: 'session',
      startedAt: AT,
      attributes,
    });
    for (const [suffix, eventType] of [
      ['llm', 'llm_call'],
      ['tool', 'tool_call'],
      ['prompt', 'prompt'],
    ] as const) {
      db.auditEvents.insertAuditEvent({
        id: `${sessionId}-${suffix}`,
        eventType,
        rootSessionId: sessionId,
        parentId: sessionId,
        startedAt: AT,
        attributes,
      });
    }
  } finally {
    db.close();
  }
}

/** Record a breaker that opened at `openedAtMs`, as the forward path would. */
function openBreaker(openedAtMs: number): void {
  writeFileSync(
    join(dir, ATTACHED_FORWARD_STATE_FILENAME),
    JSON.stringify({ consecutiveFailures: 3, openedAtMs, lastFailure: 'unreachable' }),
  );
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

type PanelState = PanelProps['sync']['state'];

/** The bars as [kind, synced, queued, notSent, total], failing unless the panel drew bars. */
async function bars(): Promise<[string, number, number, number, number][]> {
  const state = (await panel()).state;
  if (state.status !== 'ready') throw new Error(`expected bars, got ${state.status}`);
  return state.kinds.map((k): [string, number, number, number, number] => [
    k.kind,
    k.synced,
    k.queued,
    k.notSent,
    k.total,
  ]);
}

/** The state a usable key whose mode could not be read renders. */
function expectModeUnread(state: PanelState | undefined): void {
  if (state?.status !== 'credential-unusable') {
    throw new Error(`expected credential-unusable, got ${String(state?.status)}`);
  }
  expect(state.detail).toContain(
    'could not tell whether this machine is attached as a personal or an organization device',
  );
  expect(state.detail).toContain('Reload the page');
}

describe('the settings route — the sync panel', () => {
  // ─── Whether it appears at all ─────────────────────────────────────────────

  // A machine that has never attached is not a machine with nothing to sync —
  // it is one this panel has no business describing. Zeros in a bar and absence
  // look identical and mean different things, so the page renders neither.
  it('renders no panel at all on a standalone machine', async () => {
    expect(await renderPanel()).toBeNull();
  });

  // `runMode: 'attached'` alone is a stored answer, not an attachment: the
  // descriptor is what names a deployment, and without one there is nothing to
  // put in the panel's own header line.
  it('renders no panel for an attached run mode with no deployment named', async () => {
    applyOnboarding({ runMode: 'attached' }, akaHome());
    expect(await renderPanel()).toBeNull();
  });

  // The mirror, and the half a descriptor check alone would miss: a settings
  // file can carry a deployment descriptor while the run mode says standalone —
  // a hand-edit, or an administrator's overlay pinning the mode under a user
  // file that still names one. The machine sends nothing in that state, and a
  // panel describing a backlog to a deployment it does not talk to is the same
  // false claim as a panel of zeros.
  it('renders no panel when the run mode says standalone, whatever the file names', async () => {
    applyOnboarding(
      { runMode: 'standalone', controlPlane: { endpoint: ENDPOINT, attachedAt: AT } },
      akaHome(),
    );
    expect(await renderPanel()).toBeNull();
  });

  it('renders a panel once the machine is attached', async () => {
    attach();
    expect(await renderPanel()).not.toBeNull();
  });

  // ─── Which state it is in, and the order those questions are asked ──────────

  it('names the deployment’s label when it has one, and the endpoint otherwise', async () => {
    attach({ label: 'Acme Prod' });
    expect((await panel()).deployment).toBe('Acme Prod');

    applyOnboarding({ controlPlane: { endpoint: ENDPOINT, attachedAt: AT } }, akaHome());
    dropMemoisedDb();
    expect((await panel()).deployment).toBe(ENDPOINT);
  });

  it('reports a machine holding no key as unable to use it, not as unshared', async () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: AT } },
      akaHome(),
    );
    grant();

    const state = (await panel()).state;
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
  it('blames the key, not the sharing setting, when both are wrong', async () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: AT } },
      akaHome(),
    );

    expect((await panel()).state.status).toBe('credential-unusable');
  });

  it('blames the key ahead of a grant that has merely gone stale', async () => {
    applyOnboarding(
      { runMode: 'attached', controlPlane: { endpoint: ENDPOINT, attachedAt: AT } },
      akaHome(),
    );
    grant({ payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1 });

    expect((await panel()).state.status).toBe('credential-unusable');
  });

  // The one unusable reason a user can act on, and the only one whose fix
  // depends on which endpoint is which. Naming just one of them would send the
  // reader to undo the wrong half.
  it('names both endpoints when the key belongs to another deployment', async () => {
    attach();
    grant();
    writeControlPlaneCredential(settingsDir(akaHome()), {
      specVersion: 1,
      endpoint: 'https://old.example.com',
      apiKey: KEY,
    });

    const state = (await panel()).state;
    if (state.status !== 'credential-unusable') throw new Error('expected an unusable key');
    expect(state.detail).toContain('https://old.example.com');
    expect(state.detail).toContain(ENDPOINT);
  });

  // THE BRANCH THAT MATTERS MOST, and the one bars would lie about. The ledger
  // counts a backlog on every attached machine; without a grant, nothing has
  // been told it may send that backlog, so a progress bar would promise
  // delivery of rows that will sit for ever.
  it('shows no bars, and no backlog, on a machine that has not shared its history', async () => {
    attach();
    seedSession('s-1');

    expect((await panel()).state).toEqual({ status: 'not-shared' });
  });

  // Stale and absent both fail the validity check and only one of them can be
  // resumed in place, so they must not collapse into one sentence.
  it('separates a grant that predates the payload from no grant at all', async () => {
    attach();
    grant({ payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION - 1 });

    expect((await panel()).state).toEqual({ status: 'consent-stale' });
  });

  // A grant naming another deployment must read as NO grant — never as a stale
  // one offering to resume, which would send this machine's activity somewhere
  // the user never agreed to.
  it('reads a grant for another deployment as no grant, not a stale one', async () => {
    attach();
    grant({ endpoint: 'https://elsewhere.example.com' });

    expect((await panel()).state).toEqual({ status: 'not-shared' });
  });

  it('says nothing is recorded rather than showing empty bars', async () => {
    attach();
    grant();

    expect((await panel()).state).toEqual({ status: 'nothing-recorded' });
  });

  // ─── The bars ──────────────────────────────────────────────────────────────

  // Lane order, not the store's. `partitionByKind` returns whatever its index
  // walk produces — alphabetical by accident — which interleaves the structural
  // kinds with the three that carry text. Those two lanes behave differently
  // and are gated differently, and a reader comparing across them is comparing
  // unlike things.
  it('shows the structural kinds first, then the ones that carry text', async () => {
    attach();
    grant();
    seedSession('s-1');
    withStore((db) => {
      db.historySync.markCaptureOwed('s-1-prompt');
    });
    dropMemoisedDb();

    const state = (await panel()).state;
    if (state.status !== 'ready') throw new Error('expected ready');
    expect(state.kinds.map((k) => k.kind)).toEqual(['session', 'llm_call', 'tool_call', 'prompt']);
  });

  it('gives every recorded kind a row, under a name a reader would use', async () => {
    attach();
    grant();
    seedSession('s-1');

    const state = (await panel()).state;
    if (state.status !== 'ready') throw new Error('expected ready');
    expect(state.kinds.map((k) => k.kind).sort()).toEqual(['llm_call', 'session', 'tool_call']);
    expect(state.kinds.map((k) => k.label)).not.toContain('llm_call');
    expect(state.kinds.find((k) => k.kind === 'llm_call')?.label).toBe('Model calls');
  });

  // The capture lane is entered by being OWED, not by existing: a prompt
  // recorded while nobody was forwarding was offered to nobody and is owed to
  // nobody. Counting it as queued would put most of a working machine's store
  // into a backlog nothing will ever send.
  it('leaves an unowed capture out entirely, and counts one that is owed', async () => {
    attach();
    grant();
    seedSession('s-1');

    const before = (await panel()).state;
    if (before.status !== 'ready') throw new Error('expected ready');
    expect(before.kinds.map((k) => k.kind)).not.toContain('prompt');

    withStore((db) => {
      db.historySync.markCaptureOwed('s-1-prompt');
    });
    dropMemoisedDb();

    const after = (await panel()).state;
    if (after.status !== 'ready') throw new Error('expected ready');
    expect(after.kinds.find((k) => k.kind === 'prompt')).toMatchObject({
      label: 'Prompts',
      queued: 1,
      synced: 0,
      total: 1,
    });
  });

  it('counts a delivered row as sent and takes it out of the queue', async () => {
    attach();
    grant();
    seedSession('s-1');
    withStore((db) => {
      db.historySync.markSynced(['s-1-llm'], T0);
    });
    dropMemoisedDb();

    const state = (await panel()).state;
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
  it('counts a claimed row as still queued, never as sent', async () => {
    attach();
    grant();
    seedSession('s-1');
    withStore((db) => {
      db.historySync.claimRows(['s-1-llm'], T0);
    });
    dropMemoisedDb();

    const state = (await panel()).state;
    if (state.status !== 'ready') throw new Error('expected ready');
    expect(state.kinds.find((k) => k.kind === 'llm_call')).toMatchObject({
      synced: 0,
      queued: 1,
      total: 1,
    });
  });

  // One number, because a reader deciding what to do next is served by "these
  // will not go" — the store's own surfaces carry the breakdown.
  it('puts every terminal row in one not-sent figure', async () => {
    attach();
    grant();
    seedSession('s-1');
    seedSession('s-2');
    withStore((db) => {
      db.historySync.markSkipped(['s-1-llm'], T0);
      db.historySync.markRefused(['s-2-llm'], T0);
    });
    dropMemoisedDb();

    const state = (await panel()).state;
    if (state.status !== 'ready') throw new Error('expected ready');
    expect(state.kinds.find((k) => k.kind === 'llm_call')).toMatchObject({
      notSent: 2,
      queued: 0,
      synced: 0,
      total: 2,
    });
  });

  // ─── Whether a pass is running ─────────────────────────────────────────────

  it('reports no pass running on a store nothing has claimed', async () => {
    attach();
    grant();
    expect((await panel()).running).toBe(false);
  });

  it('reports a pass running while a live claim is held', async () => {
    attach();
    grant();
    withStore((db) => {
      db.historySync.claim(4321, 'host-a', Date.now(), 60_000);
    });
    dropMemoisedDb();

    expect((await panel()).running).toBe(true);
  });

  // The claim of a process that died without releasing it. Anyone may take it,
  // so calling it running would show "Sending…" for ever on a machine where
  // nothing is.
  it('reports no pass running for an abandoned claim', async () => {
    attach();
    grant();
    withStore((db) => {
      db.historySync.claim(4321, 'host-a', Date.now() - 10 * 60_000, 60_000);
    });
    dropMemoisedDb();

    expect((await panel()).running).toBe(false);
  });

  // ─── Held off after repeated failures ──────────────────────────────────────
  //
  // THE ORIGINAL SYMPTOM. A pass started while the breaker is open declines
  // before it opens the store, and the child is detached, so that decision
  // reaches nothing — the button appears to do nothing at all. The page can
  // only say so by reading the same file the pass would.

  it('reports nothing paused on a machine that has not been failing', async () => {
    attach();
    grant();
    expect((await panel()).paused).toBe(false);
  });

  it('reports a machine held off while the breaker is still cooling', async () => {
    attach();
    grant();
    openBreaker(Date.now());

    expect((await panel()).paused).toBe(true);
  });

  // The expensive direction. The stamp is never cleared by elapsing and the
  // half-open probe re-stamps it before every attempt, so reading any stamp as
  // open would show a machine as paused through the whole window in which the
  // live path has resumed probing.
  it('reports nothing paused once the cooldown has elapsed, stamp and all', async () => {
    attach();
    grant();
    openBreaker(Date.now() - BREAKER_COOLDOWN_MS - 1);

    expect((await panel()).paused).toBe(false);
  });

  // The backlog is still accurate and still owed while a machine is held off,
  // and that is the moment a reader most wants to see what it is holding.
  it('still reports the backlog while it is paused', async () => {
    attach();
    grant();
    seedSession('s-1');
    openBreaker(Date.now());
    dropMemoisedDb();

    const props = await panel();
    expect(props.paused).toBe(true);
    expect(props.state.status).toBe('ready');
  });

  // ─── The last pass, and what is not sent as rows at all ────────────────────

  it('carries the last pass’s outcome and instant through from the progress file', async () => {
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

    const props = await panel();
    expect(props.lastOutcome).toBe('unreachable');
    expect(props.lastPassAt).toBe(AT);
  });

  it('says nothing about a last pass when none has been recorded', async () => {
    attach();
    grant();

    const props = await panel();
    expect(props.lastOutcome).toBeUndefined();
    expect(props.lastPassAt).toBeUndefined();
  });

  // These are the entities a reader asks about in the same breath as activity,
  // and none of them is a row this drain sends. Saying so beside the button is
  // what stops the button implying otherwise.
  it('names what the deployment does not receive as rows, with no count to imply a backlog', async () => {
    attach();
    grant();

    const lines = (await panel()).localOnly ?? [];
    expect(lines.map((line) => line.id)).toEqual(['findings', 'shares', 'inventory']);
    for (const line of lines) {
      expect(line.count).toBeUndefined();
      expect(line.detail.length).toBeGreaterThan(0);
    }
  });

  // Every relative label on the page has to be computed against ONE instant, or
  // the server render and the hydration disagree whenever a rounding boundary
  // falls between them and React discards the markup. That the instant is
  // captured per REQUEST rather than once per process is pinned separately, in
  // render-instant-wiring.
  it('hands the panel the instant this render is measured against', async () => {
    attach();
    grant();

    const before = Date.now();
    const props = await renderPanel();
    if (props === null) throw new Error('the page rendered no sync panel');
    expect(props.renderedAt).toBeGreaterThanOrEqual(before);
    expect(props.renderedAt).toBeLessThanOrEqual(Date.now());
  });
});

describe('the settings route — the sync panel on a scoped attachment', () => {
  // A scoped attachment sends activity only from what its enrolled repositories
  // recorded, and its history drain filters every pass by that scope. The bars
  // are counted by the same scope, resolved from the same inputs, so they
  // describe what this machine sends rather than everything its store holds.
  // Each case writes a real credential file and a real settings record; only the
  // store's rows are seeded by hand, and one case calls the reader directly to
  // give it a mode the page could not read.

  it('counts the enrolled repository and leaves a personal one out of every bar', async () => {
    attachScoped(scopeRecord([WORK]));
    grant();
    seedKeyedSession('work-1', WORK);
    seedKeyedSession('home-1', PERSONAL);
    withStore((db) => {
      db.historySync.markCaptureOwed('work-1-prompt');
      db.historySync.markCaptureOwed('home-1-prompt');
    });

    // [kind, synced, queued, notSent, total]
    expect(await bars()).toEqual([
      ['session', 0, 1, 0, 1],
      ['llm_call', 0, 1, 0, 1],
      ['tool_call', 0, 1, 0, 1],
      ['prompt', 0, 1, 0, 1],
    ]);
  });

  // One population in every bucket, sent rows included: a repository that is
  // unenrolled leaves the bars, and what it already sent leaves with it. The
  // scope is read on every render, so the next one shows the change.
  it('takes an unenrolled repository out of the bars at the next render, sent rows and all', async () => {
    attachScoped(scopeRecord([WORK, PERSONAL]));
    grant();
    seedKeyedSession('work-1', WORK);
    seedKeyedSession('home-1', PERSONAL);
    withStore((db) => {
      db.historySync.markSynced(['work-1-llm', 'home-1-llm'], T0);
      db.historySync.markRefused(['home-1-tool'], T0);
    });

    expect(await bars()).toEqual([
      ['session', 0, 2, 0, 2],
      ['llm_call', 2, 0, 0, 2],
      ['tool_call', 0, 1, 1, 2],
    ]);

    applyOnboarding({ attachmentScope: scopeRecord([WORK]) }, akaHome());

    expect(await bars()).toEqual([
      ['session', 0, 1, 0, 1],
      ['llm_call', 1, 0, 0, 1],
      ['tool_call', 0, 1, 0, 1],
    ]);
  });

  // "Nothing recorded yet" over a full store would be false: the rows are there,
  // and this scope sends none of them. Every way of enrolling nothing for this
  // deployment reads the same, and the WORK session below is what a record bound
  // to another deployment would count if its binding were skipped.
  it.each<[string, unknown]>([
    ['no scope is recorded', undefined],
    ['the stored scope is not a record at all', 'not-a-scope-record'],
    [
      'the scope was recorded for another deployment',
      scopeRecord([WORK], 'https://old.example.com'),
    ],
    ['the scope lists no repository yet', scopeRecord([])],
  ])('says no repository is enrolled when %s, over a full store', async (_name, scope) => {
    attachScoped(scope);
    grant();
    seedKeyedSession('work-1', WORK);
    seedKeyedSession('home-1', PERSONAL);
    seedSession('s-1');

    expect((await panel()).state).toEqual({ status: 'nothing-in-scope', enrolled: 0 });
  });

  it('says nothing from an enrolled repository is counted yet, over a store full of other activity', async () => {
    // Listed twice: the count is of the distinct identities the scope enrolls,
    // not of entries in the file.
    attachScoped(scopeRecord([WORK, WORK]));
    grant();
    seedKeyedSession('home-1', PERSONAL);
    seedSession('s-1');

    expect((await panel()).state).toEqual({ status: 'nothing-in-scope', enrolled: 1 });
  });

  // The page reads the credential twice, once for its state and once for its
  // mode, and the two can disagree for a moment. Counted machine-wide, the bars
  // would say a personal device owes its whole store; counted under an empty
  // scope, that it owes nothing. Neither is known, so neither is drawn, and the
  // question comes before the grant's so no other state hides it. Called
  // directly, because one render of the page reads both halves from one file.
  it('reads a usable key whose mode it could not read as unusable, granted or not', () => {
    attach();
    seedSession('s-1');
    const stateNow = (): PanelState | undefined =>
      readSyncPanel(readEffectiveSettings().settings, { usable: true }, T0, undefined)?.state;

    expectModeUnread(stateNow());
    grant();
    expectModeUnread(stateNow());
  });

  // The same disagreement through the PAGE, which is where a fallback would hide:
  // a `?? 'machine'` on the mode the page passes down would hand the reader a
  // mode it never read, and every case that calls the reader directly would stay
  // green while the panel drew a personal device's whole store as its queue. The
  // first render has the mode readable (the control: bars), the second has only
  // that read answer `undefined` over the same usable key.
  it('renders a usable key whose mode the page could not read as unusable, not as machine-wide', async () => {
    attach();
    grant();
    seedSession('s-1');
    expect((await panel()).state.status).toBe('ready');

    modeRead.unread = true;

    expectModeUnread((await panel()).state);
  });

  // A machine-wide attachment never reads the scope record, so one left in the
  // settings changes nothing: everything recorded is counted, as before.
  it('counts everything recorded on a machine-wide attachment, whatever scope is recorded', async () => {
    attach();
    applyOnboarding({ attachmentScope: scopeRecord([WORK]) }, akaHome());
    grant();
    seedKeyedSession('work-1', WORK);
    seedKeyedSession('home-1', PERSONAL);
    seedSession('s-1');

    expect(await bars()).toEqual([
      ['session', 0, 3, 0, 3],
      ['llm_call', 0, 3, 0, 3],
      ['tool_call', 0, 3, 0, 3],
    ]);
  });
});
