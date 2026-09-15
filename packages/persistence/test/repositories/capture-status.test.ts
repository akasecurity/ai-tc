import { randomUUID } from 'node:crypto';

import type { WebCaptureStatus, WebSourceTool } from '@akasecurity/schema';
import { CAPTURE_STATUS_RECENCY_MS, toCaptureStatusAttributes } from '@akasecurity/schema';
import { beforeEach, describe, expect, it } from 'vitest';

import { SqliteAuditEventsRepository } from '../../src/repositories/audit-events.ts';
import { SqliteCaptureStatusRepository } from '../../src/repositories/capture-status.ts';
import { useTempStore } from '../helpers/temp-store.ts';

const store = useTempStore('aka-capture-status-', { migrated: true });

// The instant every read below is taken at. Fixed rather than `Date.now()`,
// because `latest` bounds its scan to the last CAPTURE_STATUS_RECENCY_MS and a
// wall-clock read would put the 2026-01-01 fixtures outside that window the
// moment the calendar moved past them. Two hours after the newest fixture, so
// every case here is comfortably inside it and the window is exercised only by
// the cases below that mean to.
const NOW = Date.parse('2026-01-01T02:00:00.000Z');

const STATUS: WebCaptureStatus = {
  patched: true,
  live: true,
  blind: false,
  sendsSeenDom: 2,
  exchangesSeenNet: 2,
  parseFailures: 0,
  unparsedBodies: 0,
  shapeMisses: [],
  conversationEndpoints: 1,
  closed: false,
  enforcement: 'watching',
};

// `rootSessionId` is what groups a site's rows into DOCUMENTS, so a case about
// grouping has to set it. It is left unset by default, which is both what the
// host wrote before it stamped one and — deliberately — what makes every case
// that does not name it read as ONE document: two unstamped rows cannot be told
// apart, so the read may not guess they are different pages. `parentId` stays
// unset throughout; nothing here tests the gateway layer's FK planting.
function writeStatus(opts: {
  id?: string;
  startedAt: string;
  tool: string;
  status?: WebCaptureStatus;
  rootSessionId?: string;
}): void {
  const audit = new SqliteAuditEventsRepository(store.openRaw());
  audit.insertAuditEvent({
    id: opts.id ?? randomUUID(),
    eventType: 'capture_status',
    startedAt: opts.startedAt,
    ...(opts.rootSessionId === undefined ? {} : { rootSessionId: opts.rootSessionId }),
    attributes:
      opts.status === undefined
        ? { source_tool: opts.tool }
        : toCaptureStatusAttributes(opts.status, opts.tool as WebSourceTool),
  });
}

// `audit_events.root_session_id` is a self-FK and these suites run against a
// raw handle, where DatabaseSync enforces FKs — so the root row has to exist
// before anything can name it. A `session` row carries NULL attributes and so
// NULL `source_tool`, which is why planting one is invisible to this read.
function plantRoot(sessionId: string): void {
  new SqliteAuditEventsRepository(store.openRaw()).ensureSessionRoot(
    sessionId,
    '2026-01-01T00:00:00.000Z',
  );
}

let repo: SqliteCaptureStatusRepository;

beforeEach(() => {
  repo = new SqliteCaptureStatusRepository(store.openRaw());
});

describe('SqliteCaptureStatusRepository.latest', () => {
  it('returns the newest row per site', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'claude-ai', status: STATUS });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'claude-ai',
      status: { ...STATUS, exchangesSeenNet: 5 },
    });
    writeStatus({
      startedAt: '2026-01-01T00:10:00.000Z',
      tool: 'claude-ai',
      status: { ...STATUS, exchangesSeenNet: 9 },
    });
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: STATUS });

    const records = repo.latest(NOW);
    expect(records).toHaveLength(2);
    const claudeAi = records.find((r) => r.tool === 'claude-ai');
    expect(claudeAi?.status.exchangesSeenNet).toBe(9);
  });

  it('breaks a tie on started_at by the higher id, whichever landed first', () => {
    // Seeded in DESCENDING id order, so insertion order and id order disagree:
    // asserting the winner against rows written in ascending order passes
    // whether the tiebreaker is `a.id DESC` or nothing at all.
    writeStatus({
      id: 'b-row',
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: { ...STATUS, exchangesSeenNet: 42 },
    });
    writeStatus({
      id: 'a-row',
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: { ...STATUS, exchangesSeenNet: 7 },
    });

    const chatgpt = repo.latest(NOW).find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.status.exchangesSeenNet).toBe(42);
  });

  it('skips a row whose bag is not a status, keeping the other site', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt' }); // no status fields at all
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'claude-ai', status: STATUS });

    const records = repo.latest(NOW);
    expect(records.map((r) => r.tool)).toEqual(['claude-ai']);
  });

  it('skips a row whose source_tool is not a web chat id', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'claude-code', status: STATUS });

    expect(repo.latest(NOW)).toEqual([]);
  });

  it('answers an empty store with no records', () => {
    expect(repo.latest(NOW)).toEqual([]);
  });
});

// A page relays a fresh nothing-seen-yet report the moment its tap patches, so
// the newest row for a site is very often a report that observed nothing. The
// read has to see past those, or reloading the tab — which is what the `blind`
// remediation tells the user to do — replaces the report that told them to.
describe('SqliteCaptureStatusRepository.latest — a watching-only report', () => {
  // Patched, endpoints to watch, nothing observed: what a page reports on load.
  const WATCHING: WebCaptureStatus = {
    patched: true,
    live: false,
    blind: false,
    sendsSeenDom: 0,
    exchangesSeenNet: 0,
    parseFailures: 0,
    unparsedBodies: 0,
    shapeMisses: [],
    conversationEndpoints: 1,
    closed: false,
    enforcement: 'watching',
  };
  const BLIND: WebCaptureStatus = { ...WATCHING, blind: true, sendsSeenDom: 3 };

  it('does not replace a report that observed the turn path', () => {
    // One document, named explicitly: this is a within-document property (a
    // page that reloaded and has re-tested nothing), and sharing a root is
    // what keeps it separable from the cross-document fold.
    plantRoot('doc-a');
    writeStatus({
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: BLIND,
      rootSessionId: 'doc-a',
    });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'chatgpt',
      status: WATCHING,
      rootSessionId: 'doc-a',
    });

    const chatgpt = repo.latest(NOW).find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.status.blind).toBe(true);
    expect(chatgpt?.observedAt).toBe('2026-01-01T00:00:00.000Z');
  });

  it('is replaced by a later report that did observe the turn path', () => {
    plantRoot('doc-a');
    writeStatus({
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: BLIND,
      rootSessionId: 'doc-a',
    });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'chatgpt',
      status: WATCHING,
      rootSessionId: 'doc-a',
    });
    writeStatus({
      startedAt: '2026-01-01T00:10:00.000Z',
      tool: 'chatgpt',
      status: STATUS,
      rootSessionId: 'doc-a',
    });

    const chatgpt = repo.latest(NOW).find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.status.blind).toBe(false);
    expect(chatgpt?.observedAt).toBe('2026-01-01T00:10:00.000Z');
  });

  it('is what a site with nothing else to report shows', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: WATCHING });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'chatgpt',
      status: { ...WATCHING, sendsSeenDom: 1 },
    });

    const chatgpt = repo.latest(NOW).find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.observedAt).toBe('2026-01-01T00:05:00.000Z');
    expect(chatgpt?.status.sendsSeenDom).toBe(1);
  });

  it('buries an older verdict once enough of them have piled up on top', () => {
    // The lookback is bounded because this read walks the capture_status
    // range; past it the older verdict is stale and the newest row is shown.
    // The count has to exceed STATUS_LOOKBACK_ROWS, which is module-private —
    // so raising that constant reds this case rather than quietly changing
    // what it measures.
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: BLIND });
    const base = Date.parse('2026-01-01T01:00:00.000Z');
    for (let i = 1; i <= 140; i += 1) {
      writeStatus({
        startedAt: new Date(base + i * 20_000).toISOString(),
        tool: 'chatgpt',
        status: WATCHING,
      });
    }

    expect(repo.latest(NOW).find((r) => r.tool === 'chatgpt')?.status.blind).toBe(false);
  });

  it('does not hide a build that stopped declaring endpoints', () => {
    // conversationEndpoints === 0 is a statement about this build, not an
    // absence of evidence, so it supersedes like any observation would.
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: BLIND });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'chatgpt',
      status: { ...WATCHING, conversationEndpoints: 0 },
    });

    const chatgpt = repo.latest(NOW).find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.status.conversationEndpoints).toBe(0);
    expect(chatgpt?.status.blind).toBe(false);
  });
});

// One site, several documents: two tabs, or a tab and the page it replaced.
// The read returns each document's own report rather than one row per site,
// because choosing between them is a decision about capture STATE and this
// package cannot import the module that owns those semantics.
//
// Every case above seeds an unset root, so they are all one document — which
// is the point to carry into review: that suite structurally cannot tell
// pooling from grouping, so these cases plant explicit roots.
describe('SqliteCaptureStatusRepository.latest — two documents on one site', () => {
  const WATCHING: WebCaptureStatus = { ...STATUS, live: false, exchangesSeenNet: 0 };
  const BLIND: WebCaptureStatus = { ...WATCHING, blind: true, sendsSeenDom: 3 };

  it('returns one record per document, not one per site', () => {
    plantRoot('doc-a');
    plantRoot('doc-b');
    writeStatus({
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: BLIND,
      rootSessionId: 'doc-b',
    });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'chatgpt',
      status: STATUS,
      rootSessionId: 'doc-a',
    });

    const chatgpt = repo.latest(NOW).filter((r) => r.tool === 'chatgpt');
    // Length, not a `find`: a single-record assertion passes on a read that
    // pooled the two and returned the newer one, which is the defect.
    expect(chatgpt).toHaveLength(2);
    expect(chatgpt.map((r) => r.rootSessionId).sort()).toEqual(['doc-a', 'doc-b']);
    expect(chatgpt.find((r) => r.rootSessionId === 'doc-b')?.status.blind).toBe(true);
    expect(chatgpt.find((r) => r.rootSessionId === 'doc-a')?.status.blind).toBe(false);
  });

  it('applies the picker inside each document and not across them', () => {
    // doc-b's own newer watching report must not bury its verdict, and doc-a's
    // healthy report must not bury it either. One document's history is the
    // only thing that can supersede that document's verdict.
    plantRoot('doc-a');
    plantRoot('doc-b');
    writeStatus({
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: BLIND,
      rootSessionId: 'doc-b',
    });
    writeStatus({
      startedAt: '2026-01-01T00:01:00.000Z',
      tool: 'chatgpt',
      status: WATCHING,
      rootSessionId: 'doc-b',
    });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'chatgpt',
      status: STATUS,
      rootSessionId: 'doc-a',
    });

    const docB = repo.latest(NOW).find((r) => r.rootSessionId === 'doc-b');
    expect(docB?.status.blind).toBe(true);
    // The verdict's own row, which is older than that document's last word.
    expect(docB?.observedAt).toBe('2026-01-01T00:00:00.000Z');
    expect(docB?.lastReportAt).toBe('2026-01-01T00:01:00.000Z');
  });

  it('carries each document-s last word, closed flag and all', () => {
    plantRoot('doc-b');
    writeStatus({
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: BLIND,
      rootSessionId: 'doc-b',
    });
    writeStatus({
      startedAt: '2026-01-01T00:01:00.000Z',
      tool: 'chatgpt',
      status: { ...BLIND, closed: true },
      rootSessionId: 'doc-b',
    });

    const docB = repo.latest(NOW).find((r) => r.rootSessionId === 'doc-b');
    expect(docB?.closed).toBe(true);
    expect(docB?.lastReportAt).toBe('2026-01-01T00:01:00.000Z');
  });

  it('reads rows the host wrote before it stamped a root as one document', () => {
    // Two unstamped rows are indistinguishable, so they may not be read as two
    // pages — a fold over them would let the older one vote for ever.
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: BLIND });
    writeStatus({ startedAt: '2026-01-01T00:05:00.000Z', tool: 'chatgpt', status: STATUS });

    const chatgpt = repo.latest(NOW).filter((r) => r.tool === 'chatgpt');
    expect(chatgpt).toHaveLength(1);
    expect(chatgpt[0]?.rootSessionId).toBeUndefined();
    // And the picker still ran inside that one document: its newest report DID
    // observe the turn path, so it supersedes the verdict.
    expect(chatgpt[0]?.status.blind).toBe(false);
  });

  it('keeps an unstamped document separate from a stamped one', () => {
    plantRoot('doc-a');
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: BLIND });
    writeStatus({
      startedAt: '2026-01-01T00:05:00.000Z',
      tool: 'chatgpt',
      status: STATUS,
      rootSessionId: 'doc-a',
    });

    const chatgpt = repo.latest(NOW).filter((r) => r.tool === 'chatgpt');
    expect(chatgpt).toHaveLength(2);
    expect(chatgpt.find((r) => r.rootSessionId === undefined)?.status.blind).toBe(true);
  });

  it('does not let one site-s documents appear under another site', () => {
    plantRoot('doc-a');
    plantRoot('doc-x');
    writeStatus({
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: BLIND,
      rootSessionId: 'doc-a',
    });
    writeStatus({
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'claude-ai',
      status: STATUS,
      rootSessionId: 'doc-x',
    });

    const records = repo.latest(NOW);
    expect(records.filter((r) => r.tool === 'chatgpt').map((r) => r.rootSessionId)).toEqual([
      'doc-a',
    ]);
    expect(records.filter((r) => r.tool === 'claude-ai').map((r) => r.rootSessionId)).toEqual([
      'doc-x',
    ]);
  });
});

// A status is a report about one instant, and only the browser extension ever
// writes one — so nothing supersedes an old verdict once the extension stops
// reporting. The read is bounded so it decays instead of standing for ever.
describe('SqliteCaptureStatusRepository.latest — the recency bound', () => {
  it('omits a site whose newest report has aged out of the window', () => {
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'chatgpt', status: STATUS });

    // The positive control and the absence read the SAME row, at the two
    // instants either side of the boundary: the window is `started_at >= now -
    // CAPTURE_STATUS_RECENCY_MS`, so the last instant that reports it is
    // exactly `row + the window` and the next millisecond is the first that
    // does not. Without the control this passes on a read that returns nothing
    // for any reason at all.
    const row = Date.parse('2026-01-01T00:00:00.000Z');
    expect(repo.latest(row + CAPTURE_STATUS_RECENCY_MS).map((r) => r.tool)).toEqual(['chatgpt']);
    expect(repo.latest(row + CAPTURE_STATUS_RECENCY_MS + 1)).toEqual([]);
  });

  it('reports a site whose newest report is inside the window, however old the rest are', () => {
    // Two years of history under one recent report: the old rows are outside
    // the window and the recent one is not, so the site still reports — the
    // bound retires stale VERDICTS, it does not retire a live site because its
    // store is long.
    writeStatus({ startedAt: '2024-01-01T00:00:00.000Z', tool: 'chatgpt', status: STATUS });
    writeStatus({
      startedAt: '2026-01-01T00:00:00.000Z',
      tool: 'chatgpt',
      status: { ...STATUS, exchangesSeenNet: 9 },
    });

    const chatgpt = repo.latest(NOW).find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.status.exchangesSeenNet).toBe(9);
  });

  it('does not let an aged-out row of one site suppress another site', () => {
    writeStatus({ startedAt: '2020-01-01T00:00:00.000Z', tool: 'chatgpt', status: STATUS });
    writeStatus({ startedAt: '2026-01-01T00:00:00.000Z', tool: 'claude-ai', status: STATUS });

    expect(repo.latest(NOW).map((r) => r.tool)).toEqual(['claude-ai']);
  });
});
