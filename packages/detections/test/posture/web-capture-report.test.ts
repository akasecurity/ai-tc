import type { ReportedCaptureDocument, WebCaptureStatus } from '@akasecurity/schema';
import {
  CAPTURE_STATUS_DOCUMENT_QUIET_MS,
  WebCaptureStatus as WebCaptureStatusSchema,
  WebSourceTool,
} from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  deriveWebCaptureState,
  reportedCaptureDocumentForSite,
  WEB_CAPTURE_DRIFT_RULE,
  WEB_CAPTURE_DRIFT_STATES,
  webCaptureReport,
  type WebCaptureState,
} from '../../src/posture/web-capture-posture.ts';

function status(over: Partial<WebCaptureStatus> = {}): WebCaptureStatus {
  return WebCaptureStatusSchema.parse({
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
    ...over,
  });
}

/** A live document that has said nothing since the report it carries. */
function record(
  tool: ReportedCaptureDocument['tool'],
  over: Partial<WebCaptureStatus> = {},
  observedAt = '2026-01-01T00:00:00.000Z',
  document: Partial<
    Pick<ReportedCaptureDocument, 'rootSessionId' | 'lastReportAt' | 'closed'>
  > = {},
): ReportedCaptureDocument {
  return {
    tool,
    observedAt,
    status: status(over),
    // The defaults are the single-document shape every case below the fold's
    // own describe blocks was written against, so those keep asserting what
    // they asserted: one document, still around, with nothing newer than the
    // row it carries.
    lastReportAt: document.lastReportAt ?? observedAt,
    closed: document.closed ?? false,
    ...(document.rootSessionId === undefined ? {} : { rootSessionId: document.rootSessionId }),
  };
}

const AT_00 = '2026-01-01T00:00:00.000Z';
const AT_05 = '2026-01-01T00:05:00.000Z';

/** A document that went `blind` and is still around to say so. */
function blindDocument(
  observedAt = AT_00,
  document: Partial<Pick<ReportedCaptureDocument, 'rootSessionId' | 'lastReportAt' | 'closed'>> = {
    rootSessionId: 'doc-b',
  },
): ReportedCaptureDocument {
  return record('chatgpt', { blind: true, sendsSeenDom: 3 }, observedAt, document);
}

/** A document that captured a turn — one that DID re-test the site. */
function activeDocument(
  observedAt = AT_05,
  document: Partial<Pick<ReportedCaptureDocument, 'rootSessionId' | 'lastReportAt' | 'closed'>> = {
    rootSessionId: 'doc-a',
  },
): ReportedCaptureDocument {
  return record('chatgpt', { live: true, exchangesSeenNet: 1 }, observedAt, document);
}

/** A document that has loaded, is watching, and has observed nothing at all. */
function watchingDocument(
  observedAt = AT_05,
  document: Partial<Pick<ReportedCaptureDocument, 'rootSessionId' | 'lastReportAt' | 'closed'>> = {
    rootSessionId: 'doc-a',
  },
): ReportedCaptureDocument {
  return record('chatgpt', {}, observedAt, document);
}

function chatgptRow(documents: readonly ReportedCaptureDocument[]) {
  const row = webCaptureReport(documents).find((r) => r.tool === 'chatgpt');
  expect(row).toBeDefined();
  return row;
}

describe('webCaptureReport — shape', () => {
  it('reports one row per registered site, in registry order', () => {
    const rows = webCaptureReport([]);
    expect(rows.map((r) => r.tool)).toEqual(WebSourceTool.options);
  });

  it('a site nothing reported is unreported, not absent', () => {
    const rows = webCaptureReport([record('chatgpt')]);
    const claudeAi = rows.find((r) => r.tool === 'claude-ai');
    expect(claudeAi).toBeDefined();
    expect(claudeAi?.state).toBe('unreported');
    expect('observedAt' in (claudeAi as object)).toBe(false);
  });

  it('drift agrees with WEB_CAPTURE_DRIFT_STATES across the whole state table', () => {
    const base = status();
    const STATES: Record<WebCaptureState, WebCaptureStatus | undefined> = {
      unreported: undefined,
      standby: status({ conversationEndpoints: 0 }),
      unpatched: status({ patched: false }),
      blind: status({ blind: true }),
      degraded: status({ shapeMisses: ['x'] }),
      idle: base,
      active: status({ live: true }),
    };

    let driftCount = 0;
    for (const [state, s] of Object.entries(STATES) as [
      WebCaptureState,
      WebCaptureStatus | undefined,
    ][]) {
      const records: ReportedCaptureDocument[] =
        s === undefined
          ? []
          : [
              {
                tool: 'chatgpt',
                observedAt: AT_00,
                status: s,
                lastReportAt: AT_00,
                closed: false,
              },
            ];
      const row = webCaptureReport(records).find((r) => r.tool === 'chatgpt');
      expect(row?.state).toBe(state);
      expect(row?.drift).toBe(WEB_CAPTURE_DRIFT_STATES.has(state));
      if (row?.drift === true) driftCount++;
    }
    expect(driftCount).toBe(2);
  });

  it('is quiet when nothing has reported at all', () => {
    const rows = webCaptureReport([]);
    expect(rows.some((r) => r.drift)).toBe(false);
    expect(rows.every((r) => r.state === 'unreported')).toBe(true);
    expect(rows.every((r) => !('remediation' in r))).toBe(true);
  });

  it('is quiet on a build that declares nothing, however loud the rest of the report is', () => {
    const rows = webCaptureReport([
      record('chatgpt', {
        conversationEndpoints: 0,
        closed: false,
        patched: true,
        blind: true,
        parseFailures: 5,
        shapeMisses: ['message.id'],
        sendsSeenDom: 9,
      }),
    ]);
    const chatgpt = rows.find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.state).toBe('standby');
    expect(chatgpt?.drift).toBe(false);
    expect(chatgpt !== undefined && 'remediation' in chatgpt).toBe(false);
  });

  it('a drifting row carries remediation; a non-drifting one carries none', () => {
    const rows = webCaptureReport([
      record('chatgpt', { blind: true }),
      record('claude-ai', { live: true }),
    ]);
    const chatgpt = rows.find((r) => r.tool === 'chatgpt');
    const claudeAi = rows.find((r) => r.tool === 'claude-ai');
    expect(chatgpt?.remediation).toBeTruthy();
    expect(claudeAi !== undefined && 'remediation' in claudeAi).toBe(false);
  });

  it('derives each site from its own documents', () => {
    const rows = webCaptureReport([
      record('chatgpt', { blind: true }),
      record('claude-ai', { live: true }),
    ]);
    const drifting = rows.filter((r) => r.drift);
    expect(drifting).toHaveLength(1);
    expect(drifting[0]?.tool).toBe('chatgpt');
    const claudeAi = rows.find((r) => r.tool === 'claude-ai');
    expect(claudeAi?.headline).toContain('turn');
  });

  it('carries the record observedAt through', () => {
    const rows = webCaptureReport([record('chatgpt', {}, '2026-03-04T05:06:07.000Z')]);
    const chatgpt = rows.find((r) => r.tool === 'chatgpt');
    expect(chatgpt?.observedAt).toBe('2026-03-04T05:06:07.000Z');
  });

  it('the rule carries the id and severity every surface cites it by', () => {
    expect(WEB_CAPTURE_DRIFT_RULE.ruleId).toBe('web-capture-drift');
    expect(WEB_CAPTURE_DRIFT_RULE.severity).toBe('medium');
  });
});

// A browser is many documents and each reports only about itself, so a site's
// state is a fold rather than a lookup. Every case here is two documents on
// ONE site: the single-document cases above cannot tell a fold from a `find`.
describe('webCaptureReport — two documents on one site', () => {
  it('a healthy document does not mask another document-s drift', () => {
    // The healthy document is FIRST, which is the order the store's own read
    // returns (newest first) — and the order in which a `find` over the list
    // returns it and reports the site healthy while a tab is still swallowing
    // the user's messages.
    const row = chatgptRow([activeDocument(), blindDocument()]);
    expect(row?.state).toBe('blind');
    expect(row?.drift).toBe(true);
  });

  it('reports blind when the drifting document is the newer one', () => {
    // The positive control: reversed in time, this passed before the fold
    // existed, so its green says nothing on its own — it is here to show the
    // case above differs from it in the ORDER alone.
    const row = chatgptRow([blindDocument(AT_05), activeDocument(AT_00)]);
    expect(row?.state).toBe('blind');
  });

  it('a closed document stops voting once a live one has captured a turn', () => {
    // The reload the `blind` remediation asks for: the document that was told
    // to reload is gone, and the page that replaced it has observed the site's
    // turn path. Without this the fold would keep the verdict for the whole
    // recency window and the fix the copy prescribes could never clear it.
    const row = chatgptRow([
      activeDocument(),
      blindDocument(AT_00, { rootSessionId: 'doc-b', closed: true }),
    ]);
    expect(row?.state).toBe('active');
    expect(row?.drift).toBe(false);
  });

  it('a closed document keeps voting while nothing has re-tested the site', () => {
    // Same reload, but the new page has only patched and is watching — it has
    // tested nothing, so it clears nothing. This is the picker's own rule at
    // document grain, and it is what stops a reload blanking the site.
    const row = chatgptRow([
      watchingDocument(),
      blindDocument(AT_00, { rootSessionId: 'doc-b', closed: true }),
    ]);
    expect(row?.state).toBe('blind');
  });

  it('a document quiet past the bound stops voting once a live one re-tested', () => {
    // The document that died without a `pagehide` — a crash, an OS kill, a
    // discarded tab. It cannot say it is going away, so falling far enough
    // behind the site's newest report is what retires it.
    const longAgo = new Date(
      Date.parse(AT_05) - CAPTURE_STATUS_DOCUMENT_QUIET_MS - 1,
    ).toISOString();
    const row = chatgptRow([
      activeDocument(),
      blindDocument(longAgo, { rootSessionId: 'doc-b', lastReportAt: longAgo }),
    ]);
    expect(row?.state).toBe('active');
  });

  it('a document still inside the bound keeps voting', () => {
    // One millisecond the other side of the same bound, so this and the case
    // above straddle it: together they pin the constant rather than merely
    // exercising the branch.
    const recently = new Date(Date.parse(AT_05) - CAPTURE_STATUS_DOCUMENT_QUIET_MS).toISOString();
    const row = chatgptRow([
      activeDocument(),
      blindDocument(recently, { rootSessionId: 'doc-b', lastReportAt: recently }),
    ]);
    expect(row?.state).toBe('blind');
  });

  it('reads a document-s liveness from its own last word, not the row it carries', () => {
    // The picker inside a document chooses the newest row that observed the
    // turn path, which can be older than the document's newest report. A fold
    // that measured the quiet bound against the PICKED row's timestamp would
    // retire a document that reported thirty seconds ago.
    const longAgo = new Date(
      Date.parse(AT_05) - CAPTURE_STATUS_DOCUMENT_QUIET_MS - 1,
    ).toISOString();
    const row = chatgptRow([
      activeDocument(),
      blindDocument(longAgo, { rootSessionId: 'doc-b', lastReportAt: AT_05 }),
    ]);
    expect(row?.state).toBe('blind');
  });

  it('answers the same whichever order the documents arrive in', () => {
    const documents = [
      blindDocument(AT_00, { rootSessionId: 'doc-b' }),
      blindDocument(AT_00, { rootSessionId: 'doc-c' }),
      activeDocument(AT_00, { rootSessionId: 'doc-a' }),
    ];
    const forward = reportedCaptureDocumentForSite(documents);
    const backward = reportedCaptureDocumentForSite([...documents].reverse());
    expect(forward?.rootSessionId).toBe(backward?.rootSessionId);
    // And it is one of the two worst, not whichever the array put first.
    expect(forward?.rootSessionId).toBe('doc-c');
  });

  it('does not let one site-s documents decide another site', () => {
    const row = webCaptureReport([
      blindDocument(AT_00, { rootSessionId: 'doc-b' }),
      record('claude-ai', { live: true }, AT_00, { rootSessionId: 'doc-x' }),
    ]);
    expect(row.find((r) => r.tool === 'chatgpt')?.state).toBe('blind');
    expect(row.find((r) => r.tool === 'claude-ai')?.state).toBe('active');
  });

  it('answers no documents with undefined', () => {
    expect(reportedCaptureDocumentForSite([])).toBeUndefined();
  });
});

// The fold takes the WORST state, and nothing in the module's own ordering
// says which that is: the union's declaration order and
// `deriveWebCaptureState`'s branch order are both precedence. So the ranking
// is pinned pairwise, which goes red however a future ordering is worded.
describe('reportedCaptureDocumentForSite — the severity order', () => {
  // Annotated over the union minus `unreported`, so a state added to
  // `WebCaptureState` fails to compile here until it is placed. `unreported`
  // is excluded because no DOCUMENT can be in it — it is what an absent
  // status derives to, and the case above pins that an empty list is what
  // produces it.
  const STATUS_FOR: Record<Exclude<WebCaptureState, 'unreported'>, Partial<WebCaptureStatus>> = {
    blind: { blind: true },
    degraded: { shapeMisses: ['x'] },
    unpatched: { patched: false },
    idle: {},
    standby: { conversationEndpoints: 0 },
    active: { live: true },
  };

  // Worst first. The two drift states lead: a tap that failed to install is
  // common after an extension reload and must not hide drift another document
  // measured, and `standby` sits under `idle` because a build that declares no
  // endpoints says nothing about the site at all.
  const WORST_FIRST = ['blind', 'degraded', 'unpatched', 'idle', 'standby', 'active'] as const;

  it('every row reaches the state it names', () => {
    // The anti-vacuity guard for the table below: an override whose shape is
    // wrong derives to some OTHER state, and the pair then compares two states
    // neither of them names while still passing.
    for (const [state, over] of Object.entries(STATUS_FOR) as [
      Exclude<WebCaptureState, 'unreported'>,
      Partial<WebCaptureStatus>,
    ][]) {
      expect(deriveWebCaptureState(status(over)), `row ${state}`).toBe(state);
    }
    expect([...WORST_FIRST].sort()).toEqual(Object.keys(STATUS_FOR).sort());
  });

  type DocumentState = Exclude<WebCaptureState, 'unreported'>;
  const pairs: [DocumentState, DocumentState][] = WORST_FIRST.flatMap((worse, at) =>
    WORST_FIRST.slice(at + 1).map((better): [DocumentState, DocumentState] => [worse, better]),
  );

  it.each(pairs)('%s outranks %s', (worse, better) => {
    const documents = [
      record('chatgpt', STATUS_FOR[better], AT_00, { rootSessionId: 'doc-better' }),
      record('chatgpt', STATUS_FOR[worse], AT_00, { rootSessionId: 'doc-worse' }),
    ];
    expect(deriveWebCaptureState(reportedCaptureDocumentForSite(documents)?.status)).toBe(worse);
    expect(
      deriveWebCaptureState(reportedCaptureDocumentForSite([...documents].reverse())?.status),
    ).toBe(worse);
  });

  it('pins every pair of the six states a document can be in', () => {
    // 6 choose 2. Without this the loop above could silently generate none.
    expect(pairs).toHaveLength(15);
  });
});
