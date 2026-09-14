// Posture over the browser extension's reported `WebCaptureStatus` rows — one
// state per SITE, folded from every document that reported for it, since a
// browser is many documents and each reports only for itself. A sibling of
// config-posture.ts rather than an addition to it, because that module's whole
// surface is `ConfigScanResult`-shaped and this input is not.
// Pure like everything in @akasecurity/detections: no I/O, no Node APIs.
//
// The state vocabulary exists to answer one question honestly: is a site's
// capture silent because nobody has surveyed its endpoints yet (Phase 0 —
// every machine today), or because its contract moved underneath a capture
// that used to work (real drift)? Both look identical on every field except
// `conversationEndpoints`, which is why that field is tested FIRST in
// `deriveWebCaptureState` and why no later branch may be reordered above it —
// doing so would ship a rule that fires on every machine that merely installs
// the extension, for a reason that is not drift.
import type { InspectionDefinitionInput } from '@akasecurity/schema';
import type { ReportedCaptureDocument, WebCaptureStatus, WebSourceTool } from '@akasecurity/schema';
import {
  CAPTURE_STATUS_DOCUMENT_QUIET_MS,
  CAPTURE_STATUS_RECENCY_DAYS,
  webCaptureStatusObservedTurnPath,
  WebSourceTool as WebSourceToolEnum,
} from '@akasecurity/schema';

const RULE_VERSION = '1';

/**
 * What one web chat site's network capture is doing, in one word.
 *
 * Ordered by precedence, not by severity: `deriveWebCaptureState` returns the
 * FIRST that applies, and the order is what stops a site with nothing declared
 * from being read as a site that went silent.
 */
export type WebCaptureState =
  'unreported' | 'standby' | 'unpatched' | 'blind' | 'degraded' | 'active' | 'idle';

/** Broken turns before the parser is treated as stale rather than unlucky. */
export const DRIFT_MIN_PARSE_FAILURES = 2;

/** The states `web-capture-drift` fires on. */
export const WEB_CAPTURE_DRIFT_STATES: ReadonlySet<WebCaptureState> = new Set([
  'blind',
  'degraded',
]);

/**
 * The one web-capture posture rule.
 *
 * Singular rather than the `readonly InspectionDefinitionInput[]` its
 * config-posture sibling exports, because the array shape is what
 * `recordConfigScan` takes and nothing persists this rule: every surface reads
 * `.ruleId` and `.severity` off one rule, and an array of one only invited a
 * `[0]` at each of them.
 */
export const WEB_CAPTURE_DRIFT_RULE: InspectionDefinitionInput = {
  ruleId: 'web-capture-drift',
  version: RULE_VERSION,
  name: 'Web chat capture is not reading the site',
  category: 'config',
  severity: 'medium',
  definition: JSON.stringify({
    kind: 'web-capture-drift',
    states: [...WEB_CAPTURE_DRIFT_STATES],
    minParseFailures: DRIFT_MIN_PARSE_FAILURES,
  }),
};

/**
 * Derive the one-word state a reported status is in.
 *
 * `status === undefined` covers a site nothing has ever reported for.
 * `conversationEndpoints === 0` is checked immediately after and BEFORE every
 * other signal, including `blind` — a site with nothing declared can look
 * exactly like a drifting one on every other field (a user who sent messages
 * the network never saw, a stale parser), and the guard is what tells them
 * apart. See `web-capture-posture.test.ts`'s false-signal proof.
 */
export function deriveWebCaptureState(status: WebCaptureStatus | undefined): WebCaptureState {
  if (status === undefined) return 'unreported';
  if (status.conversationEndpoints === 0) return 'standby';
  if (!status.patched) return 'unpatched';
  if (status.blind) return 'blind';
  if (status.shapeMisses.length > 0) return 'degraded';
  if (status.parseFailures >= DRIFT_MIN_PARSE_FAILURES) return 'degraded';
  return status.live ? 'active' : 'idle';
}

/** Whether `web-capture-drift` fires for this status. */
export function webCaptureDriftFires(status: WebCaptureStatus | undefined): boolean {
  return WEB_CAPTURE_DRIFT_STATES.has(deriveWebCaptureState(status));
}

/**
 * How bad each state is, worst first — what the per-site fold takes the worst
 * of.
 *
 * Derived from nothing else, deliberately. `WebCaptureState`'s declaration
 * order and `deriveWebCaptureState`'s branch order are both PRECEDENCE (which
 * test wins), and reading either as severity would rank `standby` and
 * `unpatched` above the two drift states: one of a user's two tabs running a
 * build that declares no endpoints would then outrank a real `blind` verdict
 * from the other, which is the false signal this module's header exists to
 * prevent.
 *
 * The two drift states outrank `unpatched` for the same reason in reverse — a
 * tap that failed to install is common after an extension reload and leaves a
 * row behind it, and it must not hide drift the other document actually
 * measured. `standby` sits below `idle` because a build declaring no endpoints
 * says nothing at all about the site.
 *
 * Annotated `Record<WebCaptureState, number>` so a state added to the union
 * fails to compile until someone decides where it ranks.
 */
const STATE_SEVERITY: Record<WebCaptureState, number> = {
  blind: 0,
  degraded: 1,
  unpatched: 2,
  idle: 3,
  standby: 4,
  active: 5,
  unreported: 6,
};

/**
 * Whether `a`'s report is the one a site should be shown as, against `b`'s.
 *
 * Worst state first, then the newest `observedAt`, then the grouping id — a
 * total order, so the answer never depends on which order the rows came back
 * in. The last term is arbitrary and only has to be deterministic.
 */
function worseThan(a: ReportedCaptureDocument, b: ReportedCaptureDocument): boolean {
  const sa = STATE_SEVERITY[deriveWebCaptureState(a.status)];
  const sb = STATE_SEVERITY[deriveWebCaptureState(b.status)];
  if (sa !== sb) return sa < sb;
  if (a.observedAt !== b.observedAt) return a.observedAt > b.observedAt;
  return (a.rootSessionId ?? '') > (b.rootSessionId ?? '');
}

/**
 * The one document whose report a site is shown as, from every document that
 * reported for it.
 *
 * Two tabs on one site, or a tab and the page it has just replaced, all report
 * for that site at once, and each reports only about itself. Taking the newest
 * of them is what a single-record read does, and it lets a healthy document
 * hide a drifting one — the failure these rows exist to surface. So the WORST
 * state wins, among the documents that still have a vote.
 *
 * A document is RETIRED when it said it was going away (`closed`) or when its
 * newest report is more than `CAPTURE_STATUS_DOCUMENT_QUIET_MS` behind the
 * site's newest. Retired documents are dropped only once some live document
 * has observed the site's turn path — the picker's own rule, lifted to
 * document grain: a page that has just loaded and re-tested nothing may not
 * clear a verdict, and the document it would be clearing is exactly the one it
 * replaced. With no such evidence the retired documents keep voting, so a
 * reload does not blank the site.
 *
 * `undefined` for no documents at all, which reads as `unreported`.
 */
export function reportedCaptureDocumentForSite(
  documents: readonly ReportedCaptureDocument[],
): ReportedCaptureDocument | undefined {
  let newestReport = '';
  for (const d of documents) if (d.lastReportAt > newestReport) newestReport = d.lastReportAt;

  // A timestamp that does not parse counts as live rather than retired:
  // retirement is what DISCARDS a verdict, so an unreadable clock must never
  // be the reason one disappears. Every writer here stamps an ISO instant, so
  // this is a floor and not a case that happens.
  const retired = (d: ReportedCaptureDocument): boolean => {
    if (d.closed) return true;
    const behind = Date.parse(newestReport) - Date.parse(d.lastReportAt);
    return Number.isFinite(behind) && behind > CAPTURE_STATUS_DOCUMENT_QUIET_MS;
  };

  const voting = documents.filter((d) => !retired(d));
  const tested = voting.some((d) => webCaptureStatusObservedTurnPath(d.status));
  const pool = tested ? voting : documents;

  let worst: ReportedCaptureDocument | undefined;
  for (const d of pool) if (worst === undefined || worseThan(d, worst)) worst = d;
  return worst;
}

/**
 * User-facing copy for one state, split into the HEADLINE (the CLI/popup's
 * primary line) and, for the two drift states only, the REMEDIATION (the
 * fix, printed under the rule id). Held here so the CLI and any later surface
 * print the same words rather than each inventing its own.
 *
 * A plain lookup, and `active` no longer quotes the turn count. The count on a
 * stored status is only as current as the report that carried it, and the
 * bridge relays on a TRANSITION rather than per turn — so once a tab has gone
 * live nothing moves the signature again, and every surface went on printing
 * "1 turn observed" for a session of fifty. Bucketing the count into the
 * signature narrows that without closing it (a doubling bucket still says 31
 * for a 62-turn session) and writes rows into a table with no retention
 * policy, so the number is dropped instead. `exchangesSeenNet` is still on the
 * stored status for a surface that wants to show it as of that report.
 */
export interface WebCaptureStateCopy {
  headline: string;
  remediation?: string;
}

const STATIC_COPY: Record<WebCaptureState, WebCaptureStateCopy> = {
  active: { headline: 'turns are being observed on this site' },
  unreported: {
    // Says "recently" rather than "yet": the store read is bounded to
    // CAPTURE_STATUS_RECENCY_MS, so this state covers a site nothing has ever
    // reported for AND one whose last report has aged out. The two are the
    // same fact to a reader — nobody has confirmed anything lately — and the
    // copy may not claim the stronger of them.
    headline: `no report in the last ${String(CAPTURE_STATUS_RECENCY_DAYS)} days — open the site in Chrome with the extension loaded`,
  },
  standby: {
    headline: 'this build declares no endpoints for the site, so nothing is observed yet',
  },
  unpatched: {
    // Says what the flags say and no more. `patched` is false both for a tap
    // that installed and hooked neither transport and for one that never ran
    // at all — a page reports the same status either way, so the copy may not
    // assert one of them.
    headline:
      'the page tap captured neither fetch nor XHR — it may not have installed; reload the extension at chrome://extensions',
  },
  idle: { headline: 'watching; no turn has been observed yet' },
  blind: {
    headline: 'messages were sent in the page that the network capture never saw',
    remediation:
      "reload the tab. If it persists after `aka update` and reloading the extension at chrome://extensions, the site's send path has changed and needs a new extension build.",
  },
  degraded: {
    headline: "the site's payloads no longer carry the fields the extension reads",
    remediation:
      "run `aka update`, then reload the extension at chrome://extensions. If it stays degraded after an update, the site's contract has changed and needs a new extension build.",
  },
};

/** The headline/remediation copy for `state`. */
export function webCaptureStateCopy(state: WebCaptureState): WebCaptureStateCopy {
  return STATIC_COPY[state];
}

/** One site's capture posture, as a read surface renders it. */
export interface WebCaptureSiteReport {
  tool: WebSourceTool;
  state: WebCaptureState;
  /** The primary line for this state. */
  headline: string;
  /** The fix. Present for a drift state and absent for every other. */
  remediation?: string;
  /** Whether `web-capture-drift` fires for this site. */
  drift: boolean;
  /** When the reported status was received, ISO-8601. Absent for an unreported site. */
  observedAt?: string;
}

/**
 * One row per registered site, in registry order, from the documents the local
 * store holds reports from.
 *
 * Every site is reported, including one nothing has reported for — an absent
 * row is a fact the surface has to show, not a row to omit. Each site's state
 * is folded from its OWN documents, so a drifting site never colours another
 * and no site is decided by a document that reported about a different one.
 * Pure: the caller decides whether a report is worth rendering at all.
 */
export function webCaptureReport(
  documents: readonly ReportedCaptureDocument[],
): readonly WebCaptureSiteReport[] {
  return WebSourceToolEnum.options.map((tool) => {
    const record = reportedCaptureDocumentForSite(documents.filter((d) => d.tool === tool));
    const state = deriveWebCaptureState(record?.status);
    const copy = webCaptureStateCopy(state);
    return {
      tool,
      state,
      headline: copy.headline,
      ...(copy.remediation !== undefined ? { remediation: copy.remediation } : {}),
      drift: WEB_CAPTURE_DRIFT_STATES.has(state),
      ...(record !== undefined ? { observedAt: record.observedAt } : {}),
    };
  });
}
