// Posture over one browser-extension tab's reported `WebCaptureStatus` — a
// sibling of config-posture.ts rather than an addition to it, because that
// module's whole surface is `ConfigScanResult`-shaped and this input is not.
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
import type { WebCaptureStatus } from '@akasecurity/schema';

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

export const WEB_CAPTURE_POSTURE_RULES: readonly InspectionDefinitionInput[] = [
  {
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
  },
];

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
    headline: 'no page has reported yet — open the site in Chrome with the extension loaded',
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
