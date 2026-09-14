/**
 * Minimal popup status UI: native-host connection state, a whole-store
 * findings tally (via the health relay — see native-host/protocol.ts), a
 * per-site network-capture line, and a quick link to `aka dashboard`. Mirrors
 * the CLI plugins' onboarding/health surfaces, much smaller — this is a
 * glance, not a dashboard.
 */
import type { BackgroundRequest, BackgroundResponse } from '../messaging.ts';
import type {
  CaptureStateResponse,
  WebCaptureState,
  WebEnforcementState,
  WebSourceTool,
} from '../native-host/protocol.ts';

const DASHBOARD_URL = 'http://localhost:4319/security';

// Annotated Record<WebSourceTool, …> so a site added to the schema subset
// fails to compile here until it is given a label (§2's convention).
const SITE_LABELS: Record<WebSourceTool, string> = {
  chatgpt: 'ChatGPT',
  'claude-ai': 'Claude.ai',
};

// Mirrors @akasecurity/detections' WEB_CAPTURE_DRIFT_STATES. Duplicated
// rather than imported: this file ships in esbuild's BROWSER bundle, and
// @akasecurity/detections — like @akasecurity/plugin-sdk, which wraps it —
// pulls in Node-only code (node:sqlite, node:worker_threads) that cannot
// resolve for a browser target. bridge.ts keeps its own copy of
// RESPONSE_TEXT_MAX_BYTES for the identical reason.
//
// Typed against the vocabulary so a typo is a compile error, and exported so
// popup.test.ts can hold it equal to the original — the copy is only as good
// as the check that keeps it true, which is the half of the bridge's precedent
// that matters.
export const DRIFT_STATES: ReadonlySet<WebCaptureState> = new Set<WebCaptureState>([
  'blind',
  'degraded',
]);

// What a half-resolved composer means, in words a user can act on. 'watching'
// and 'unknown' are deliberately absent: the first is healthy, and the second is
// the absence of an opinion rather than a fault — rendering it would put a
// warning on every tab whose DOM half has not run yet.
const ENFORCEMENT_NOTES: Partial<Record<WebEnforcementState, string>> = {
  'composer-only': 'not enforcing — send button not found',
  'button-only': 'not enforcing — composer not found',
  unattached: 'not enforcing — composer and send button not found',
};

/** Render the network-capture section from a `capture_state` reply. */
export function renderCaptureSites(response: CaptureStateResponse): void {
  const section = document.getElementById('capture-section');
  const notEnabled = document.getElementById('capture-not-enabled');
  const sitesEl = document.getElementById('capture-sites');
  if (!section || !notEnabled || !sitesEl) return;
  section.hidden = false;
  if (!response.consented) {
    notEnabled.hidden = false;
    sitesEl.replaceChildren();
    return;
  }
  notEnabled.hidden = true;
  const rows = response.sites.flatMap((site) => {
    const row = document.createElement('div');
    row.className = `row ${DRIFT_STATES.has(site.state) ? 'tone-error' : 'muted'}`;
    row.textContent = `${SITE_LABELS[site.tool]}: ${site.state}`;
    const note = site.enforcement === undefined ? undefined : ENFORCEMENT_NOTES[site.enforcement];
    if (note === undefined) return [row];
    // A second row rather than a word folded into the first: the two describe
    // different halves, and a tab can read the site perfectly while enforcing
    // nothing on it.
    const enforcementRow = document.createElement('div');
    enforcementRow.className = 'row tone-error';
    enforcementRow.textContent = `${SITE_LABELS[site.tool]}: ${note}`;
    return [row, enforcementRow];
  });
  sitesEl.replaceChildren(...rows);
}

function relay(request: BackgroundRequest): Promise<BackgroundResponse> {
  return chrome.runtime.sendMessage<BackgroundRequest, BackgroundResponse>(request);
}

function setStatus(text: string, tone: 'ok' | 'error' | 'pending'): void {
  const dot = document.getElementById('status-dot');
  const label = document.getElementById('status-text');
  if (dot) dot.className = `dot ${tone === 'pending' ? '' : tone}`.trim();
  if (label) label.textContent = text;
}

function setFindings(count: number): void {
  const row = document.getElementById('findings-row');
  const text = document.getElementById('findings-text');
  if (!row || !text) return;
  text.textContent = `${count.toString()} finding${count === 1 ? '' : 's'} recorded (all time)`;
  row.hidden = false;
}

/** Exported for its own test — re-invoked under a stubbed relay. */
export async function refresh(): Promise<void> {
  const ping = await relay({ type: 'ping' }).catch((): BackgroundResponse => ({
    type: 'error',
    requestId: undefined,
    ok: false,
    message: 'relay failed',
  }));

  if (ping.type !== 'ping') {
    setStatus('Native host not reachable — run `aka extension install`', 'error');
    return;
  }
  setStatus(ping.onboarded ? 'Connected' : 'Connected (not onboarded — run aka:setup)', 'ok');

  const health = await relay({ type: 'health' }).catch((): BackgroundResponse => ({
    type: 'error',
    requestId: undefined,
    ok: false,
    message: 'relay failed',
  }));
  if (health.type === 'health') setFindings(health.findings);

  const captureState = await relay({ type: 'capture_state' }).catch((): BackgroundResponse => ({
    type: 'error',
    requestId: undefined,
    ok: false,
    message: 'relay failed',
  }));
  // A non-capture_state reply (an old host that predates this request type)
  // leaves the section hidden — it starts `hidden` in the markup.
  if (captureState.type === 'capture_state') renderCaptureSites(captureState);
}

document.getElementById('open-dashboard')?.addEventListener('click', () => {
  void chrome.tabs.create({ url: DASHBOARD_URL });
});

void refresh();
