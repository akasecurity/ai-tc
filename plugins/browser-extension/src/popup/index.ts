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
  WebChatWithholding,
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

/**
 * The enforcement states that are a FAULT — every member of the vocabulary
 * except the two that are not one.
 *
 * Spelled as an exclusion rather than as its own list so the table below is a
 * total map over it: a member added to `WebEnforcementState` lands in this
 * type and fails to compile until someone writes its sentence.
 */
type EnforcementFault = Exclude<WebEnforcementState, 'watching' | 'unknown'>;

// What a half-resolved composer means, in words a user can act on. 'watching'
// and 'unknown' are excluded above rather than merely omitted here: the first
// is healthy, and the second is the absence of an opinion rather than a fault —
// rendering it would put a warning on every tab whose DOM half has not run
// yet. A `Partial<Record<…>>` expressed that by allowing any key to be absent,
// which also let a NEW fault state render no note with no compile error to say
// so; annotated total over the exclusion, the compiler asks for the sentence.
const ENFORCEMENT_NOTES: Record<EnforcementFault, string> = {
  'composer-only': 'not enforcing — send button not found',
  'button-only': 'not enforcing — composer not found',
  unattached: 'not enforcing — composer and send button not found',
};

// Why nothing from a chat is recorded on this machine, in words. Total over the
// vocabulary, so a reason added to the schema fails to compile until it is
// worded here.
export const WITHHELD_NOTES: Record<WebChatWithholding, string> = {
  'personal-device':
    'personal device — chats are checked, and only replies in an enrolled account are recorded or sent',
  'unreadable-attachment':
    'attachment unreadable — chats are checked, and nothing from them is recorded or sent; run aka status',
};

/**
 * The line naming the account a site's requests were last seen in, on a machine
 * that withholds web chats: whether replies in it are recorded and sent, and if
 * not, why, with the command that would enroll it.
 */
export function accountNote(account: {
  identity: string;
  enrolled: boolean;
  recorded: boolean;
}): string {
  if (account.recorded)
    return `${account.identity} — enrolled; replies in it are recorded and sent`;
  if (account.enrolled) {
    return `${account.identity} — enrolled, but web-chat capture is off, so nothing is recorded`;
  }
  return `${account.identity} — not enrolled; to send its replies, run aka enroll --account ${account.identity}`;
}

// Read through a widened ALIAS rather than a cast at the lookup: the table is
// total over the faults, and this is the one place a full-vocabulary state
// indexes it. Assignment, not assertion — so the widening is checked.
const NOTE_FOR: Readonly<Partial<Record<WebEnforcementState, string>>> = ENFORCEMENT_NOTES;

/** Render the network-capture section from a `capture_state` reply. */
export function renderCaptureSites(response: CaptureStateResponse): void {
  const section = document.getElementById('capture-section');
  const notEnabled = document.getElementById('capture-not-enabled');
  const withheldEl = document.getElementById('capture-withheld');
  const sitesEl = document.getElementById('capture-sites');
  if (!section || !notEnabled || !withheldEl || !sitesEl) return;
  section.hidden = false;
  // Ahead of the consent answer: a machine that withholds records nothing from
  // a chat whether or not capture was consented to, so the network states would
  // describe recording that is not happening. What still matters there is
  // whether each site is being CHECKED, so its enforcement faults are shown
  // beneath the line. An older host's reply lacks the field and reads as not
  // withheld.
  withheldEl.hidden = response.withheld === undefined;
  if (response.withheld !== undefined) {
    withheldEl.textContent = WITHHELD_NOTES[response.withheld];
    notEnabled.hidden = true;
    sitesEl.replaceChildren(
      ...response.sites.flatMap((site) => {
        const rows: HTMLElement[] = [];
        // The account first: it is what decides whether anything is recorded,
        // and the line carries the command that enrolls it.
        if (site.account !== undefined) {
          const accountRow = document.createElement('div');
          accountRow.className = 'row muted';
          accountRow.textContent = `${SITE_LABELS[site.tool]}: ${accountNote(site.account)}`;
          rows.push(accountRow);
        }
        const note = site.enforcement === undefined ? undefined : NOTE_FOR[site.enforcement];
        if (note !== undefined) {
          const row = document.createElement('div');
          row.className = 'row tone-error';
          row.textContent = `${SITE_LABELS[site.tool]}: ${note}`;
          rows.push(row);
        }
        return rows;
      }),
    );
    return;
  }
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
    const note = site.enforcement === undefined ? undefined : NOTE_FOR[site.enforcement];
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
