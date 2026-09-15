// The two facts this extension's content scripts share within one tab.
//
// Chrome runs every content script an extension injects into a frame in ONE
// isolated world, so they share a global object while each keeps its own module
// scope. That shared object is the only channel between them — they cannot
// import each other without bundling one into the other, and the manifest loads
// them as separate files on purpose (the network half must be listening at
// document_start, the DOM half needs a mounted composer).
//
// Both entries are scoped to the isolated world, which page script cannot
// reach: a site can neither read the session id nor drive the DOM-send signal.

export interface SharedScope {
  __akaWebSessionId?: string;
  __akaNoteDomSend?: () => void;
  // Deliberately `string` rather than the union below: this crosses a shared
  // global, so what a reader gets is whatever was last written there, and the
  // read validates rather than trusting the declaration.
  __akaEnforcement?: string;
  __akaNoteEnforcement?: () => void;
}

// Mirrors WebEnforcementState's members in @akasecurity/schema. Carried rather
// than imported because this module is bundled into the content scripts, which
// take no runtime dependency on schema; test/tab-session.test.ts pins the two
// lists equal, so a member added there fails here.
const ENFORCEMENT_STATES = [
  'watching',
  'composer-only',
  'button-only',
  'unattached',
  'unknown',
] as const;

export type EnforcementState = (typeof ENFORCEMENT_STATES)[number];

/**
 * The session id both halves of the tab report under.
 *
 * Minted by whichever script runs first and adopted by the rest. Two ids for
 * one tab would put the network path's `llm_call` leaves under a different
 * session root than the DOM path's prompts, so a turn could never be joined to
 * the message that produced it.
 */
export function resolveSessionId(scope: SharedScope): string {
  const existing = scope.__akaWebSessionId;
  if (typeof existing === 'string' && existing !== '') return existing;
  const minted = crypto.randomUUID();
  scope.__akaWebSessionId = minted;
  return minted;
}

/**
 * Register what to call when the DOM path observes a send.
 *
 * The network path needs it because installation is not visibility: a tap that
 * patched cleanly and forwards nothing looks exactly like a tab nobody typed
 * in, and a DOM send with no network exchange behind it is the one signal that
 * tells the two apart.
 */
export function setDomSendListener(scope: SharedScope, listener: () => void): void {
  scope.__akaNoteDomSend = listener;
}

/** Report a DOM-observed send. A no-op when nothing registered. */
export function notifyDomSend(scope: SharedScope): void {
  try {
    scope.__akaNoteDomSend?.();
  } catch {
    // Health reporting never delays or breaks the send it is reporting on.
  }
}

/**
 * Record what the DOM enforcement path is doing in this tab.
 *
 * Written on every reattach, not only when it succeeds. The network half is
 * what reports status, and it cannot see the DOM half's own resolution — so
 * without this a tab whose watcher never bound is indistinguishable from one
 * nobody typed in, on every surface the product has.
 */
export function publishEnforcementState(scope: SharedScope, state: EnforcementState): void {
  scope.__akaEnforcement = state;
  // Notifying is part of publishing, not a second step the caller can forget.
  // The network half is what relays status and recomputes only on its own
  // events, so a publish nobody is told about sits here unreported — on a tab
  // with no network traffic, permanently. That was a real gap, and a separate
  // notify call is exactly the shape that produced it.
  try {
    scope.__akaNoteEnforcement?.();
  } catch {
    // Health reporting never breaks the half that is reporting.
  }
}

/** Register what to call when the DOM half publishes a new enforcement state. */
export function setEnforcementListener(scope: SharedScope, listener: () => void): void {
  scope.__akaNoteEnforcement = listener;
}

/** The last published state, or 'unknown' when nothing valid has been. */
export function readEnforcementState(scope: SharedScope): EnforcementState {
  const raw = scope.__akaEnforcement;
  return ENFORCEMENT_STATES.includes(raw as EnforcementState)
    ? (raw as EnforcementState)
    : 'unknown';
}
