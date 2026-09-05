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
}

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
