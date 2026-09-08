import {
  extractComposerText,
  firstMatch,
  setComposerText,
  watchButtonClick,
  watchEnterToSend,
} from './dom-utils.ts';
import type { ProviderAdapter } from './types.ts';

// Best-effort, layered fallback selectors — chatgpt.com's DOM has carried
// #prompt-textarea and data-testid="send-button" across several redesigns,
// but neither is guaranteed for whatever build is live when this loads. A
// miss here means findComposer()/findSendButton() return null and this
// adapter silently does nothing (fail-open) rather than misfiring on the
// wrong element. These selectors track the live site best-effort and can go
// stale with a redesign — verify against the real site before relying on
// block/redact actually firing.
const COMPOSER_SELECTORS = [
  '#prompt-textarea',
  'form [contenteditable="true"][role="textbox"]',
  'form [contenteditable="true"]',
];
const SEND_BUTTON_SELECTORS = ['[data-testid="send-button"]', 'button[aria-label*="send" i]'];

function findSendButton(): HTMLElement | null {
  return firstMatch(SEND_BUTTON_SELECTORS);
}

export const chatgptAdapter: ProviderAdapter = {
  id: 'chatgpt',
  hostnames: ['chatgpt.com', 'chat.openai.com'],
  findComposer() {
    return firstMatch(COMPOSER_SELECTORS);
  },
  findSendButton,
  extractText: extractComposerText,
  setText: setComposerText,
  watchSubmit(composer, onSubmit) {
    const unwatchEnter = watchEnterToSend(composer, onSubmit);
    const sendButton = findSendButton();
    const unwatchClick = sendButton ? watchButtonClick(sendButton, onSubmit) : undefined;
    return () => {
      unwatchEnter();
      unwatchClick?.();
    };
  },
  submit() {
    const sendButton = findSendButton();
    if (!sendButton) return false;
    sendButton.click();
    return true;
  },

  // NETWORK HALF — UNIMPLEMENTED, and not for a single, blanket reason.
  // chatgpt.com serves this adapter's traffic over two routes with nothing
  // in common but the host, and each is blocked on something different:
  //
  // - The ANONYMOUS turn route (`/unauth-mweb/conversation/updates`) IS
  //   known: its path was read off a real capture, and its response is
  //   streamed HTML template fragments carrying `data-*` attributes (not
  //   SSE, not JSON). What blocks a parser for it is two unobserved
  //   SEMANTICS, not the URL: whether the assistant's text is the
  //   VALUE of `data-assistant-stream-block` or the element's CONTENT (the
  //   two produce different strings, and picking either without evidence
  //   would emit markup as if it were the reply), and which of possibly
  //   several `data-message-id` values names the assistant's message rather
  //   than the user's — the natural key a stored row would hash on. Both are
  //   settled by one uncapped capture of a complete anonymous turn.
  // - The AUTHENTICATED turn route's WIRE FORMAT is known (JSON request; SSE
  //   with a `delta_encoding: v1` preamble and p/o/v/c delta objects), but
  //   its PATH was never isolated — only that it sits somewhere under
  //   `/backend-api/` and is not `sentinel`. "Under /backend-api/" is not a
  //   path, so no entry is declared for it; a placeholder or a guessed route
  //   would be exactly the invented-endpoint failure this project forbids.
  //
  // An empty `endpoints` generates an empty entry in the tap's build-time
  // table, so the tap forwards nothing from this site and the parsers below
  // are never reached. An adapter that matches nothing is honest; one that
  // matches a guessed URL reads as coverage while observing the wrong
  // traffic, or none.
  endpoints: [],
  requiredPaths: { request: [], response: [] },
  // No endpoint is declared above, so there is nothing for a parser to switch
  // on yet — an empty array is the honest state until one is.
  protocolTokens: [],
  parseRequest: () => ({ requiredPathsSeen: false }),
  parseStream: () => ({ push: () => undefined, end: () => null }),
};
