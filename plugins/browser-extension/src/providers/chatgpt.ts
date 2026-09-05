import {
  extractContentEditableText,
  firstMatch,
  setContentEditableText,
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
  extractText: extractContentEditableText,
  setText: setContentEditableText,
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

  // The network half is UNIMPLEMENTED for this site: the endpoint paths and
  // stream shapes chatgpt.com actually uses are not known to this repository
  // and are not guessed here. An empty `endpoints` generates an empty entry in
  // the tap's build-time table, so the tap forwards nothing from this site and
  // the parsers below are never reached. An adapter that matches nothing is
  // honest; one that matches a guessed URL reads as coverage while observing
  // the wrong traffic, or none.
  endpoints: [],
  requiredPaths: { request: [], response: [] },
  parseRequest: () => ({ requiredPathsSeen: false }),
  parseStream: () => ({ push: () => undefined, end: () => null }),
};
