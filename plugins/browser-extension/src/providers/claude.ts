import {
  extractContentEditableText,
  firstMatch,
  setContentEditableText,
  watchButtonClick,
  watchEnterToSend,
} from './dom-utils.ts';
import type { ProviderAdapter } from './types.ts';

// Same caveat as chatgpt.ts: best-effort, layered fallback selectors that
// can go stale with a site redesign — verify against the live site before
// relying on block/redact actually firing.
const COMPOSER_SELECTORS = [
  'div[contenteditable="true"][aria-label*="claude" i]',
  'fieldset [contenteditable="true"]',
  'form [contenteditable="true"]',
];
const SEND_BUTTON_SELECTORS = ['button[aria-label*="send" i]', 'fieldset button[type="submit"]'];

function findSendButton(): HTMLElement | null {
  return firstMatch(SEND_BUTTON_SELECTORS);
}

export const claudeAdapter: ProviderAdapter = {
  id: 'claude-ai',
  hostnames: ['claude.ai'],
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

  // Same as chatgpt.ts: the network half is UNIMPLEMENTED, because claude.ai's
  // endpoint paths and stream shapes are not known to this repository and are
  // not guessed. An empty `endpoints` puts nothing in the tap's build-time
  // table, so nothing from this site is forwarded and the parsers below are
  // never reached.
  endpoints: [],
  requiredPaths: { request: [], response: [] },
  parseRequest: () => ({ requiredPathsSeen: false }),
  parseStream: () => ({ push: () => undefined, end: () => null }),
};
