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
    findSendButton()?.click();
  },
};
