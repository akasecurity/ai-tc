// @vitest-environment jsdom
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { claudeAdapter } from '../../src/providers/claude.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const ADAPTER_SOURCE = readFileSync(
  join(HERE, '..', '..', 'src', 'providers', 'claude.ts'),
  'utf8',
);

// The selector lists as written in the adapter's own source — the fixture
// below is asserted against them, so a selector change that leaves the
// fixture behind fails here instead of silently testing a stale DOM shape.
function selectorsFrom(name: string): string[] {
  // Non-greedy up to the array's closing `];` — the selector strings
  // themselves contain `]` characters.
  const block = new RegExp(`${name} = \\[([\\s\\S]*?)\\];`).exec(ADAPTER_SOURCE)?.[1];
  if (block === undefined) throw new Error(`no ${name} array in claude.ts`);
  return [...block.matchAll(/'([^']+)'/g)].map((m) => m[1] ?? '');
}
const COMPOSER_SELECTORS = selectorsFrom('COMPOSER_SELECTORS');
const SEND_BUTTON_SELECTORS = selectorsFrom('SEND_BUTTON_SELECTORS');

function mountFixture(): { composer: HTMLElement; sendButton: HTMLElement } {
  document.body.innerHTML = `
    <fieldset>
      <div contenteditable="true" aria-label="Write your prompt to Claude"></div>
      <button type="submit" aria-label="Send message">Send</button>
    </fieldset>`;
  const composer = document.querySelector<HTMLElement>('div[contenteditable]');
  const sendButton = document.querySelector<HTMLElement>('button');
  if (!composer || !sendButton) throw new Error('fixture failed to mount');
  return { composer, sendButton };
}

beforeEach(() => {
  document.body.innerHTML = '';
});

describe('claudeAdapter', () => {
  it('the fixture matches the selector lists the adapter actually queries', () => {
    const { composer, sendButton } = mountFixture();
    expect(COMPOSER_SELECTORS.some((selector) => composer.matches(selector))).toBe(true);
    expect(SEND_BUTTON_SELECTORS.some((selector) => sendButton.matches(selector))).toBe(true);
  });

  it('finds the composer and the send button', () => {
    const { composer, sendButton } = mountFixture();
    expect(claudeAdapter.findComposer()).toBe(composer);
    expect(claudeAdapter.findSendButton()).toBe(sendButton);
  });

  it('watchSubmit fires on Enter keydown AND on a send-button click; cleanup detaches both', () => {
    const { composer, sendButton } = mountFixture();
    const onSubmit = vi.fn();
    const cleanup = claudeAdapter.watchSubmit(composer, onSubmit);

    composer.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).toHaveBeenCalledTimes(1);

    sendButton.click();
    expect(onSubmit).toHaveBeenCalledTimes(2);

    cleanup();
    composer.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    sendButton.click();
    expect(onSubmit).toHaveBeenCalledTimes(2);
  });
});
