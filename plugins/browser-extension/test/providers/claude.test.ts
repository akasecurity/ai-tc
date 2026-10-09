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

describe('claudeAdapter.workspaceOf', () => {
  const ORG = '0a1b2c3d-0000-4000-8000-00000000000a';
  const CONVERSATION = '0a1b2c3d-0000-4000-8000-00000000000b';
  const completion = (org: string): string =>
    `https://claude.ai/api/organizations/${org}/chat_conversations/${CONVERSATION}/completion`;
  const endpoint = claudeAdapter.endpoints[0];
  if (endpoint === undefined) throw new Error('the claude adapter declares no endpoint');
  const read = (url: string): string | undefined => claudeAdapter.workspaceOf?.({ url, endpoint });

  it('reads the organization the completion request names', () => {
    expect(read(completion(ORG))).toBe(ORG);
  });

  it('reads each request on its own, so a switch between turns is seen on the next one', () => {
    const other = '0a1b2c3d-0000-4000-8000-00000000000c';
    expect(read(completion(ORG))).toBe(ORG);
    expect(read(completion(other))).toBe(other);
  });

  it('ignores a query string', () => {
    expect(read(`${completion(ORG)}?rendering_mode=messages`)).toBe(ORG);
  });

  it('reads nothing off a route that is not the completion route', () => {
    expect(
      read(`https://claude.ai/api/organizations/${ORG}/chat_conversations/${CONVERSATION}`),
    ).toBeUndefined();
    expect(read(`https://claude.ai/api/organizations/${ORG}/projects`)).toBeUndefined();
    expect(
      read(`https://claude.ai/organizations/${ORG}/chat_conversations/${CONVERSATION}/completion`),
    ).toBeUndefined();
  });

  it('reads nothing off a url it cannot parse', () => {
    expect(read('not a url')).toBeUndefined();
    expect(read('')).toBeUndefined();
  });
});
