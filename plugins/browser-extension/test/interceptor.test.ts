// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';

import type { BannerTone } from '../src/interceptor.ts';
import { createSubmitInterceptor } from '../src/interceptor.ts';
import type { BackgroundRequest, BackgroundResponse } from '../src/messaging.ts';
import type { ProviderAdapter } from '../src/providers/types.ts';

// A fake adapter whose submit() synchronously re-invokes handleSubmit — the
// exact re-entrancy a real programmatic send-button click produces (the
// watchSubmit capture listener sees our own click). The interceptor's bypass
// must absorb that second invocation or every approved send loops forever.
function harness(responses: Partial<BackgroundResponse>[]) {
  const composer = document.createElement('div');
  composer.textContent = 'the composer text';
  document.body.append(composer);

  const relayCalls: BackgroundRequest[] = [];
  const banners: { message: string; tone: BannerTone }[] = [];
  const setTextCalls: string[] = [];
  let submitCount = 0;
  let reentrantPrevented = 0;

  const adapter: ProviderAdapter = {
    id: 'chatgpt',
    matches: () => true,
    findComposer: () => composer,
    findSendButton: () => null,
    extractText: (el) => el.textContent,
    setText: (el, text) => {
      el.textContent = text;
      setTextCalls.push(text);
    },
    watchSubmit: () => () => undefined,
    submit: () => {
      submitCount += 1;
      // Mimic the capture-phase click listener firing on the programmatic
      // click: handleSubmit re-enters synchronously with a fresh event.
      const reentrant = new Event('click', { cancelable: true });
      interceptor.handleSubmit(reentrant, composer);
      if (reentrant.defaultPrevented) reentrantPrevented += 1;
    },
  };

  const queue = [...responses];
  const interceptor = createSubmitInterceptor({
    adapter,
    sessionId: 'test-session',
    relay: (request) => {
      relayCalls.push(request);
      const next = queue.shift();
      if (!next) return Promise.reject(new Error('relay exhausted'));
      return Promise.resolve(next as BackgroundResponse);
    },
    showBanner: (message, tone) => {
      banners.push({ message, tone });
    },
  });

  return {
    composer,
    interceptor,
    relayCalls,
    banners,
    setTextCalls,
    submitted: () => submitCount,
    reentrantPrevented: () => reentrantPrevented,
  };
}

function capture(over: Partial<Extract<BackgroundResponse, { type: 'capture' }>>) {
  return {
    type: 'capture' as const,
    requestId: 'r',
    ok: true as const,
    action: 'log' as const,
    ruleIds: [],
    ...over,
  };
}

async function settle(): Promise<void> {
  // Two microtask/macrotask hops: the decide() promise chain, then the
  // bypass-clearing setTimeout(0).
  await new Promise((resolve) => setTimeout(resolve, 5));
}

describe('createSubmitInterceptor', () => {
  it('a clean send relays exactly ONE capture and the re-entrant click passes through unprevented', async () => {
    const h = harness([capture({ action: 'log' })]);
    const event = new Event('keydown', { cancelable: true });
    h.interceptor.handleSubmit(event, h.composer);

    expect(event.defaultPrevented).toBe(true); // held until the decision
    await settle();

    expect(h.submitted()).toBe(1);
    expect(h.relayCalls).toHaveLength(1); // the loop bug re-relayed here
    expect(h.reentrantPrevented()).toBe(0); // bypass let the real send happen
  });

  it('block: nothing is submitted, no re-entry, banner shown', async () => {
    const h = harness([
      capture({ action: 'block', text: null, ruleIds: ['secrets/aws-access-key'] }),
    ]);
    const event = new Event('keydown', { cancelable: true });
    h.interceptor.handleSubmit(event, h.composer);
    await settle();

    expect(h.submitted()).toBe(0);
    expect(h.relayCalls).toHaveLength(1);
    expect(h.banners[0]?.tone).toBe('block');
    expect(h.banners[0]?.message).toContain('secrets/aws-access-key');
  });

  it('redact: composer rewritten to the masked text BEFORE the single pass-through send', async () => {
    const h = harness([
      capture({ action: 'redact', text: 'masked [REDACTED:SECRET]', ruleIds: ['r1'] }),
    ]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.setTextCalls).toEqual(['masked [REDACTED:SECRET]']);
    expect(h.composer.textContent).toBe('masked [REDACTED:SECRET]');
    expect(h.submitted()).toBe(1);
    expect(h.relayCalls).toHaveLength(1); // the masked text is NOT re-scanned as a second capture
    expect(h.banners[0]?.tone).toBe('redact');
  });

  it('fail-open: a relay error still lets the original message through, once', async () => {
    const h = harness([]); // relay rejects
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.submitted()).toBe(1);
    expect(h.banners).toHaveLength(0);
  });

  it('empty composer: no interception at all (no preventDefault, no relay)', () => {
    const h = harness([]);
    h.composer.textContent = '   ';
    const event = new Event('keydown', { cancelable: true });
    h.interceptor.handleSubmit(event, h.composer);

    expect(event.defaultPrevented).toBe(false);
    expect(h.relayCalls).toHaveLength(0);
  });

  it('a stale bypass cannot leak: the send AFTER an approved one is scanned again', async () => {
    const h = harness([capture({ action: 'log' }), capture({ action: 'log' })]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle(); // first send completes; bypass consumed (and timer cleared)

    const second = new Event('keydown', { cancelable: true });
    h.interceptor.handleSubmit(second, h.composer);
    expect(second.defaultPrevented).toBe(true); // intercepted again, not bypassed
    await settle();
    expect(h.relayCalls).toHaveLength(2);
  });
});
