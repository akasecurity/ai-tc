// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';

import type { BannerRequest } from '../src/interceptor.ts';
import { createSubmitInterceptor } from '../src/interceptor.ts';
import type { BackgroundRequest, BackgroundResponse } from '../src/messaging.ts';
import type { ProviderAdapter } from '../src/providers/types.ts';

// A fake adapter whose submit() synchronously re-invokes handleSubmit — the
// exact re-entrancy a real programmatic send-button click produces (the
// watchSubmit capture listener sees our own click). The interceptor's bypass
// must absorb that second invocation or every approved send loops forever.
function harness(
  responses: Partial<BackgroundResponse>[],
  overrides: {
    // Lets a case model a composer whose framework reverts the redact write.
    setText?: (el: HTMLElement, text: string) => void;
    // Models send-button selector drift: submit() finds nothing to click and
    // reports the send did not happen.
    sendButtonMissing?: boolean;
    // Models a health-reporting fault: the network path's counter throws.
    noteSendThrows?: boolean;
  } = {},
) {
  const composer = document.createElement('div');
  composer.textContent = 'the composer text';
  document.body.append(composer);

  const relayCalls: BackgroundRequest[] = [];
  const banners: BannerRequest[] = [];
  const setTextCalls: string[] = [];
  let submitCount = 0;
  let reentrantPrevented = 0;
  // The signal the network path counts turns against. Recorded in the order it
  // arrives relative to submit(), because the pairing depends on it.
  const sendSignals: number[] = [];

  const adapter: ProviderAdapter = {
    id: 'chatgpt',
    hostnames: ['chatgpt.com'],
    findComposer: () => composer,
    findSendButton: () => null,
    extractText: (el) => el.textContent,
    setText: (el, text) => {
      setTextCalls.push(text);
      if (overrides.setText) {
        overrides.setText(el, text);
        return;
      }
      el.textContent = text;
    },
    // The network half, unused here: the interceptor is the DOM path, and it
    // reaches none of these. Declared so this adapter is a whole one — a
    // partial cast would let the interface grow a member nothing in this file
    // notices.
    endpoints: [],
    requiredPaths: { request: [], response: [] },
    protocolTokens: [],
    parseRequest: () => ({ requiredPathsSeen: false }),
    parseStream: () => ({ push: () => undefined, end: () => null }),
    watchSubmit: () => () => undefined,
    submit: () => {
      if (overrides.sendButtonMissing) return false;
      submitCount += 1;
      // Mimic the capture-phase click listener firing on the programmatic
      // click: handleSubmit re-enters synchronously with a fresh event.
      const reentrant = new Event('click', { cancelable: true });
      interceptor.handleSubmit(reentrant, composer);
      if (reentrant.defaultPrevented) reentrantPrevented += 1;
      return true;
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
    showBanner: (banner) => {
      banners.push(banner);
    },
    noteSend: () => {
      if (overrides.noteSendThrows) throw new Error('health reporting broke');
      sendSignals.push(submitCount);
    },
  });

  return {
    composer,
    interceptor,
    relayCalls,
    banners,
    setTextCalls,
    sendSignals,
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

  it('warn: banner names the flagged rules and the message still goes out exactly once', async () => {
    const h = harness([capture({ action: 'warn', ruleIds: ['core-pii/email'] })]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.banners[0]?.tone).toBe('warn');
    expect(h.banners[0]?.message).toContain('core-pii/email');
    expect(h.setTextCalls).toHaveLength(0);
    expect(h.submitted()).toBe(1);
    expect(h.relayCalls).toHaveLength(1);
  });

  it('redact with no text field: blocks rather than sending the original', async () => {
    // `text` is `string | null` on the wire, so this shape is protocol-legal.
    // It used to fall past both the redact and warn branches into passThrough,
    // sending the unredacted composer contents with NO banner at all — the
    // user reading that as "nothing was flagged". A redact the client cannot
    // carry out has to block.
    const h = harness([capture({ action: 'redact', ruleIds: ['r1'] })]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.setTextCalls).toHaveLength(0);
    expect(h.composer.textContent).toBe('the composer text');
    expect(h.submitted()).toBe(0);
    expect(h.banners[0]?.tone).toBe('block');
    expect(h.banners[0]?.message).toContain('could not redact');
  });

  it('redact that the composer silently reverts: blocks instead of claiming success', async () => {
    // setText is a best-effort DOM write against a framework-backed composer
    // (Claude.ai's is ProseMirror). If the framework reverts it, or the node
    // was stale, the old code still showed "AKA redacted …" and sent the
    // original — a false assurance about the one action the product performs.
    const h = harness([capture({ action: 'redact', text: 'masked', ruleIds: ['r1'] })], {
      setText: () => {
        /* the framework reverts the write: composer keeps its original text */
      },
    });
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.submitted()).toBe(0);
    expect(h.banners[0]?.tone).toBe('block');
    expect(h.banners[0]?.message).toContain('could not redact');
  });

  it('a second Enter while a decision is in flight neither re-relays nor double-sends', async () => {
    const h = harness([capture({ action: 'warn', ruleIds: ['r1'] })]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.relayCalls).toHaveLength(1);
    expect(h.submitted()).toBe(1);
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

  it('send-button drift: the message is not silently swallowed, and the next send is still scanned', async () => {
    // The interceptor has already preventDefault()ed the user's real send by
    // the time it calls submit(). If the send button selector has drifted,
    // the click never happens — so without this the message is simply gone,
    // with no banner, and the user reads the empty composer as "sent".
    const h = harness([capture({ action: 'log' }), capture({ action: 'log' })], {
      sendButtonMissing: true,
    });
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.submitted()).toBe(0);
    expect(h.composer.textContent).toBe('the composer text'); // text retained
    expect(h.banners).toHaveLength(1);
    expect(h.banners[0]?.tone).toBe('block');
    expect(h.banners[0]?.message).toContain('was NOT sent');

    // The bypass armed for a send that never happened must not be left over
    // to wave the user's NEXT real send through unscanned.
    const next = new Event('keydown', { cancelable: true });
    h.interceptor.handleSubmit(next, h.composer);
    expect(next.defaultPrevented).toBe(true);
    await settle();
    expect(h.relayCalls).toHaveLength(2);
  });

  it('send-button drift on a redact: never claims the redacted text was sent', async () => {
    // The redact banner says "before sending". Showing it when the send then
    // failed tells the user their masked message went out when nothing did.
    const h = harness([capture({ action: 'redact', text: 'masked', ruleIds: ['r1'] })], {
      sendButtonMissing: true,
    });
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.submitted()).toBe(0);
    const messages = h.banners.map((b) => b.message).join(' ');
    expect(messages).not.toContain('before sending');
    expect(messages).toContain('was NOT sent');
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

// The network path counts a DOM-observed send as a turn it must see a network
// exchange for, and reports the tab BLIND after a run of sends nothing
// answered. So the signal has to name a send that actually happened: charged
// at the relay instead, every message AKA itself stopped would count against a
// tap that is working correctly, and a session that blocked three secrets
// would report the interception as broken.
describe('the DOM-send signal the network path counts against', () => {
  it('fires once per message that actually went out, after the send', async () => {
    const h = harness([capture({ action: 'log' })]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();
    expect(h.submitted()).toBe(1);
    // The value recorded is submitCount at the moment of the signal: the send
    // is already on its way, so the request it started can answer it.
    expect(h.sendSignals).toEqual([1]);
  });

  it('does not fire for a message the decision blocked', async () => {
    // The case the counter got wrong. Nothing was sent, so no network turn can
    // answer it, and charging it to the tap reports enforcement as drift.
    const h = harness([capture({ action: 'block', ruleIds: ['aws-key'] })]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();
    expect(h.submitted()).toBe(0);
    expect(h.sendSignals).toEqual([]);
  });

  it('does not fire for a redact the composer would not take', async () => {
    const h = harness([capture({ action: 'redact', text: 'masked', ruleIds: ['r1'] })], {
      setText: () => undefined,
    });
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();
    expect(h.submitted()).toBe(0);
    expect(h.sendSignals).toEqual([]);
  });

  it('does not fire when the send button drifted away', async () => {
    // submit() reported the message did not go out. handleSubmit has already
    // preventDefault()ed the user's own send, so nothing sent it and nothing
    // will — a DOM-adapter fault, which must not be reported as a network one.
    const h = harness([capture({ action: 'log' })], { sendButtonMissing: true });
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();
    expect(h.sendSignals).toEqual([]);
  });

  it('fires for a send the host never answered, which still left the composer', async () => {
    // Fail-open: the message went out, so a network turn is owed for it.
    const h = harness([]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();
    expect(h.submitted()).toBe(1);
    expect(h.sendSignals).toEqual([1]);
  });

  it('never lets a reporting fault reach the message it is reporting on', async () => {
    const h = harness([capture({ action: 'log' })], { noteSendThrows: true });
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();
    expect(h.submitted()).toBe(1);
    // And the send is still treated as having happened.
    expect(h.banners).toEqual([]);
  });
});

describe('the block banner carries the exception route', () => {
  it('hands the ledger reference through as its own command', async () => {
    // The reference is the whole point: without it the user is told a message
    // was blocked and given no way to allow it. It rides as a separate field
    // rather than inside the prose so the banner can render it selectably.
    const h = harness([
      {
        type: 'capture',
        action: 'block',
        text: null,
        ruleIds: ['secrets/aws-access-key'],
        blockedReferences: [
          { reference: '3f2a91', ruleId: 'secrets/aws-access-key', maskedValue: 'A******E' },
        ],
      },
    ]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.submitted()).toBe(0);
    expect(h.banners[0]?.tone).toBe('block');
    expect(h.banners[0]?.exception?.command).toBe('aka exception approve 3f2a91');
    expect(h.banners[0]?.message).toContain('A******E');
  });

  it('omits the command when the host ledgered nothing', async () => {
    const h = harness([
      { type: 'capture', action: 'block', text: null, ruleIds: ['secrets/aws-access-key'] },
    ]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.banners[0]?.tone).toBe('block');
    expect(h.banners[0]?.exception?.command).toBe('aka exception approve');
  });

  it('points a WARN at the same flow, since a warned value is ledgered too', async () => {
    const h = harness([
      {
        type: 'capture',
        action: 'warn',
        ruleIds: ['secrets/aws-access-key'],
        blockedReferences: [
          { reference: '55aa', ruleId: 'secrets/aws-access-key', maskedValue: 'A******E' },
        ],
      },
    ]);
    h.interceptor.handleSubmit(new Event('keydown', { cancelable: true }), h.composer);
    await settle();

    expect(h.submitted()).toBe(1);
    expect(h.banners[0]?.message).toContain('aka exception approve 55aa');
  });
});
