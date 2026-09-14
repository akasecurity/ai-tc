// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest';

import {
  extractComposerText,
  firstMatch,
  setComposerText,
  watchButtonClick,
  watchEnterToSend,
} from '../../src/providers/dom-utils.ts';

// A framework value tracker, modelled on React's. React redefines `value` as an
// own accessor on the element and caches what it last saw written; on the next
// event it compares the cached value against the live one and suppresses
// `onChange` when they agree. So a plain `el.value = x` updates the cache and
// the framework concludes nothing changed. Writing through the PROTOTYPE's
// native setter bypasses the instance accessor, leaves the cache stale, and is
// what makes the framework notice.
function installValueTracker(el: HTMLTextAreaElement): { cached: () => string } {
  const native = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value') as
    | {
        get?: (this: HTMLTextAreaElement) => string;
        set?: (this: HTMLTextAreaElement, v: string) => void;
      }
    | undefined;
  const get = native?.get;
  const set = native?.set;
  if (!get || !set) throw new Error('no native value descriptor');
  let cached = get.call(el);
  Object.defineProperty(el, 'value', {
    configurable: true,
    get(this: HTMLTextAreaElement): string {
      return get.call(this);
    },
    set(this: HTMLTextAreaElement, next: string) {
      cached = next;
      set.call(this, next);
    },
  });
  return { cached: () => cached };
}

describe('firstMatch', () => {
  it('returns the first selector (in list order) that matches an element', () => {
    document.body.innerHTML = '<div id="b">B</div>';
    expect(firstMatch(['#a', '#b', '#c'])?.id).toBe('b');
  });

  it('returns null when none of the selectors match', () => {
    document.body.innerHTML = '<div id="z"></div>';
    expect(firstMatch(['#a', '#b'])).toBeNull();
  });
});

describe('extractComposerText', () => {
  // jsdom does not implement innerText — it reads `undefined` on every element.
  // A case asserting `extractComposerText(el) === el.innerText` therefore
  // compares undefined against undefined and holds however the function is
  // written, so the contenteditable branch is given an innerText to read.
  it('reads a contenteditable composer through innerText', () => {
    const el = document.createElement('div');
    document.body.append(el);
    el.textContent = 'what the DOM holds';
    Object.defineProperty(el, 'innerText', { value: 'what the user sees', configurable: true });

    expect(extractComposerText(el)).toBe('what the user sees');
  });

  it('reads a textarea composer through value, not the DOM tree', () => {
    // A textarea the user typed into holds nothing in its child nodes, so both
    // textContent and (in a real browser) innerText read empty. Reading either
    // returns '', which the interceptor treats as an empty composer and passes
    // through unscanned — a send that never reaches detection and raises no
    // banner.
    const el = document.createElement('textarea');
    document.body.append(el);
    el.value = 'AKIAIOSFODNN7EXAMPLE';

    expect(el.textContent).toBe('');
    expect(extractComposerText(el)).toBe('AKIAIOSFODNN7EXAMPLE');
  });

  it('reads an input composer through value', () => {
    const el = document.createElement('input');
    el.type = 'text';
    document.body.append(el);
    el.value = 'typed prompt';

    expect(extractComposerText(el)).toBe('typed prompt');
  });
});

describe('setComposerText', () => {
  it('overwrites a contenteditable composer and fires an input event', () => {
    const el = document.createElement('div');
    document.body.append(el);
    const onInput = vi.fn();
    el.addEventListener('input', onInput);

    setComposerText(el, 'redacted value');

    expect(el.textContent).toBe('redacted value');
    expect(onInput).toHaveBeenCalledTimes(1);
  });

  it('overwrites a textarea composer through value and fires an input event', () => {
    // Writing textContent on a textarea sets its default content and leaves
    // `value` untouched, so the original text is what gets sent.
    const el = document.createElement('textarea');
    document.body.append(el);
    el.value = 'AKIAIOSFODNN7EXAMPLE';
    const onInput = vi.fn();
    el.addEventListener('input', onInput);

    setComposerText(el, 'redacted value');

    expect(el.value).toBe('redacted value');
    expect(onInput).toHaveBeenCalledTimes(1);
  });

  it('writes a textarea through the native setter so a value tracker goes stale', () => {
    const el = document.createElement('textarea');
    document.body.append(el);
    el.value = 'AKIAIOSFODNN7EXAMPLE';
    const tracker = installValueTracker(el);

    setComposerText(el, 'redacted value');

    // The write landed...
    expect(el.value).toBe('redacted value');
    // ...and the tracker did NOT observe it, which is what makes a framework
    // treat the next input event as a real change rather than a no-op. A plain
    // `el.value = text` would leave these two equal, the framework would keep
    // its own model of the original, and the redact would be reverted or sent
    // around.
    expect(tracker.cached()).toBe('AKIAIOSFODNN7EXAMPLE');
  });
});

describe('watchEnterToSend', () => {
  it('fires onSubmit for Enter without Shift', () => {
    const el = document.createElement('div');
    document.body.append(el);
    const onSubmit = vi.fn();
    watchEnterToSend(el, onSubmit);

    el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });

  it('does not fire for Shift+Enter (newline)', () => {
    const el = document.createElement('div');
    document.body.append(el);
    const onSubmit = vi.fn();
    watchEnterToSend(el, onSubmit);

    el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', shiftKey: true, bubbles: true }));
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('does not fire while an IME composition is in progress', () => {
    const el = document.createElement('div');
    document.body.append(el);
    const onSubmit = vi.fn();
    watchEnterToSend(el, onSubmit);

    el.dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Enter', isComposing: true, bubbles: true }),
    );
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('stops firing once the returned cleanup function has run', () => {
    const el = document.createElement('div');
    document.body.append(el);
    const onSubmit = vi.fn();
    const unwatch = watchEnterToSend(el, onSubmit);
    unwatch();

    el.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).not.toHaveBeenCalled();
  });
});

describe('watchButtonClick', () => {
  it('fires onSubmit on click, and stops after the cleanup function runs', () => {
    const button = document.createElement('button');
    document.body.append(button);
    const onSubmit = vi.fn();
    const unwatch = watchButtonClick(button, onSubmit);

    button.click();
    expect(onSubmit).toHaveBeenCalledTimes(1);

    unwatch();
    button.click();
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });
});

describe('watchEnterToSend: winning the Enter race', () => {
  it('runs before an ANCESTOR capture listener, which is how the site sends', () => {
    // The live claude.ai failure. A listener on the composer runs in the
    // target phase; the capture descent reaches every ancestor first, so a
    // site handling Enter with a capture-phase listener above the composer
    // (React's onKeyDownCapture at its root container) has already sent the
    // message by the time a target-phase listener is called. Sending with the
    // BUTTON blocked correctly and Enter did not — that is this, exactly.
    const root = document.createElement('div');
    const composer = document.createElement('div');
    root.append(composer);
    document.body.append(root);

    const order: string[] = [];
    root.addEventListener(
      'keydown',
      () => {
        order.push('site-ancestor-capture');
      },
      true,
    );
    const unwatch = watchEnterToSend(composer, () => {
      order.push('aka');
    });

    composer.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    unwatch();

    expect(order[0]).toBe('aka');
  });

  it('ignores Enter pressed outside the composer it was given', () => {
    // The listener now sits on the document, so it sees every keystroke on the
    // page. Anything outside this composer — a search box, another editor —
    // must not be read as a send.
    const composer = document.createElement('div');
    const elsewhere = document.createElement('input');
    document.body.append(composer, elsewhere);
    const onSubmit = vi.fn();
    const unwatch = watchEnterToSend(composer, onSubmit);

    elsewhere.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).not.toHaveBeenCalled();

    composer.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    unwatch();
  });

  it('fires for a keystroke on a node INSIDE the composer', () => {
    // A contenteditable's event target can be a descendant element rather than
    // the composer itself.
    const composer = document.createElement('div');
    const inner = document.createElement('p');
    composer.append(inner);
    document.body.append(composer);
    const onSubmit = vi.fn();
    const unwatch = watchEnterToSend(composer, onSubmit);

    inner.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    unwatch();
  });
});

describe('watchEnterToSend: Enter that is not a send', () => {
  // A document-capture listener runs before EVERY listener on or below the
  // composer, including the site's own handling of Enter as "accept the
  // highlighted item". Intercepting that one routes half-typed text through
  // the decision path and, on pass-through, sends it — a message the user
  // never asked to send. The composer's own ARIA is what says a popup is open.
  function composerWithPopup(attrs: Record<string, string>): HTMLElement {
    const el = document.createElement('div');
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    document.body.append(el);
    return el;
  }

  it('ignores Enter while the composer reports an expanded popup', () => {
    const composer = composerWithPopup({ 'aria-expanded': 'true' });
    const onSubmit = vi.fn();
    const unwatch = watchEnterToSend(composer, onSubmit);
    composer.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).not.toHaveBeenCalled();
    unwatch();
  });

  it('ignores Enter while an active descendant is highlighted', () => {
    const composer = composerWithPopup({ 'aria-activedescendant': 'opt-3' });
    const onSubmit = vi.fn();
    const unwatch = watchEnterToSend(composer, onSubmit);
    composer.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).not.toHaveBeenCalled();
    unwatch();
  });

  it('still sends when the popup is closed again', () => {
    // aria-expanded="false" is the CLOSED state and must not suppress a send —
    // the attribute being present is not the signal, its value is.
    const composer = composerWithPopup({ 'aria-expanded': 'false' });
    const onSubmit = vi.fn();
    const unwatch = watchEnterToSend(composer, onSubmit);
    composer.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    unwatch();
  });

  it('ignores Enter while a listbox the composer controls is present', () => {
    const listbox = document.createElement('div');
    listbox.id = 'lb-1';
    listbox.setAttribute('role', 'listbox');
    document.body.append(listbox);
    const composer = composerWithPopup({ 'aria-controls': 'lb-1' });
    const onSubmit = vi.fn();
    const unwatch = watchEnterToSend(composer, onSubmit);
    composer.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).not.toHaveBeenCalled();
    unwatch();
  });

  it('sends when aria-controls names something that is not a listbox', () => {
    const panel = document.createElement('div');
    panel.id = 'p-1';
    document.body.append(panel);
    const composer = composerWithPopup({ 'aria-controls': 'p-1' });
    const onSubmit = vi.fn();
    const unwatch = watchEnterToSend(composer, onSubmit);
    composer.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
    unwatch();
  });
});
