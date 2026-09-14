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
    | { get?: (this: HTMLTextAreaElement) => string; set?: (this: HTMLTextAreaElement, v: string) => void }
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
