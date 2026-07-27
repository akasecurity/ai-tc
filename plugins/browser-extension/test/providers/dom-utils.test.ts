// @vitest-environment jsdom
import { describe, expect, it, vi } from 'vitest';

import {
  extractContentEditableText,
  firstMatch,
  setContentEditableText,
  watchButtonClick,
  watchEnterToSend,
} from '../../src/providers/dom-utils.ts';

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

describe('extractContentEditableText', () => {
  it('reads the element innerText', () => {
    const el = document.createElement('div');
    el.textContent = 'hello world';
    document.body.append(el);
    expect(extractContentEditableText(el)).toBe(el.innerText);
  });
});

describe('setContentEditableText', () => {
  it('overwrites the element content and fires an input event', () => {
    const el = document.createElement('div');
    document.body.append(el);
    const onInput = vi.fn();
    el.addEventListener('input', onInput);

    setContentEditableText(el, 'redacted value');

    expect(el.textContent).toBe('redacted value');
    expect(onInput).toHaveBeenCalledTimes(1);
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
