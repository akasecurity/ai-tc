// @vitest-environment jsdom
//
// The clear button is why this suite needs a DOM. Its properties are all about
// what happens AFTER a click — the callback, the re-render, and where focus
// lands once the button has removed itself — and a server render sees none of
// them. The environment is opted into per file, as this package's
// vitest.config.ts asks.
import { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { renderToStaticMarkup } from 'react-dom/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SearchField } from '../../src/shared/SearchField.tsx';

/**
 * A host that owns the query the way every real call site does — controlled,
 * with the field rendering what the parent last set. Clearing is only
 * observable through a re-render, so a test that passed a fixed `value` would
 * assert on markup the clear could never change.
 */
function Host({
  initial,
  onChange,
  clearLabel,
}: {
  initial: string;
  onChange?: (next: string) => void;
  clearLabel?: string;
}) {
  const [value, setValue] = useState(initial);
  return (
    <SearchField
      value={value}
      onValueChange={(next) => {
        setValue(next);
        onChange?.(next);
      }}
      label="Search assets"
      placeholder="Search assets…"
      surface="card"
      {...(clearLabel === undefined ? {} : { clearLabel })}
    />
  );
}

let container: HTMLDivElement;
let root: ReturnType<typeof createRoot>;

beforeEach(() => {
  (globalThis as unknown as { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.append(container);
  root = createRoot(container);
});

afterEach(() => {
  // Unmounted here rather than at the end of a body: a failing assertion would
  // skip an in-body teardown and leave a live root (and a focused element) in
  // the document for every case after it.
  act(() => {
    root.unmount();
  });
  container.remove();
});

const input = (): HTMLInputElement => {
  const el = container.querySelector('input');
  if (el === null) throw new Error('no input rendered');
  return el;
};
const clearButton = (): HTMLButtonElement | null => container.querySelector('button');

function mount(props: Parameters<typeof Host>[0]): void {
  act(() => {
    root.render(<Host {...props} />);
  });
}

describe('SearchField', () => {
  // The affordance half. Both directions are asserted: a control that is always
  // there is as wrong as one that never is, and only the empty case can show
  // that the button's presence is a function of the value at all.
  it('offers nothing to clear while the box is empty', () => {
    mount({ initial: '' });
    expect(clearButton()).toBeNull();
  });

  it('offers a clear button once there is a term', () => {
    mount({ initial: 'aws' });
    expect(clearButton()?.getAttribute('aria-label')).toBe('Clear search');
  });

  it('names the clear button after what it clears when the host says so', () => {
    mount({ initial: 'aws', clearLabel: 'Clear model search' });
    expect(clearButton()?.getAttribute('aria-label')).toBe('Clear model search');
  });

  it('reports the empty term and empties the box', () => {
    const onChange = vi.fn();
    mount({ initial: 'aws', onChange });

    act(() => {
      clearButton()?.click();
    });

    expect(onChange).toHaveBeenCalledWith('');
    expect(input().value).toBe('');
    // The button is gone with the term it cleared — the first case's property,
    // reached the other way round.
    expect(clearButton()).toBeNull();
  });

  // The property the button's own disappearance puts at risk. A focused element
  // that unmounts drops focus to <body>, which strands a keyboard user at the
  // top of the document with the search they were editing behind them.
  it('hands focus back to the input after clearing', () => {
    mount({ initial: 'aws' });

    const button = clearButton();
    act(() => {
      button?.focus();
    });
    // The positive control: without it, an implementation that never moves
    // focus would read the same as one that moves it correctly, because focus
    // would have been on the input the whole time.
    expect(document.activeElement).toBe(button);

    act(() => {
      button?.click();
    });

    expect(document.activeElement).toBe(input());
  });

  // Escape is the clear button's keyboard equal. Without it the pointer
  // affordance is one click and the keyboard one is a Tab away, which is the
  // gap `type="search"` would have closed natively had it not also drawn a
  // second clear button of the browser's own.
  it('clears on Escape', () => {
    const onChange = vi.fn();
    mount({ initial: 'aws', onChange });

    act(() => {
      input().dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    });

    expect(onChange).toHaveBeenCalledWith('');
    expect(input().value).toBe('');
  });

  // An empty box has nothing to clear, so Escape there belongs to whatever is
  // above — a Dialog or Sheet that closes on it. Swallowing it unconditionally
  // would trap the user inside a modal whose search box happens to have focus.
  it('leaves Escape alone while the box is empty', () => {
    const onChange = vi.fn();
    mount({ initial: '', onChange });

    const ev = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true });
    act(() => {
      input().dispatchEvent(ev);
    });

    expect(onChange).not.toHaveBeenCalled();
    expect(ev.defaultPrevented).toBe(false);
  });

  // WCAG 2.5.8 asks for 24x24 CSS px. jsdom does no layout, so the size is
  // asserted through the utility that sets it: a button sized to its own
  // `size-3.5` glyph is 14x14, which is what this exists to stop coming back.
  it('gives the clear button a target bigger than its glyph', () => {
    mount({ initial: 'aws' });
    expect(clearButton()?.className).toContain('size-6');
  });

  // The input's accessible name comes from `label`, never from the placeholder —
  // a placeholder is not an accessible name, and it is gone from the screen the
  // moment anything is typed.
  it('names the input from its label rather than its placeholder', () => {
    const html = renderToStaticMarkup(
      <SearchField
        value=""
        onValueChange={vi.fn()}
        label="Search finding types"
        placeholder="Search types…"
        surface="card"
      />,
    );
    expect(html).toContain('aria-label="Search finding types"');
    expect(html).toContain('placeholder="Search types…"');
  });
});
