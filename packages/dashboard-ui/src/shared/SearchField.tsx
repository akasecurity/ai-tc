'use client';
// The one search box both products render. Every search surface in the OSS
// dashboard and the enterprise dashboard goes through this, so the things a
// search box owes its user are decided once rather than once per call site:
//
//  - a CLEAR affordance, shown only while there is something to clear, on a
//    target big enough to hit;
//  - Escape as its keyboard equal, so clearing is not a Tab away;
//  - a focus indicator that survives the input suppressing its own outline;
//  - focus that stays put when the clear button removes itself.
//
// Props-driven and bundler-agnostic like the rest of this package — the host
// owns the query state (debounced, URL-backed or plain local) and this renders it.
import { cn } from '@akasecurity/ui-kit';
import { useRef } from 'react';

import { SearchIcon, XIcon } from './icons.tsx';

/**
 * What the field is sitting ON, which is the only thing that decides its fill:
 * a fill equal to the surface under it leaves the border drawing a rectangle
 * against its own colour. `card` covers Card, DialogContent and SheetContent
 * (all `bg-surface`); `canvas` is the page itself, where `--color-canvas` and
 * `--color-surface-2` are the same hex in light and a `bg-surface-2` field
 * would have no fill of its own.
 */
export type FieldSurface = 'card' | 'canvas';

/**
 * The edge and the fill, resolved from that one choice rather than retyped per
 * call site. `border-border-field` is the edge: `border-border` measures 1.26:1
 * light and 1.42:1 dark, under the 3:1 a control boundary is asked for.
 * theme/field-boundary.test.ts pins both halves here.
 */
const SURFACE_CLASS: Record<FieldSurface, string> = {
  card: 'rounded-lg border border-border-field bg-surface-2',
  canvas: 'rounded-lg border border-border-field bg-surface',
};

export function SearchField({
  value,
  onValueChange,
  label,
  placeholder,
  surface,
  className,
  iconClassName,
  clearLabel = 'Clear search',
}: {
  value: string;
  onValueChange: (next: string) => void;
  /**
   * The input's accessible name. Required rather than defaulted: a page with
   * two search boxes needs them told apart, and a default would name both.
   */
  label: string;
  placeholder: string;
  /** Which surface the field sits on — see `FieldSurface`. */
  surface: FieldSurface;
  /**
   * This field's own GEOMETRY, and only that — `h-9`, `w-64`, `flex-1`,
   * `shrink-0`, a margin. The edge and the fill come from `surface`, so a call
   * site cannot put one of them back on `border-border` by hand.
   */
  className?: string;
  /** Sizes the leading glyph where a denser control wants a smaller one. */
  iconClassName?: string;
  /**
   * Overridden where "search" is not what the box is called — the accessible
   * name of a control that appears and disappears should say what it clears.
   */
  clearLabel?: string;
}) {
  const inputRef = useRef<HTMLInputElement>(null);

  const clear = () => {
    onValueChange('');
    // Clearing unmounts the button, and a focused element that disappears drops
    // focus to <body> — which strands a keyboard user at the top of the
    // document. Hand it back to the input, which is where they were and where
    // they want to keep typing. Harmless when Escape got here: focus is already
    // on the input.
    inputRef.current?.focus();
  };

  return (
    // The focus ring sits HERE rather than on the input, so it wraps the whole
    // control — glyph, text and clear button — and so it is still drawn while
    // the input suppresses its own outline. An input that suppresses the native
    // outline and puts nothing back is a control whose focus is invisible.
    <div
      className={cn(
        'flex items-center gap-2 px-3 focus-within:border-primary focus-within:ring-2 focus-within:ring-primary/40',
        SURFACE_CLASS[surface],
        className,
      )}
    >
      <SearchIcon
        aria-hidden
        focusable={false}
        className={cn('size-4 shrink-0 text-text-3', iconClassName)}
      />
      <input
        ref={inputRef}
        type="text"
        value={value}
        onChange={(ev) => {
          onValueChange(ev.target.value);
        }}
        onKeyDown={(ev) => {
          // `type="search"` would give this natively, but it also injects a
          // second, browser-drawn clear button beside ours. So the type stays
          // `text` and the shortcut is supplied here — otherwise clearing costs
          // a keyboard user a Tab where a pointer user gets one click.
          if (ev.key === 'Escape' && value !== '') {
            // Nothing above this listens for Escape today; stopping it here
            // keeps a later Dialog or Sheet ancestor from also closing on the
            // keystroke that was meant for the field.
            ev.preventDefault();
            ev.stopPropagation();
            clear();
          }
        }}
        // A query is a proper noun about as often as it is a word; the red
        // underline under a rule id or a hostname is noise either way.
        spellCheck={false}
        placeholder={placeholder}
        aria-label={label}
        className="min-w-0 flex-1 bg-transparent text-sm text-text placeholder:text-text-3 focus:outline-hidden"
      />
      {value !== '' && (
        <button
          type="button"
          aria-label={clearLabel}
          onClick={clear}
          // `size-6` is the target, `size-3.5` the glyph inside it: WCAG 2.5.8
          // asks for 24x24 CSS px, and a button sized to its own icon is 14.
          // The field is h-8.5 at its densest, so 24 fits without growing it.
          className="grid size-6 shrink-0 cursor-pointer place-items-center rounded text-text-3 hover:text-text focus:outline-hidden focus-visible:ring-2 focus-visible:ring-primary/40"
        >
          <XIcon aria-hidden focusable={false} className="size-3.5" />
        </button>
      )}
    </div>
  );
}
