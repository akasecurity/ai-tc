'use client';

import { cn } from '@akasecurity/ui-kit';
import { useState } from 'react';

/**
 * Which of a chart's series are currently plotted, and the toggle a legend
 * binds to. `visible` is what the chart is handed, so hiding a series removes
 * it from the paths, the hover markers AND the tooltip in one move, and the
 * y-scale rebuilds from what is left.
 */
export interface SeriesVisibility<S extends { key: string }> {
  /** The series still plotted, in the caller's order. */
  visible: S[];
  hidden: ReadonlySet<S['key']>;
  /**
   * Hide a plotted series, or re-show a hidden one. Hiding the LAST visible
   * series is refused — see `useSeriesVisibility`.
   */
  toggle: (key: S['key']) => void;
}

/**
 * Series-visibility state for a legend-driven chart. Every series starts
 * visible, which is also what a server render produces, so the markup
 * hydration reconciles against is the markup the first client render builds.
 *
 * Hiding the last visible series is refused. An empty chart is not a view of
 * anything — the grid renders over a y-scale with no data behind it, and the
 * hover tooltip degrades to a bare date with no rows — so the refusal keeps
 * every reachable state one that says something. The legend marks that series
 * `aria-disabled` rather than `disabled`, so it keeps its focus stop, and its
 * accessible name carries the reason so that keeping the stop is worth
 * something.
 */
export function useSeriesVisibility<S extends { key: string }>(
  series: readonly S[],
): SeriesVisibility<S> {
  const [hidden, setHidden] = useState<ReadonlySet<S['key']>>(() => new Set<S['key']>());

  function toggle(key: S['key']): void {
    setHidden((prev) => {
      if (prev.has(key)) {
        const next = new Set(prev);
        next.delete(key);
        return next;
      }
      // Refusing by returning `prev` unchanged is also what keeps the click
      // from costing a re-render.
      const stillPlotted = series.some((s) => s.key !== key && !prev.has(s.key));
      if (!stillPlotted) return prev;
      const next = new Set(prev);
      next.add(key);
      return next;
    });
  }

  return { visible: series.filter((s) => !hidden.has(s.key)), hidden, toggle };
}

/**
 * A series' trailing value, with an empty string normalized to "nothing to
 * report" exactly as `null` is — otherwise an entry renders an empty styled
 * span and its accessible name picks up a trailing separator.
 */
function metaText(value: string | null | undefined): string | null {
  return value === undefined || value === '' ? null : value;
}

/** One series' colour chip. Hollow means the series is hidden from the chart. */
function Swatch({ color, hollow }: { color: string; hollow: boolean }) {
  return (
    <span
      className="size-2 rounded-xs"
      // Hollow rather than merely dimmer: the ring keeps the series' own colour
      // identifiable, which a faded fill does not.
      style={
        hollow
          ? { background: 'transparent', boxShadow: `inset 0 0 0 1.5px ${color}` }
          : { background: color }
      }
    />
  );
}

/** One series' trailing value, styled the same in both legend renderings. */
function MetaText({ text }: { text: string | null }) {
  if (text === null) return null;
  return <span className="text-text-3">{text}</span>;
}

/**
 * A chart's series legend, where each entry toggles its series in the chart.
 *
 * Sized and spaced to sit in a `CardAction`; the negative margin against the
 * padding keeps the hover target wider than the text without moving the text,
 * so the interaction costs the header no layout.
 */
export function SeriesLegend<S extends { key: string; label: string; color: string }>({
  series,
  visibility,
  metaLabel,
  interactive,
}: {
  series: readonly S[];
  visibility: SeriesVisibility<S>;
  /**
   * Optional trailing value per series (the MTTR card's latest bucket), as
   * TEXT rather than a node. The legend styles it and folds it into each
   * entry's accessible name: a button's name is computed from its contents,
   * and the flex `gap` that separates the two visually is not a character, so
   * a node handed in whole would be announced run together — "Low1d 1h".
   * Return `null` for a series with nothing to report.
   */
  metaLabel?: (key: S['key']) => string | null;
  /**
   * Whether a chart is on screen to toggle. A card's header renders ABOVE its
   * loading, error and empty states, so the legend outlives the chart — and a
   * control that visibly does nothing is worse than no control. Pass the same
   * condition the chart renders under; the entries render as plain, static
   * swatches when it is false.
   *
   * REQUIRED rather than defaulted: a default reads as safe at every call site
   * that omits it, which is every call site until somebody remembers, and the
   * value it would have to default to is the permissive one.
   */
  interactive: boolean;
}) {
  const { hidden, visible, toggle } = visibility;
  if (!interactive) {
    return (
      <>
        {series.map((s) => (
          // Every series drawn as visible: with no chart on screen, a hollow
          // swatch would describe a filter nothing is applying.
          <span key={s.key} className="inline-flex items-center gap-1.5">
            <Swatch color={s.color} hollow={false} />
            {s.label}
            <MetaText text={metaText(metaLabel?.(s.key))} />
          </span>
        ))}
      </>
    );
  }
  return (
    <>
      {series.map((s) => {
        const isHidden = hidden.has(s.key);
        const isLast = !isHidden && visible.length === 1;
        const meta = metaText(metaLabel?.(s.key));
        const entryName = meta === null ? s.label : `${s.label}, ${meta}`;
        return (
          <button
            key={s.key}
            type="button"
            // Spelled out rather than left to the contents: a button's name is
            // computed from its own text, and the flex `gap` separating the
            // label from its value is not a character, so the two would be
            // announced run together. The name still contains the visible text.
            //
            // P2: the locked reason rides the NAME rather than `title`. Once
            // `aria-label` is set, `title` is demoted to the accessible
            // DESCRIPTION, which is announced inconsistently and never at all
            // without a pointer — so the entry that cannot be actioned would
            // say why to nobody using a keyboard.
            aria-label={isLast ? `${entryName}, only series left` : entryName}
            aria-pressed={!isHidden}
            aria-disabled={isLast || undefined}
            title={
              isLast
                ? `${s.label} is the only series left — show another before hiding it`
                : isHidden
                  ? `Show ${s.label}`
                  : `Hide ${s.label}`
            }
            onClick={() => {
              toggle(s.key);
            }}
            className={cn(
              // Tailwind's preflight carries no button cursor rule, so a bare
              // <button> falls through to the UA's arrow. `cn` resolves the
              // conflict last-wins, so the locked entry's override below holds.
              '-mx-1 inline-flex cursor-pointer items-center gap-1.5 rounded-sm px-1 transition-colors',
              'hover:bg-surface-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-primary/40',
              // P1: de-emphasis by TOKEN, never by alpha. A hidden entry is
              // still the operable control that brings its series back, so
              // WCAG 1.4.3's carve-out for an INACTIVE component does not
              // reach it and its text owes 4.5:1. `opacity` composites the
              // text against the card and collapses that — measured 2.33:1
              // (light label), 2.17:1 (light value), 3.99:1 (dark label) and
              // 2.82:1 (dark value) at 0.55. No alpha survives: even 0.95
              // lands at 4.49:1, because the value sits at 4.97:1 unfaded.
              // `text-text-3` measures 4.97:1 light / 5.77:1 dark, and the
              // hollow swatch carries the rest of the signal.
              isHidden && 'text-text-3',
              // The only series left cannot be hidden, so it offers neither the
              // pointer nor the hover highlight that say a click does something.
              isLast && 'cursor-default hover:bg-transparent',
            )}
          >
            <Swatch color={s.color} hollow={isHidden} />
            {s.label}
            <MetaText text={meta} />
          </button>
        );
      })}
    </>
  );
}
