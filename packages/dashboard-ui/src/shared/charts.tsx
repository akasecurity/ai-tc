'use client';

import { arc, area, curveMonotoneX, line, pie, type PieArcDatum } from 'd3-shape';
import { type ReactNode, useEffect, useId, useRef, useState } from 'react';

import { COLORS } from '../lib/colors.ts';

export interface DonutSegment {
  label: string;
  value: number;
  color: string;
}

/**
 * A donut chart with a centered overlay. Hand-rolled SVG (d3-shape generates the
 * arc paths) so it stays in sync with the CSS-variable design tokens and adds no
 * heavyweight charting runtime.
 */
export function Donut({
  segments,
  size = 120,
  thickness = 16,
  children,
}: {
  segments: DonutSegment[];
  size?: number;
  thickness?: number;
  children?: ReactNode;
}) {
  const outerRadius = size / 2;
  const innerRadius = outerRadius - thickness;
  // d3's default pie angles run clockwise from 12 o'clock, matching the previous
  // recharts config (startAngle 90 → endAngle -270). `.sort(null)` preserves the
  // caller's segment order instead of sorting by value.
  const arcs = pie<DonutSegment>()
    .value((d) => d.value)
    .sort(null)(segments);
  const arcGen = arc<PieArcDatum<DonutSegment>>().innerRadius(innerRadius).outerRadius(outerRadius);

  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      {/* Decorative: the slices are unlabeled SVG; callers surface the data in
          a legend. The centered `children` overlay stays accessible. */}
      <div aria-hidden>
        <svg width={size} height={size}>
          <g transform={`translate(${String(outerRadius)},${String(outerRadius)})`}>
            {arcs.map((a) => (
              <path
                key={a.data.label}
                d={arcGen(a) ?? undefined}
                fill={a.data.color}
                stroke="none"
              />
            ))}
          </g>
        </svg>
      </div>
      {children && (
        <div className="absolute inset-0 grid place-items-center text-center">{children}</div>
      )}
    </div>
  );
}

/**
 * A compact single-series sparkline. Renders on a fixed viewBox and stretches to
 * the parent via `preserveAspectRatio="none"` — no ResizeObserver needed — so it
 * drops into a stat tile or a narrow table cell. `vectorEffect` keeps the stroke
 * an even width despite the non-uniform scale.
 *
 * Decorative by default. Pass `labels` (one per point, index-aligned to `data`)
 * to make it hoverable: the nearest point gets a marker dot and a tooltip with
 * its label + value. The dot and tooltip are absolutely-positioned HTML (a circle
 * inside the stretched SVG would render as an ellipse); x positions are
 * percentages of the same viewBox fractions the path uses, so they track the
 * non-uniform scale.
 */
export function Sparkline({
  data,
  color,
  height = 34,
  fill = true,
  strokeWidth = 2,
  labels,
  formatValue,
}: {
  data: number[];
  color: string;
  height?: number;
  fill?: boolean;
  strokeWidth?: number;
  /** Per-point hover labels (same length as `data`); omit for a decorative line. */
  labels?: string[];
  /** Tooltip value formatter (defaults to String). */
  formatValue?: (v: number) => string;
}) {
  const gradientId = `spark-${useId().replace(/:/g, '')}`;
  const [hover, setHover] = useState<number | null>(null);
  const viewW = 100;
  const pad = 2;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const xAt = (i: number) =>
    data.length <= 1 ? viewW / 2 : pad + (i / (data.length - 1)) * (viewW - pad * 2);
  const yAt = (v: number) => height - pad - ((v - min) / range) * (height - pad * 2);
  const points = data.map((v, i): [number, number] => [xAt(i), yAt(v)]);

  const linePath =
    line()
      .x((d) => d[0])
      .y((d) => d[1])
      .curve(curveMonotoneX)(points) ?? undefined;
  const areaPath =
    area()
      .x((d) => d[0])
      .y0(height)
      .y1((d) => d[1])
      .curve(curveMonotoneX)(points) ?? undefined;

  const svg = (
    // Decorative: the trend is a supporting glyph beside a labeled value; the
    // hover tooltip (when enabled) is a pointer affordance on top of that.
    <svg
      aria-hidden
      width="100%"
      height={height}
      viewBox={`0 0 ${String(viewW)} ${String(height)}`}
      preserveAspectRatio="none"
      className="block"
    >
      {fill && (
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.18} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
      )}
      {fill && <path d={areaPath} fill={`url(#${gradientId})`} stroke="none" />}
      <path
        d={linePath}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );

  // Defensive: hover only when every point has a label — a mis-aligned labels
  // array degrades to the decorative line rather than mislabeling points.
  const interactive = labels?.length === data.length && data.length > 0;
  if (!interactive) return svg;

  const hoverValue = hover === null ? undefined : data[hover];
  const hoverLabel = hover === null ? undefined : labels[hover];

  return (
    <div
      aria-hidden
      className="relative"
      onMouseMove={(e) => {
        const rect = e.currentTarget.getBoundingClientRect();
        if (rect.width === 0) return;
        const viewX = ((e.clientX - rect.left) / rect.width) * viewW;
        const i =
          data.length <= 1
            ? 0
            : Math.round(((viewX - pad) / (viewW - pad * 2)) * (data.length - 1));
        setHover(Math.min(data.length - 1, Math.max(0, i)));
      }}
      onMouseLeave={() => {
        setHover(null);
      }}
    >
      {svg}
      {hover !== null && hoverValue !== undefined && hoverLabel !== undefined && (
        <>
          <span
            className="pointer-events-none absolute size-2 -translate-x-1/2 -translate-y-1/2 rounded-full border border-white/80"
            style={{
              left: `${String((xAt(hover) / viewW) * 100)}%`,
              top: yAt(hoverValue),
              background: color,
            }}
          />
          <div
            className="pointer-events-none absolute z-10 -translate-x-1/2 whitespace-nowrap"
            style={{
              left: `clamp(36px, ${String((xAt(hover) / viewW) * 100)}%, calc(100% - 36px))`,
              bottom: height + 6,
              borderRadius: 8,
              border: `1px solid ${COLORS.border}`,
              background: COLORS.surface,
              padding: '4px 8px',
              fontSize: 12,
              boxShadow: '0 4px 12px rgb(0 0 0 / 0.08)',
            }}
          >
            <div style={{ color: COLORS.text3, fontSize: 11 }}>{hoverLabel}</div>
            <div className="font-semibold" style={{ color: COLORS.text2 }}>
              {(formatValue ?? String)(hoverValue)}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export interface AreaSeries {
  /** Stable key for the series (used for the dataKey + gradient id). */
  key: string;
  color: string;
}

const MARGIN = { top: 6, right: 6, bottom: 0, left: 6 } as const;

/** Tracks the rendered width of an element via ResizeObserver. */
export function useMeasuredWidth() {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) setWidth(entry.contentRect.width);
    });
    ro.observe(el);
    return () => {
      ro.disconnect();
    };
  }, []);
  return [ref, width] as const;
}

/**
 * Multi-series smooth area chart. `data` is an array of points where each point
 * holds a value per series key (e.g. `{ label, findings, redactions, blocks }`).
 *
 * A per-key value may be `null` to mean "no data at this point" — those render
 * as GAPS in the line/area (via d3's `.defined()`), not as a misleading zero,
 * and are skipped in the hover tooltip. Count charts that never pass null are
 * unaffected. `valueFormat` humanizes the tooltip value (default `String(v)`),
 * so e.g. an MTTR chart can render `"2d 4h"` instead of raw milliseconds.
 *
 * Hand-rolled SVG: d3-shape generates the area/line paths and a ResizeObserver
 * supplies the responsive width — no charting runtime needed.
 */
export function AreaChart<K extends string>({
  data,
  series,
  height = 160,
  valueFormat = (v: number) => String(v),
}: {
  data: (Record<K, number | null> & { label: string })[];
  series: (AreaSeries & { key: K })[];
  height?: number;
  valueFormat?: (v: number, key: K) => string;
}) {
  type Point = Record<K, number | null> & { label: string };
  const gradientPrefix = useId().replace(/:/g, '');
  const [ref, width] = useMeasuredWidth();
  const [hover, setHover] = useState<number | null>(null);

  const innerW = Math.max(0, width - MARGIN.left - MARGIN.right);
  const innerH = Math.max(0, height - MARGIN.top - MARGIN.bottom);
  const definedValues: number[] = [];
  for (const d of data) {
    for (const s of series) {
      const v = d[s.key];
      if (typeof v === 'number') definedValues.push(v);
    }
  }
  const maxValue = Math.max(1, ...definedValues);

  const xAt = (i: number) => (data.length <= 1 ? 0 : (i / (data.length - 1)) * innerW);
  const yAt = (v: number) => innerH - (v / maxValue) * innerH;

  const gridLines = [0, 0.25, 0.5, 0.75, 1];

  function handleMove(e: React.MouseEvent) {
    if (!ref.current || data.length === 0) return;
    const rect = ref.current.getBoundingClientRect();
    const px = e.clientX - rect.left - MARGIN.left;
    const step = data.length <= 1 ? 0 : innerW / (data.length - 1);
    const i = step === 0 ? 0 : Math.round(px / step);
    setHover(Math.min(data.length - 1, Math.max(0, i)));
  }

  const hoverPoint = hover === null ? null : data[hover];

  return (
    // Decorative: the chart is unlabeled SVG; the series legend conveys the keys.
    <div ref={ref} aria-hidden className="relative" style={{ height }}>
      {width > 0 && (
        <svg
          width={width}
          height={height}
          onMouseMove={handleMove}
          onMouseLeave={() => {
            setHover(null);
          }}
        >
          <defs>
            {series.map((s) => (
              <linearGradient
                key={s.key}
                id={`${gradientPrefix}-${s.key}`}
                x1="0"
                y1="0"
                x2="0"
                y2="1"
              >
                <stop offset="0%" stopColor={s.color} stopOpacity={0.16} />
                <stop offset="100%" stopColor={s.color} stopOpacity={0} />
              </linearGradient>
            ))}
          </defs>
          <g transform={`translate(${String(MARGIN.left)},${String(MARGIN.top)})`}>
            {gridLines.map((t) => (
              <line
                key={t}
                x1={0}
                x2={innerW}
                y1={innerH * t}
                y2={innerH * t}
                stroke={COLORS.border}
                strokeOpacity={0.6}
              />
            ))}
            {series.map((s) => {
              // `.defined()` breaks the path at null points so a no-data bucket
              // renders as a gap, not a dip to zero. The y accessor still runs
              // for undefined points (result ignored), so it must not throw —
              // `?? 0` keeps it finite.
              const areaPath =
                area<Point>()
                  .defined((d) => d[s.key] !== null)
                  .x((_d, i) => xAt(i))
                  .y0(yAt(0))
                  .y1((d) => yAt(d[s.key] ?? 0))
                  .curve(curveMonotoneX)(data) ?? undefined;
              const linePath =
                line<Point>()
                  .defined((d) => d[s.key] !== null)
                  .x((_d, i) => xAt(i))
                  .y((d) => yAt(d[s.key] ?? 0))
                  .curve(curveMonotoneX)(data) ?? undefined;
              return (
                <g key={s.key}>
                  <path d={areaPath} fill={`url(#${gradientPrefix}-${s.key})`} stroke="none" />
                  <path d={linePath} fill="none" stroke={s.color} strokeWidth={2} />
                </g>
              );
            })}
            {hoverPoint && hover !== null && (
              <g>
                <line x1={xAt(hover)} x2={xAt(hover)} y1={0} y2={innerH} stroke={COLORS.border} />
                {series.map((s) => {
                  const v = hoverPoint[s.key];
                  // No marker for a no-data point — nothing sits on the line there.
                  if (v === null) return null;
                  return <circle key={s.key} cx={xAt(hover)} cy={yAt(v)} r={3} fill={s.color} />;
                })}
              </g>
            )}
          </g>
        </svg>
      )}
      {hoverPoint && hover !== null && (
        <div
          className="pointer-events-none absolute top-0 -translate-x-1/2"
          style={{
            left: Math.min(width - 60, Math.max(60, MARGIN.left + xAt(hover))),
            borderRadius: 8,
            border: `1px solid ${COLORS.border}`,
            background: COLORS.surface,
            padding: '6px 8px',
            fontSize: 12,
            boxShadow: '0 4px 12px rgb(0 0 0 / 0.08)',
          }}
        >
          <div style={{ color: COLORS.text3, fontSize: 11, marginBottom: 4 }}>
            {hoverPoint.label}
          </div>
          {series.map((s) => {
            const v = hoverPoint[s.key];
            // Skip a no-data series entirely rather than showing a bogus "0".
            if (v === null) return null;
            return (
              <div
                key={s.key}
                className="flex items-center gap-1.5"
                style={{ color: COLORS.text2 }}
              >
                <span
                  className="size-2 rounded-xs"
                  style={{ background: s.color, display: 'inline-block' }}
                />
                <span className="font-semibold">{valueFormat(v, s.key)}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
