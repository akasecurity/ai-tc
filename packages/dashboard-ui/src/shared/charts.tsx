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
 * Hand-rolled SVG: d3-shape generates the area/line paths and a ResizeObserver
 * supplies the responsive width — no charting runtime needed.
 */
export function AreaChart<K extends string>({
  data,
  series,
  height = 160,
}: {
  data: (Record<K, number> & { label: string })[];
  series: (AreaSeries & { key: K })[];
  height?: number;
}) {
  type Point = Record<K, number> & { label: string };
  const gradientPrefix = useId().replace(/:/g, '');
  const [ref, width] = useMeasuredWidth();
  const [hover, setHover] = useState<number | null>(null);

  const innerW = Math.max(0, width - MARGIN.left - MARGIN.right);
  const innerH = Math.max(0, height - MARGIN.top - MARGIN.bottom);
  const maxValue = Math.max(1, ...data.flatMap((d) => series.map((s) => d[s.key])));

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
              const areaPath =
                area<Point>()
                  .x((_d, i) => xAt(i))
                  .y0(yAt(0))
                  .y1((d) => yAt(d[s.key]))
                  .curve(curveMonotoneX)(data) ?? undefined;
              const linePath =
                line<Point>()
                  .x((_d, i) => xAt(i))
                  .y((d) => yAt(d[s.key]))
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
                {series.map((s) => (
                  <circle
                    key={s.key}
                    cx={xAt(hover)}
                    cy={yAt(hoverPoint[s.key])}
                    r={3}
                    fill={s.color}
                  />
                ))}
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
          {series.map((s) => (
            <div key={s.key} className="flex items-center gap-1.5" style={{ color: COLORS.text2 }}>
              <span
                className="size-2 rounded-xs"
                style={{ background: s.color, display: 'inline-block' }}
              />
              <span className="font-semibold">{hoverPoint[s.key]}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
