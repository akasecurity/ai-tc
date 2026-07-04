// Theme tokens referenced as CSS variables (defined in @akasecurity/ui-kit/theme.css),
// so charts/SVG stay in sync with the single source of truth instead of
// duplicating hex values here.
export const COLORS = {
  primary: 'var(--color-primary)',
  ok: 'var(--color-ok)',
  violet: 'var(--color-violet)',
  teal: 'var(--color-teal)',
  sevCritical: 'var(--color-sev-critical)',
  sevHigh: 'var(--color-sev-high)',
  sevMedium: 'var(--color-sev-medium)',
  sevLow: 'var(--color-sev-low)',
  surface: 'var(--color-surface)',
  surface3: 'var(--color-surface-3)',
  border: 'var(--color-border)',
  text2: 'var(--color-text-2)',
  text3: 'var(--color-text-3)',
} as const;
