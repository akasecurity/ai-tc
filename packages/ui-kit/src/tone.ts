// The tonal-pair vocabulary.
//
// Every tonal family in theme.css carries two foregrounds: `--color-X` is the HUE
// (chart series, status dots, bar segments) and `--color-X-ink` is TEXT on that
// family's tint. A tinted surface therefore pairs the family's `-fill` with its
// `-ink`, and a solid surface pairs its `-ink` with `--color-on-accent`.
//
// Nothing in the names says which half belongs where, and `primary` reads the
// inverse of every other family — it IS the ink, and pairs with `-tint` rather
// than `-fill`. So every site that spells a pair by hand is a site that can spell
// it wrong, and the failure is silent: an undefined theme variable generates no
// utility at all, so the element simply inherits its color. In dark the two halves
// are equal, which hides the mistake in one theme while it ships broken in the
// other.
//
// Spelling each pair once, here, buys two things a hand-written className cannot.
// Tailwind only emits classes it can see as complete literals, so a pair assembled
// as `bg-sev-${severity}-fill` generates no CSS. And the tonal-ink guard in
// @akasecurity/eslint-config needs the family name inside one static quasi to match
// — a dynamically assembled pair is its documented blind spot, which is exactly how
// a bare hue reached `text-*` undetected.

/** A tonal family that can tint a surface. */
export type Tone =
  'neutral' | 'critical' | 'high' | 'medium' | 'low' | 'ok' | 'teal' | 'violet' | 'primary';

/**
 * The families that also carry a SOLID fill. Only the alert tones do: a solid
 * fill is an escalation, and teal/violet/primary are categorical rather than
 * urgent. `primary` has its own solid pair (`--color-primary-solid` with
 * `--color-text-inv`) that is the button's, not a tile's, so it stays out.
 */
export type SolidTone = Extract<Tone, 'critical' | 'high' | 'medium' | 'low' | 'ok'>;

/** Tinted surface plus the ink that reads on it. */
export const TONE_SOFT: Record<Tone, string> = {
  neutral: 'bg-surface-2 text-text-2',
  critical: 'bg-sev-critical-fill text-sev-critical-ink',
  high: 'bg-sev-high-fill text-sev-high-ink',
  medium: 'bg-sev-medium-fill text-sev-medium-ink',
  low: 'bg-sev-low-fill text-sev-low-ink',
  ok: 'bg-ok-fill text-ok-ink',
  teal: 'bg-teal-fill text-teal-ink',
  violet: 'bg-violet-fill text-violet-ink',
  // The inverse of every line above: primary's bare token is the ink, and its
  // tint is spelled -tint rather than -fill.
  primary: 'bg-primary-tint text-primary',
};

/** Saturated fill carrying `--color-on-accent`. */
export const TONE_SOLID: Record<SolidTone, string> = {
  critical: 'bg-sev-critical-ink text-on-accent',
  high: 'bg-sev-high-ink text-on-accent',
  medium: 'bg-sev-medium-ink text-on-accent',
  low: 'bg-sev-low-ink text-on-accent',
  ok: 'bg-ok-ink text-on-accent',
};
