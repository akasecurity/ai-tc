// The tonal-pair vocabulary.
//
// Every tonal family in theme.css carries two foregrounds: `--color-X` is the HUE
// (chart series, status dots, bar segments) and `--color-X-ink` is TEXT on that
// family's tint. A tinted surface therefore pairs the family's `-fill` with its
// `-ink`, and a solid surface pairs its `-ink` with `--color-on-accent`.
//
// The ink is calibrated to clear 4.5:1 over `--color-surface`, and that bound is
// NOT unconditional: in dark the fills are 12% alpha, so a pair's contrast
// depends on what sits beneath it. Over `--color-surface-2` critical, low and
// violet fall under 4.5, and a tinted chip on a tinted row is outside what these
// pairs promise — reach for a solid pair, or an untinted row, where that happens.
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
//
// A pair is STORED SPLIT — fill and ink as two separate whole literals — and the
// two other forms callers need are derived from it:
//
//   TONE_PARTS ──► TONE_SOFT      `${fill} ${text}`, the className handed to cn()
//              └─► toneColors()   the `var(--color-…)` pair an inline style needs
//
// Only that direction keeps all three honest. Tailwind reads the two halves as
// complete candidates whether or not anything joins them, so storing them split
// costs the compiler nothing, while the joined string and the `var()`s are
// ordinary runtime values it never has to see. Deriving the other way — splitting
// a joined string, or writing the vars out beside the classes — would give a pair
// a second place it can be spelled, and a second place is how one family came to
// mean `surface-2` in one registry and `surface-3` in another. It also decides
// which half the lint can police: the tonal-ink ban matches class literals and
// structurally cannot see a `var()`, so keeping the classes primary puts every
// family under it and the derived vars inherit whatever the classes say.

/**
 * A tonal family that can tint a surface.
 *
 * `neutral` is the untinted one: a tile carrying no family colour at all. Its
 * fill is `--color-surface-3`, which theme.css annotates "deeper inset, neutral
 * solid fill" — an object's own fill, as against `--color-surface-2`'s "row
 * hover / subtle inset", which is a state a CONTAINER enters and is applied
 * directly rather than through this registry. Badge's `default` variant and
 * Button's solid `neutral` fill with surface-3 too, so the word means one thing
 * across the package.
 */
export type Tone =
  | 'neutral'
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'ok'
  | 'teal'
  | 'violet'
  | 'primary';

/**
 * The families that also carry a SOLID fill. Only the alert tones do: a solid
 * fill is an escalation, and teal/violet/primary are categorical rather than
 * urgent. `primary` has its own solid pair (`--color-primary-solid` with
 * `--color-text-inv`) that is the button's, not a tile's, so it stays out.
 */
export type SolidTone = Extract<Tone, 'critical' | 'high' | 'medium' | 'low' | 'ok'>;

/** A family's two halves, each a complete literal Tailwind can emit on its own. */
export interface TonePair {
  readonly fill: string;
  readonly text: string;
}

/**
 * The pairs. Written out whole, never assembled: Tailwind scans source text for
 * complete class names, so a half built from a family name emits no rule at all.
 */
export const TONE_PARTS: Record<Tone, TonePair> = {
  // Neither half names a tonal family, so there is no `-ink` here for the
  // tonal-ink rule to check: this row is one the tests have to hold, because
  // nothing else can.
  neutral: { fill: 'bg-surface-3', text: 'text-text-2' },
  critical: { fill: 'bg-sev-critical-fill', text: 'text-sev-critical-ink' },
  high: { fill: 'bg-sev-high-fill', text: 'text-sev-high-ink' },
  medium: { fill: 'bg-sev-medium-fill', text: 'text-sev-medium-ink' },
  low: { fill: 'bg-sev-low-fill', text: 'text-sev-low-ink' },
  ok: { fill: 'bg-ok-fill', text: 'text-ok-ink' },
  teal: { fill: 'bg-teal-fill', text: 'text-teal-ink' },
  violet: { fill: 'bg-violet-fill', text: 'text-violet-ink' },
  // The inverse of every line above: primary's bare token is the ink, and its
  // tint is spelled -tint rather than -fill.
  primary: { fill: 'bg-primary-tint', text: 'text-primary' },
};

/**
 * Tinted surface plus the ink that reads on it.
 *
 * FILL FIRST. Callers store this string as well as passing it to `cn()` — a
 * pill's className is kept verbatim in @akasecurity/dashboard-ui's findings
 * metadata — and tailwind-merge renders either order identically, so flipping it
 * would change the value without changing a pixel.
 */
export const TONE_SOFT: Record<Tone, string> = Object.fromEntries(
  Object.entries(TONE_PARTS).map(([tone, { fill, text }]) => [tone, `${fill} ${text}`]),
) as Record<Tone, string>;

/**
 * Saturated fill carrying `--color-on-accent`. Spelled rather than derived: all
 * five share one ink half, so there is no pair to cross, and nothing outside this
 * object spells them — the duplication the rest of this file removes never
 * existed here.
 */
export const TONE_SOLID: Record<SolidTone, string> = {
  critical: 'bg-sev-critical-ink text-on-accent',
  high: 'bg-sev-high-ink text-on-accent',
  medium: 'bg-sev-medium-ink text-on-accent',
  low: 'bg-sev-low-ink text-on-accent',
  ok: 'bg-ok-ink text-on-accent',
};

/** `text-violet-ink` → `var(--color-violet-ink)`. */
function cssVar(utility: string): string {
  return `var(--color-${utility.replace(/^(?:text|bg)-/, '')})`;
}

/**
 * A family's [foreground, background] pair as theme-token CSS vars, for the one
 * thing a className cannot do: an inline `style`. Derived from the same pair the
 * classes come from, so the two forms cannot drift.
 */
export function toneColors(tone: Tone): [string, string] {
  const { fill, text } = TONE_PARTS[tone];
  return [cssVar(text), cssVar(fill)];
}
