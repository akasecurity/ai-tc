/** The longest masked tool-call target a reconciler stores, in UTF-16 code units, before the `…` marker. */
export const MAX_TARGET_LEN = 500;

/**
 * Caps a masked tool-call target at `MAX_TARGET_LEN` and appends `…` when it cut.
 *
 * Callers mask first and cap second, so a secret straddling the cap is redacted whole
 * rather than leaving an unmasked prefix. The cap never splits a surrogate pair: a lone
 * half serialises to a JSON escape the control plane cannot convert to text, and one
 * such event fails the whole batch it travels in.
 */
export function truncateTarget(s: string): string {
  if (s.length <= MAX_TARGET_LEN) return s;
  const last = s.charCodeAt(MAX_TARGET_LEN - 1);
  const end = last >= 0xd800 && last <= 0xdbff ? MAX_TARGET_LEN - 1 : MAX_TARGET_LEN;
  return `${s.slice(0, end)}…`;
}
