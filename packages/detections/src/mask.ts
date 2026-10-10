import { stripInvisiblePadding } from '@akasecurity/schema';

// ---------------------------------------------------------------------------
// maskMatch — partial-reveal masking algorithm
//
// Turns a raw matched secret into the value stored in `findings.masked_match`,
// so the real secret never lands in the DB or on the wire. Lives here in
// @akasecurity/detections (next to scan/redact) so every producer of a finding
// masks identically.
//
// Invisible padding (`stripInvisiblePadding` in @akasecurity/schema) is removed
// first, and every rule below reads the VISIBLE value: its length, its email
// split and its first/last characters. One secret seen clean and seen padded
// therefore masks to one string, the same way it shares one identity
// fingerprint, and a finding key that falls back to the masked value keys both
// alike. Characters outside that set (ZWJ/ZWNJ, for one) are kept and masked
// like any other character.
//
// Rule 1: length ≤ 5 → return fixed token '***' (no characters revealed)
// Rule 2: email (has '@' not at edges, domain contains '.') →
//         reveal first char of local part + mask remaining local chars + '@' + full domain
// Rule 3: generic ≥ 6 → reveal first + last char, FIXED 6 asterisks in the middle
//         (length-hiding: actual length is not recoverable from output)
//
// Invariant: maskMatch(raw) !== raw for raw.length > 1, with ONE documented
//   exception — single-char-local emails (e.g. 'a@b.com'): Rule 2 reveals the
//   whole local part + full domain, so there is nothing to mask and the output
//   equals the input by design. Do not "fix" this without revisiting Rule 2.
//   A padded single-char-local email ('a' + ZWSP + '@b.com') masks to that same
//   visible address; the output then differs from the input only by the
//   padding, so a caller that must never reveal a whole value compares the
//   output against the visible value as well as the raw one.
// ---------------------------------------------------------------------------

export function maskMatch(raw: string): string {
  const visible = stripInvisiblePadding(raw);

  // Rule 1 — short match: fully masked, no characters revealed
  if (visible.length <= 5) return '***';

  // Rule 2 — email: first local char + masked remainder + '@' + full domain
  const atIndex = visible.indexOf('@');
  if (atIndex > 0 && atIndex < visible.length - 1) {
    const domain = visible.slice(atIndex + 1);
    if (domain.includes('.')) {
      const local = visible.slice(0, atIndex);
      const maskedLocal =
        local.length <= 1
          ? local // single char: nothing left to mask
          : local.charAt(0) + '*'.repeat(local.length - 1);
      return `${maskedLocal}@${domain}`;
    }
  }

  // Rule 3 — generic secret: first char + FIXED 6 asterisks + last char
  return `${visible.charAt(0)}${'*'.repeat(6)}${visible.charAt(visible.length - 1)}`;
}
