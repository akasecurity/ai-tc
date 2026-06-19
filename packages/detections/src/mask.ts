// ---------------------------------------------------------------------------
// maskMatch — partial-reveal masking algorithm
//
// Turns a raw matched secret into the value stored in `findings.masked_match`,
// so the real secret never lands in the DB or on the wire. Lives here in
// @akasecurity/detections (next to scan/redact) so every producer of a finding
// masks identically.
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
// ---------------------------------------------------------------------------

export function maskMatch(raw: string): string {
  // Rule 1 — short match: fully masked, no characters revealed
  if (raw.length <= 5) return '***';

  // Rule 2 — email: first local char + masked remainder + '@' + full domain
  const atIndex = raw.indexOf('@');
  if (atIndex > 0 && atIndex < raw.length - 1) {
    const domain = raw.slice(atIndex + 1);
    if (domain.includes('.')) {
      const local = raw.slice(0, atIndex);
      const maskedLocal =
        local.length <= 1
          ? local // single char: nothing left to mask
          : local.charAt(0) + '*'.repeat(local.length - 1);
      return `${maskedLocal}@${domain}`;
    }
  }

  // Rule 3 — generic secret: first char + FIXED 6 asterisks + last char
  return `${raw.charAt(0)}${'*'.repeat(6)}${raw.charAt(raw.length - 1)}`;
}
