// Keeps vault pointers out of the detection engine's sight.
//
// A pointer's base32 body is exactly the kind of high-entropy string a generic
// secret rule matches, and rule packs are user-installable — so "no rule ever
// matches a pointer" cannot be guaranteed by auditing rule content. It is
// guaranteed here instead: every scan surface blanks pointer spans out of the
// text BEFORE the engine runs, so detection cannot see a pointer body at all,
// whatever rules are installed. Without this, a matching rule would re-tokenize
// a pointer (a pointer to a pointer), re-block a pointerized resubmit, or
// corrupt a transcript rewrite.
import { pointerTokenScanner } from '@akasecurity/schema';

export interface ShieldedSpan {
  start: number;
  end: number;
}

export interface ShieldedText {
  // The input with every pointer span replaced by same-length filler, so every
  // offset outside the pointers is identical to the original.
  text: string;
  spans: ShieldedSpan[];
}

// The filler is a repeated space: no rule matches whitespace, and a same-length
// substitution keeps every other span's offsets valid against the original.
export function shieldPointers(text: string): ShieldedText {
  const spans: ShieldedSpan[] = [];
  let out: string | null = null;
  for (const match of text.matchAll(pointerTokenScanner())) {
    spans.push({ start: match.index, end: match.index + match[0].length });
    out ??= text;
    out =
      out.slice(0, match.index) +
      ' '.repeat(match[0].length) +
      out.slice(match.index + match[0].length);
  }
  return { text: out ?? text, spans };
}

/**
 * Drop findings that touch a shielded span. The filler should never match, but
 * a rule whose span merely brushes a blanked region (a keyword before it plus a
 * window across it) could still produce a finding whose rawMatch mixes real
 * text with filler — worthless to enforce on and wrong to vault.
 */
export function dropShieldedFindings<T extends { span: { start: number; end: number } }>(
  findings: T[],
  spans: ShieldedSpan[],
): T[] {
  if (spans.length === 0) return findings;
  return findings.filter(
    (finding) => !spans.some((s) => finding.span.start < s.end && finding.span.end > s.start),
  );
}
