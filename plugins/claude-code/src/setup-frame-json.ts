/**
 * Machine-readable frame payloads the /aka:setup wizard scripts emit ALONGSIDE
 * their human-readable copy. A frame's structured JSON is wrapped in these
 * markers so a harness (or the later Claude layer) can extract exactly one
 * payload from a script's stdout without parsing the surrounding rendered card.
 * The block is additive: the human copy is never replaced.
 *
 * The payload carries only masked/enum/count data by construction — the callers
 * build it from raw-free plan/store values, never from raw detected content.
 */

export const FRAME_JSON_BEGIN = '<<<AKA_FRAME_JSON';
export const FRAME_JSON_END = 'AKA_FRAME_JSON>>>';

// Wrap a frame payload in the delimited block a script appends to its stdout.
export function frameJsonBlock(payload: unknown): string {
  return `${FRAME_JSON_BEGIN}\n${JSON.stringify(payload)}\n${FRAME_JSON_END}\n`;
}

// Extract and parse the single frame payload from a script's stdout, or
// undefined when no block is present or its contents are not valid JSON. Shared
// so the emitter and its readers (tests, harness) agree on the delimiters. A
// malformed block resolves to undefined rather than throwing, so a reader can
// treat "no readable frame" uniformly.
export function readFrameJsonBlock(stdout: string): unknown {
  const begin = stdout.indexOf(FRAME_JSON_BEGIN);
  if (begin === -1) return undefined;
  const from = begin + FRAME_JSON_BEGIN.length;
  const end = stdout.indexOf(FRAME_JSON_END, from);
  if (end === -1) return undefined;
  try {
    return JSON.parse(stdout.slice(from, end).trim());
  } catch {
    return undefined;
  }
}
