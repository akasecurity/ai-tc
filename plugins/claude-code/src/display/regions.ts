// The markdown-region walk the display-side pointer rendering shares: the
// MessageDisplay command hook (message-display-transform.ts) and the Claude Code
// mod's ui.render hook (hooks/engine.js) both decide from it where a pointer may
// be revealed and where it stays masked. No I/O and no imports, so it bundles
// into the mod's engine module.

// An open fenced-code region: the opening marker's character and run length.
// A fence closes only on a line-start run of the SAME character at least as
// long as the opener, so a ``` inside a ````-opened fence is content, and a
// tilde fence is never closed by backticks.
export interface FenceState {
  char: '`' | '~';
  len: number;
}

// Markdown-region walker over the emitted stream. Deliberately conservative:
// where a delta boundary leaves the state ambiguous, the walk errs toward
// "protected", which only ever masks a pointer that full mode might have
// revealed — never the reverse.
export interface RegionState {
  fence: FenceState | null;
  tickOpen: boolean;
  lineQuoted: boolean;
  lineSeen: boolean;
  lineIndent: number;
}

// Whether the rest of the current line, as far as this segment shows it, is
// blank up to a newline. Without a visible newline the answer is false: a
// closing fence is only honored once the whole closing line has been seen
// (keeping the fence open masks longer, never reveals early).
function restOfLineIsBlank(text: string, from: number): boolean {
  for (let k = from; k < text.length; k += 1) {
    const c = text[k];
    if (c === '\n') return true;
    if (c !== ' ' && c !== '\t' && c !== '\r') return false;
  }
  return false;
}

export function advanceRegions(state: RegionState, text: string): void {
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '\n') {
      state.lineQuoted = false;
      state.lineSeen = false;
      state.lineIndent = 0;
      i += 1;
      continue;
    }
    if (ch === '`' || ch === '~') {
      let end = i + 1;
      while (end < text.length && text[end] === ch) end += 1;
      const runLen = end - i;
      const atLineStart = !state.lineSeen && state.lineIndent <= 3;
      if (state.fence !== null) {
        // Inside a fence every marker is content except a matching closer: a
        // line-start run of the opening character, at least as long as the
        // opener, with nothing else on its line.
        if (
          atLineStart &&
          ch === state.fence.char &&
          runLen >= state.fence.len &&
          restOfLineIsBlank(text, end)
        ) {
          state.fence = null;
        }
      } else if (atLineStart && runLen >= 3) {
        state.fence = { char: ch, len: runLen };
        state.tickOpen = false;
      } else if (ch === '`' && runLen % 2 === 1) {
        // Mid-line backtick runs pair off as inline code delimiters; an odd
        // run flips the span state. Mid-line runs never touch fence state.
        state.tickOpen = !state.tickOpen;
      }
      state.lineSeen = true;
      i = end;
      continue;
    }
    if (!state.lineSeen) {
      if (ch === ' ') {
        state.lineIndent += 1;
        i += 1;
        continue;
      }
      if (ch === '\t') {
        state.lineIndent += 4;
        i += 1;
        continue;
      }
      state.lineSeen = true;
      if (ch === '>') state.lineQuoted = true;
    }
    i += 1;
  }
}
