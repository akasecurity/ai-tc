// Response framing, shared by the site adapters.
//
// Two schemes live here because they answer the same question — where does one
// complete unit end, given chunks that arrive on network boundaries rather than
// on the format's own. `createSseAssembler` frames `data:` lines;
// `createDpuFrameAssembler` frames the length-prefixed `<template>` frames
// chatgpt.com's anonymous path streams.
//
//
// Response chunks arrive on network boundaries, which land in the middle of
// lines — so an adapter that parses a chunk as though it were an event drops
// whatever straddled the split, silently and only under load. Framing is done
// once, here, and each adapter parses whole payloads.
//
// This yields one payload per complete `data:` line rather than accumulating
// until a blank line dispatches an event. Both shapes are the same for the
// one-JSON-object-per-line streams these sites send, and the line form has the
// property that matters on a cut or non-conformant stream: it never holds a
// whole response waiting for a boundary that is not coming. The cost is that a
// multi-line `data:` event arrives as several payloads; an adapter for a site
// that sends one has to rejoin them.

const DATA_PREFIX = 'data:';

export interface SseAssembler {
  // The complete `data:` payloads this chunk finished, in order. A chunk that
  // finishes none returns an empty array — including the common case of a chunk
  // that is entirely one line's middle.
  push(chunk: string): string[];
  // Whatever a final line left unterminated. A stream can end mid-line, and a
  // complete last line that merely lacked its newline carries the summary of
  // the whole turn; a fragment costs the adapter one failed parse, which is the
  // cheaper of the two errors.
  end(): string[];
}

function payloadOf(line: string): string | null {
  // A comment, a blank line, or a field that is not `data` — none of which
  // carries anything this returns.
  if (!line.startsWith(DATA_PREFIX)) return null;
  const value = line.slice(DATA_PREFIX.length);
  // Exactly one space is the separator; a second is content, so a payload
  // beginning with a space survives.
  return value.startsWith(' ') ? value.slice(1) : value;
}

const LF = 10;
const CR = 13;

export function createSseAssembler(): SseAssembler {
  // Whatever the last chunks left unterminated, held as the FRAGMENTS they
  // arrived in rather than as one joined string, and never re-examined.
  //
  // That is the whole reason this is a list. Joining the retained tail onto
  // each new chunk and scanning the result walks every byte again on every
  // chunk, so a response the site sends without line terminators — plain JSON,
  // an error page — costs the square of its length on the page's own main
  // thread. At the tap's own ceiling that is seconds of a blocked tab, and the
  // page is what must never notice this extension.
  let parts: string[] = [];
  // The last chunk ended on a carriage return that terminated the held line.
  // Kept apart rather than in `parts` because it is not yet known to be a
  // terminator: its newline may open the next chunk, and framing on it early
  // would emit a payload plus a phantom empty line.
  let heldCr = false;

  // The held fragments as one line, and the buffer emptied.
  function takeLine(): string {
    const line = parts.length === 1 ? (parts[0] ?? '') : parts.join('');
    parts = [];
    return line;
  }

  return {
    push(chunk: string): string[] {
      const payloads: string[] = [];
      let index = 0;

      if (heldCr) {
        // An empty chunk decides nothing, so the return stays ambiguous.
        if (chunk.length === 0) return payloads;
        heldCr = false;
        const held = payloadOf(takeLine());
        if (held !== null) payloads.push(held);
        // The newline that followed it belongs to that terminator, not to the
        // line this chunk starts.
        if (chunk.charCodeAt(0) === LF) index = 1;
      }

      let lineStart = index;
      while (index < chunk.length) {
        const code = chunk.charCodeAt(index);
        if (code !== LF && code !== CR) {
          index += 1;
          continue;
        }
        parts.push(chunk.slice(lineStart, index));
        if (code === CR && index === chunk.length - 1) {
          // Ambiguous: hold the line AND the return, so the next chunk decides
          // whether this was a CRLF or a bare CR.
          heldCr = true;
          return payloads;
        }
        const payload = payloadOf(takeLine());
        if (payload !== null) payloads.push(payload);
        index += code === CR && chunk.charCodeAt(index + 1) === LF ? 2 : 1;
        lineStart = index;
      }
      if (lineStart < chunk.length) parts.push(chunk.slice(lineStart));
      return payloads;
    },
    end(): string[] {
      // A held trailing return was a line terminator after all — nothing
      // followed it — so the line it terminated is whatever the fragments hold.
      heldCr = false;
      const line = takeLine();
      if (line === '') return [];
      const payload = payloadOf(line);
      return payload === null ? [] : [payload];
    },
  };
}

// The opener of one declarative-partial-update frame. The digits between the
// quotes are the frame's CONTENT LENGTH, in the same units a decoded chunk is
// measured in, and `>` closes the tag immediately after them.
const DPU_OPEN_PREFIX = '<template data-web-mobile-dpu-frame="';
const DPU_CLOSE = '</template>';

// The largest frame this will buffer toward. A length is read off the stream
// before any of the content behind it has arrived, so an absurd one — a
// corrupted digit run, or a page answering with something else entirely —
// would otherwise hold the assembler waiting for bytes that never come while
// the buffer it is filling grows to meet them.
const DPU_MAX_FRAME_LENGTH = 1024 * 1024;
// Enough for that ceiling and nothing like enough to be a payload, so a run of
// digits this long is a malformed opener rather than a big frame.
const DPU_MAX_DIGITS = 9;

export interface DpuFrameAssembler {
  // The complete frames this chunk finished, in order, each as the markup
  // BETWEEN the opener and its terminator. A chunk that finishes none returns
  // an empty array.
  push(chunk: string): string[];
  // A frame whose content is complete but whose terminator never arrived. The
  // length prefix is what makes that recoverable rather than a guess: the
  // content is known whole from its declared length, so a stream cut inside
  // the trailing `</template>` costs nothing.
  end(): string[];
}

/**
 * Frame a length-prefixed `<template data-web-mobile-dpu-frame="n">` stream.
 *
 * The length prefix is load-bearing rather than a convenience. Frames nest —
 * a frame's own content carries further `<template>` elements — so framing on
 * the first `</template>` cuts a frame short and hands the parser above half
 * an element. Reading the declared length means the terminator is only ever
 * CHECKED, never searched for.
 *
 * Anything that does not line up is RESYNCHRONISED rather than repaired: the
 * opener is skipped and the scan resumes after it. A frame this cannot read is
 * a frame this reports nothing about; it never emits content it had to guess
 * the extent of.
 */
export function createDpuFrameAssembler(): DpuFrameAssembler {
  let buffer = '';
  // How far into `buffer` the opener scan has already looked. Without it a
  // stream that never frames is re-scanned from the start on every chunk,
  // which is quadratic in the response length on the page's own main thread —
  // the cost createSseAssembler keeps its fragment list to avoid.
  let searchFrom = 0;

  function drain(frames: string[], atEnd: boolean): void {
    for (;;) {
      const open = buffer.indexOf(DPU_OPEN_PREFIX, searchFrom);
      if (open === -1) {
        // Nothing framed here. Keep only what could still be the head of an
        // opener split across this chunk boundary.
        const keep = Math.max(0, buffer.length - (DPU_OPEN_PREFIX.length - 1));
        buffer = buffer.slice(keep);
        searchFrom = 0;
        return;
      }
      const digitsAt = open + DPU_OPEN_PREFIX.length;
      const quote = buffer.indexOf('"', digitsAt);
      if (quote === -1) {
        // The digits are still arriving. Hold position rather than consuming.
        if (buffer.length - digitsAt > DPU_MAX_DIGITS) {
          searchFrom = open + 1;
          continue;
        }
        searchFrom = open;
        return;
      }
      const digits = buffer.slice(digitsAt, quote);
      const length = /^[0-9]{1,9}$/.test(digits) ? Number(digits) : -1;
      if (length < 0 || length > DPU_MAX_FRAME_LENGTH || buffer.charAt(quote + 1) !== '>') {
        // A malformed opener, or a well-formed one whose `>` has not arrived.
        // Only the second is worth waiting for.
        if (length >= 0 && length <= DPU_MAX_FRAME_LENGTH && quote + 1 >= buffer.length) {
          searchFrom = open;
          return;
        }
        searchFrom = open + 1;
        continue;
      }
      const contentAt = quote + 2;
      const contentEnd = contentAt + length;
      if (buffer.length < contentEnd) {
        // The content is still arriving.
        searchFrom = open;
        return;
      }
      const terminated = buffer.startsWith(DPU_CLOSE, contentEnd);
      if (!terminated && buffer.length < contentEnd + DPU_CLOSE.length && !atEnd) {
        searchFrom = open;
        return;
      }
      if (!terminated && !atEnd) {
        // The declared length did not land on a terminator, so it did not mean
        // what this reads it to mean. Resynchronise rather than emit content
        // whose extent is now a guess.
        searchFrom = open + 1;
        continue;
      }
      frames.push(buffer.slice(contentAt, contentEnd));
      buffer = buffer.slice(terminated ? contentEnd + DPU_CLOSE.length : contentEnd);
      searchFrom = 0;
    }
  }

  return {
    push(chunk: string): string[] {
      const frames: string[] = [];
      buffer += chunk;
      drain(frames, false);
      return frames;
    },
    end(): string[] {
      const frames: string[] = [];
      drain(frames, true);
      buffer = '';
      searchFrom = 0;
      return frames;
    },
  };
}
