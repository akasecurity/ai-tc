// Event-stream line framing, shared by every site adapter.
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
