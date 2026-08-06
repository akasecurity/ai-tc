import { parseJsonObject } from './json.ts';

// Opaque base64url keyset cursors for the most-recent-first lists.
//
// A cursor names the last row of the page just served, as the tuple its ORDER BY
// sorts on — a timestamp plus a tie-breaking id. The next page asks for rows
// strictly after it, which is why the reads compare an expanded tuple rather
// than using an offset: rows are written to this store by processes the reader
// does not coordinate with (plugin hooks, the CLI), so an offset would skip or
// repeat rows whenever one arrived between pages.
//
// A cursor that does not decode restarts from the top rather than throwing. It
// is opaque state a client hands back, not something a caller composes, so the
// only ways to hold a bad one are a hand-edited URL or a store that has since
// been reset — in both cases the first page is the useful answer.

/** The tuple a most-recent-first list resumes from. */
export interface KeysetCursor {
  startedAtMs: number;
  id: string;
}

export function encodeKeysetCursor(payload: KeysetCursor): string {
  return Buffer.from(JSON.stringify(payload)).toString('base64url');
}

export function decodeKeysetCursor(cursor: string): KeysetCursor | null {
  const parsed = parseJsonObject(Buffer.from(cursor, 'base64url').toString('utf8'));
  if (
    parsed !== undefined &&
    'startedAtMs' in parsed &&
    'id' in parsed &&
    // `Number.isInteger`, not `typeof === 'number'`. Every timestamp this
    // resumes from is epoch millis, and a payload carrying ±Infinity or a
    // fraction binds cleanly rather than failing — returning an EMPTY page with
    // a null cursor, which a caller reads as "end of list". That is the one
    // outcome a cursor that does not decode must never produce, since the
    // documented behaviour above is to restart from the top. (`1e999` is valid
    // JSON and parses to Infinity; a bare `NaN` is not, so it cannot arrive.)
    Number.isInteger(parsed.startedAtMs) &&
    typeof parsed.id === 'string'
  ) {
    return parsed as unknown as KeysetCursor;
  }
  return null;
}
