import { describe, expect, it } from 'vitest';

import { createSseAssembler } from '../src/stream-assembler.ts';

// Line framing is the one thing every site adapter needs and none of them
// should own: chunks arrive on network boundaries, which fall in the middle of
// lines, so an adapter that parses a chunk as though it were an event drops
// whatever straddled the split. Pure over the chunk sequence, so it tests
// without a page.

describe('createSseAssembler', () => {
  it('yields one payload per complete data line', () => {
    const sse = createSseAssembler();
    expect(sse.push('data: {"a":1}\n\ndata: {"a":2}\n\n')).toEqual(['{"a":1}', '{"a":2}']);
  });

  it('holds a line that a chunk boundary split, and yields it once completed', () => {
    // The property the whole module exists for: neither half is a payload, and
    // the join is what the adapter parses.
    const sse = createSseAssembler();
    expect(sse.push('data: {"mess')).toEqual([]);
    expect(sse.push('ageId":"m1"}\n')).toEqual(['{"messageId":"m1"}']);
  });

  it('holds a trailing carriage return rather than framing on it', () => {
    // A chunk ending in \r is ambiguous — the \n may be in the next chunk — so
    // splitting there yields a payload and then an empty line that is not one.
    const sse = createSseAssembler();
    expect(sse.push('data: one\r')).toEqual([]);
    expect(sse.push('\ndata: two\n')).toEqual(['one', 'two']);
  });

  it('frames on a lone carriage return too', () => {
    const sse = createSseAssembler();
    expect(sse.push('data: one\rdata: two\n')).toEqual(['one', 'two']);
  });

  it('strips exactly one space after the colon, and keeps the rest', () => {
    // Per the event-stream framing: one optional space is separator, a second
    // is content. Stripping both would corrupt a payload whose first character
    // is a space.
    const sse = createSseAssembler();
    expect(sse.push('data:  padded\n')).toEqual([' padded']);
    expect(sse.push('data:tight\n')).toEqual(['tight']);
  });

  it('ignores comments, blank lines and fields that are not data', () => {
    const sse = createSseAssembler();
    expect(sse.push(': keep-alive\n\nevent: delta\nid: 7\nretry: 1000\ndata: kept\n\n')).toEqual([
      'kept',
    ]);
  });

  it('keeps an empty data value, which is a payload rather than a blank line', () => {
    const sse = createSseAssembler();
    expect(sse.push('data:\n')).toEqual(['']);
  });

  it('flushes a final line the stream ended without terminating', () => {
    // A cut or non-conformant stream can end mid-line. Handing the fragment to
    // the adapter costs it one failed parse; dropping a COMPLETE last line that
    // merely lacked its newline loses the turn's own summary.
    const sse = createSseAssembler();
    expect(sse.push('data: last')).toEqual([]);
    expect(sse.end()).toEqual(['last']);
  });

  it('flushes a final line once and not twice', () => {
    // The second end() must have something to re-emit, or an assembler that
    // never clears its buffer satisfies this while re-emitting its last
    // fragment for as long as anything keeps calling it. The first assertion
    // is the positive control on the same bytes.
    const sse = createSseAssembler();
    sse.push('data: last');
    expect(sse.end()).toEqual(['last']);
    expect(sse.end()).toEqual([]);
  });

  it('flushes nothing when the stream ended cleanly', () => {
    const sse = createSseAssembler();
    expect(sse.push('data: one\n')).toEqual(['one']);
    expect(sse.end()).toEqual([]);
  });

  it('recovers a payload spread over hundreds of chunks with no terminator in it', () => {
    // A matched endpoint that answers with plain JSON, or an error page, sends
    // no line terminator at all — so every chunk extends one held line, and an
    // assembler that re-reads what it is holding on each push walks the whole
    // response again per chunk. This runs in a content script on the page's own
    // main thread, so that cost is the page noticing the extension: the same
    // input costs milliseconds framed once and tens of seconds re-read, which
    // is what makes a return of the rescan visible here rather than only in
    // production.
    const sse = createSseAssembler();
    const chunk = 'x'.repeat(16 * 1024);
    const chunks = 384;
    expect(sse.push('data: ')).toEqual([]);
    for (let at = 0; at < chunks; at += 1) expect(sse.push(chunk)).toEqual([]);
    // Whole, in order, and nothing dropped at a boundary.
    expect(sse.end()).toEqual([chunk.repeat(chunks)]);
  });

  it('survives a stream that is not event-stream framing at all', () => {
    // A site that answers a matched endpoint with plain JSON, or an error page.
    // Nothing here may throw: the bridge counts a throw as a lost exchange.
    const sse = createSseAssembler();
    expect(sse.push('{"not":"sse"}')).toEqual([]);
    expect(sse.push('\u0000� binary-ish\n')).toEqual([]);
    expect(sse.end()).toEqual([]);
  });
});
