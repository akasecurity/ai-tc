import { describe, expect, it } from 'vitest';

import { createDpuFrameAssembler, createSseAssembler } from '../src/stream-assembler.ts';

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
    // main thread, so that cost is the page noticing the extension. This case
    // asserts only that the payload comes back whole; the cost itself is the
    // next case's job.
    const sse = createSseAssembler();
    const chunk = 'x'.repeat(16 * 1024);
    const chunks = 384;
    expect(sse.push('data: ')).toEqual([]);
    for (let at = 0; at < chunks; at += 1) expect(sse.push(chunk)).toEqual([]);
    // Whole, in order, and nothing dropped at a boundary.
    expect(sse.end()).toEqual([chunk.repeat(chunks)]);
  });

  it('costs the same per byte at four times the chunk count — the rescan guard', () => {
    // The property the fragment list exists for: a retained fragment is never
    // re-examined, so holding a terminator-free body costs its length ONCE
    // rather than once per chunk.
    //
    // Asserted as a RATIO across two chunk counts, not as an elapsed ceiling.
    // A fixed millisecond bound is a statement about the runner, and a loose
    // one is worse than none: the honest implementation frames this input in
    // ~6 ms while the quadratic form takes ~1,030 ms, so a ceiling picked with
    // any headroom at all sits above the regression it names. A ratio cancels
    // the runner — a machine uniformly half as fast moves both sides and the
    // quotient not at all.
    //
    // Both sides are the MINIMUM of the same number of interleaved samples.
    // Noise only ever adds time, so a minimum is the estimator a loaded runner
    // cannot inflate; a stall-immune denominator against a noisy numerator
    // would make a stall explode the quotient instead of cancelling in it.
    //
    // Measured on arm64 macOS / Node 24: honest 3.87-3.95 (unchanged under 20
    // CPU burners), quadratic 16.0-17.3. The ceiling of 8 sits ~2x clear of
    // each. The quadratic form takes ~10.5 s over the whole loop, inside this
    // package's 20 s testTimeout, so it fails on this assertion rather than
    // arriving as a timeout.
    //
    // NOT caught, and deliberately: collapsing `parts` to a single joined
    // element on every push without also re-scanning it. V8's rope strings
    // make that concatenation amortised O(1), so it is linear and reads ~4
    // here. The re-SCAN is what makes the cost quadratic, and it is the only
    // thing this separates.
    const CHUNK = 'x'.repeat(4096);
    const SMALL = 128;
    const BIG = 512;
    const SAMPLES = 8;

    function cost(chunks: number): number {
      const sse = createSseAssembler();
      const started = process.hrtime.bigint();
      for (let at = 0; at < chunks; at += 1) sse.push(CHUNK);
      sse.end();
      return Number(process.hrtime.bigint() - started);
    }

    let small = Infinity;
    let big = Infinity;
    for (let i = 0; i < SAMPLES; i += 1) {
      small = Math.min(small, cost(SMALL));
      big = Math.min(big, cost(BIG));
    }
    // Guards against a degenerate denominator: a zero would make the quotient
    // Infinity or NaN, neither of which is a measurement.
    expect(small).toBeGreaterThan(0);
    expect(big / small).toBeLessThan(8);
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

// ---- length-prefixed DPU frames ----------------------------------------
//
// chatgpt.com's anonymous path streams `<template data-web-mobile-dpu-frame>`
// elements whose attribute is the CONTENT LENGTH. These inputs are shaped from
// real captured frames; the invariant they encode — that the declared length
// plus the wrapper lands exactly on the next frame — was measured on two live
// anonymous turns, over every frame in both.

/** One frame, built the way the site builds it: length first, content after. */
function frame(content: string): string {
  return `<template data-web-mobile-dpu-frame="${String(content.length)}">${content}</template>`;
}

/** Feed `stream` through a fresh assembler in fixed-size chunks. */
function framesOf(stream: string, chunk: number): string[] {
  const assembler = createDpuFrameAssembler();
  const out: string[] = [];
  for (let i = 0; i < stream.length; i += chunk)
    out.push(...assembler.push(stream.slice(i, i + chunk)));
  out.push(...assembler.end());
  return out;
}

describe('createDpuFrameAssembler', () => {
  it('yields one frame per complete template, whatever the chunk boundaries', () => {
    const stream = [frame('<p>a</p>'), frame('<div data-x="1"></div>'), frame('')].join('');
    // 1 is the adversarial case: every boundary falls inside the opener, the
    // digits, the content and the terminator in turn.
    for (const size of [1, 2, 3, 7, 40, stream.length]) {
      expect(framesOf(stream, size), `chunk size ${String(size)}`).toEqual([
        '<p>a</p>',
        '<div data-x="1"></div>',
        '',
      ]);
    }
  });

  it('keeps a frame whose own content contains a nested template', () => {
    // The reason the length prefix exists rather than a scan for the
    // terminator: these frames really do nest, so framing on the first
    // `</template>` hands the parser above half an element.
    const inner = '<p>x</p><template data-assistant-presentation-flush=""></template>';
    expect(framesOf(frame(inner) + frame('<p>y</p>'), 5)).toEqual([inner, '<p>y</p>']);
  });

  it('emits a frame whose content is complete but whose terminator was cut', () => {
    // The length prefix makes this recoverable rather than a guess: the
    // content is known whole from its declared length, so only the trailing
    // `</template>` is missing and nothing has to be inferred.
    const cut = `<template data-web-mobile-dpu-frame="3">abc`;
    expect(framesOf(cut, 4)).toEqual(['abc']);
  });

  it('withholds a frame whose content itself was cut', () => {
    // The complement of the case above, and the one that must NOT emit: the
    // declared length says more content was coming, so what arrived is a
    // fragment rather than a short frame.
    const cut = `<template data-web-mobile-dpu-frame="10">abc`;
    expect(framesOf(cut, 4)).toEqual([]);
  });

  it('resynchronises past an opener whose length does not land on a terminator', () => {
    // A length that means something other than what this reads it to mean.
    // The frame is skipped rather than emitted at a guessed extent, and the
    // NEXT well-formed frame is still recovered.
    const bad = '<template data-web-mobile-dpu-frame="2">abcdef</template>';
    expect(framesOf(bad + frame('<p>ok</p>'), 6)).toEqual(['<p>ok</p>']);
  });

  it('resynchronises past a malformed or absurd length', () => {
    for (const opener of [
      '<template data-web-mobile-dpu-frame="not-a-number">x</template>',
      '<template data-web-mobile-dpu-frame="99999999999999">x</template>',
      '<template data-web-mobile-dpu-frame="">x</template>',
    ]) {
      expect(framesOf(opener + frame('<p>ok</p>'), 9), opener.slice(0, 50)).toEqual(['<p>ok</p>']);
    }
  });

  it('yields nothing for a stream that carries no frames at all', () => {
    // An error page, a redirect body, a JSON reply — anything the route might
    // answer with instead. Reporting nothing is the whole of the contract.
    expect(framesOf('<html><body>not this protocol</body></html>', 8)).toEqual([]);
    expect(framesOf('', 4)).toEqual([]);
  });

  it('does not grow without bound on a stream that never frames', () => {
    // The buffer retains only what could still be the head of an opener, so a
    // long unframed response costs a constant rather than its own length.
    const assembler = createDpuFrameAssembler();
    for (let i = 0; i < 2000; i += 1) expect(assembler.push('x'.repeat(64))).toEqual([]);
    // Still able to frame once a real opener finally arrives.
    expect(assembler.push(frame('<p>late</p>'))).toEqual(['<p>late</p>']);
  });

  it('is idempotent at end and silent after it', () => {
    const assembler = createDpuFrameAssembler();
    expect(assembler.push(frame('<p>a</p>'))).toEqual(['<p>a</p>']);
    expect(assembler.end()).toEqual([]);
    expect(assembler.end()).toEqual([]);
  });
});
