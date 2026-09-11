// chatgpt.com anonymous-path response-stream parsing.
//
// These inputs are SYNTHETIC, shaped from two real anonymous turns captured
// through the tap. They certify this parser's FRAMING and ASSEMBLY and certify
// nothing about what chatgpt.com sends today. They are not fixtures: a fixture
// is a committed, sanitiser-produced envelope under test/fixtures/ that the bar
// in network-contract.test.ts re-judges against the live detector, and none
// exists for this site. The bar is armed the moment `chatgptAdapter.endpoints`
// becomes non-empty (see EXPECTED_DECLARING_ADAPTERS in
// test/helpers/fixture-bar.ts).
//
// Three shapes below are drawn from the captures rather than invented, because
// each is a thing a parser written from the attribute table alone gets wrong:
// the marker attribute carries an EMPTY value, a `<?marker …>` processing
// instruction sits INSIDE the block, and a later frame's text for one index has
// the earlier frame's as a PREFIX rather than continuing it.
//
// The DOM half of this adapter is covered separately under jsdom; this file
// runs under the default `node` environment.
import { describe, expect, it } from 'vitest';

import { chatgptAdapter } from '../../src/providers/chatgpt.ts';
import type { WebExchangeSummary } from '../../src/providers/types.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

const MESSAGE_ID = '88556658-40aa-4d53-9001-5dab5cc3b02d';
const CONVERSATION_ID = '0f3a91c2-7d54-4e18-9b26-5ac81de70f43';

/** One frame, built the way the site builds it: content length, then content. */
function frame(content: string): string {
  return `<template data-web-mobile-dpu-frame="${String(content.length)}">${content}</template>`;
}

/**
 * An assistant block as the wire carries it: the marker attribute EMPTY, the
 * ordinal in its own attribute, and the streaming tail marker inside the
 * element rather than after it.
 */
function block(text: string, index = 0, tail = true): string {
  const marker = tail ? `<?marker name="assistant-pending-${MESSAGE_ID}-pending-tail">` : '';
  return (
    `<p data-assistant-stream-block="" data-assistant-stream-block-index="${String(index)}">` +
    `${text}${marker}</p>`
  );
}

/** The lead-in frames every observed turn opened with. */
const PRELUDE = [
  frame('<div data-conversation-control="started" data-operation-id="op-1"></div>'),
  frame('<div data-web-mobile-conversation-turn-marker="start" data-operation-id="op-1"></div>'),
  frame(
    `<div data-conversation-control="conversation-id" data-conversation-id="${CONVERSATION_ID}"></div>`,
  ),
].join('');

function blockFrame(inner: string, withMessageId = false): string {
  const attrs = withMessageId ? ` data-message-id="${MESSAGE_ID}"` : '';
  return frame(`<div${attrs} data-operation-id="op-1">${inner}</div>`);
}

function run(stream: string, chunk = 17): WebExchangeSummary | null {
  const assembler = chatgptAdapter.parseStream();
  for (let i = 0; i < stream.length; i += chunk) assembler.push(stream.slice(i, i + chunk));
  return assembler.end();
}

describe('chatgpt anonymous stream', () => {
  it('recovers the message id, the conversation id and the assistant text', () => {
    const summary = run(PRELUDE + blockFrame(block('Hello there'), true));
    expect(summary).not.toBeNull();
    expect(summary?.messageId).toBe(MESSAGE_ID);
    expect(summary?.conversationId).toBe(CONVERSATION_ID);
    expect(summary?.responseText).toBe('Hello there');
  });

  it('takes the LAST snapshot for an index rather than concatenating them', () => {
    // The semantic the captures settled, and the one that silently corrupts a
    // reply if read the other way: frames re-send the whole block so far, so
    // appending repeats the reply's own opening.
    const stream =
      PRELUDE + blockFrame(block('Hi! How can I help'), true) + blockFrame(block('Hi! How can I help you today?'));
    expect(run(stream)?.responseText).toBe('Hi! How can I help you today?');
  });

  it('strips the streaming tail marker that sits inside the block', () => {
    // `<?marker …>` is a processing instruction rather than an element, so a
    // parser stripping only `<tag>` forms leaves it in the middle of the reply.
    const summary = run(PRELUDE + blockFrame(block('Half a sentence'), true));
    expect(summary?.responseText).toBe('Half a sentence');
    expect(summary?.responseText).not.toContain('marker');
    expect(summary?.responseText).not.toContain('<?');
  });

  it('decodes the entities element content is escaped with', () => {
    // Assistant text arrives as markup content, so a reply containing these
    // characters is on the wire escaped and would otherwise be stored that way.
    const summary = run(
      PRELUDE + blockFrame(block('a &lt; b &amp;&amp; c &gt; d &quot;q&quot; &#39;s&#39; &#x2713;'), true),
    );
    expect(summary?.responseText).toBe(`a < b && c > d "q" 's' ✓`);
  });

  it('leaves an unknown or out-of-range reference exactly as it arrived', () => {
    const summary = run(PRELUDE + blockFrame(block('&notareal; &#x110000; &#xD800;'), true));
    expect(summary?.responseText).toBe('&notareal; &#x110000; &#xD800;');
  });

  it('orders multiple blocks by their index, not by arrival', () => {
    const stream =
      PRELUDE +
      blockFrame(block('second', 1), true) +
      blockFrame(block('first', 0)) +
      blockFrame(block('third', 2));
    expect(run(stream)?.responseText).toBe('firstsecondthird');
  });

  it('reports no model and no usage, because this path carries neither', () => {
    const summary = run(PRELUDE + blockFrame(block('x'), true));
    expect(summary?.model).toBeUndefined();
    expect(summary?.usageSource).toBe('none');
    expect(summary?.toolCalls).toEqual([]);
  });

  it('returns null without a message id, rather than a half-built summary', () => {
    // The message id is the natural key the stored row hashes on, so a turn
    // that never named one is a turn this recovered nothing usable from.
    expect(run(PRELUDE + blockFrame(block('orphan text')))).toBeNull();
  });

  it('reports a turn cut before its end control, without inventing an end', () => {
    // The tap's own byte ceiling can cut a healthy long reply, so truncation
    // must not read as a contract change — whatever arrived is reported.
    const summary = run(PRELUDE + blockFrame(block('partial reply'), true));
    expect(summary?.responseText).toBe('partial reply');
  });

  it('assembles identically however the chunks fall', () => {
    const stream =
      PRELUDE + blockFrame(block('Hi! How can I help'), true) + blockFrame(block('Hi! How can I help you today?'));
    const expected = run(stream, stream.length);
    for (const size of [1, 2, 5, 31, 256]) {
      expect(run(stream, size), `chunk size ${String(size)}`).toEqual(expected);
    }
  });

  it('survives garbage, empty and non-frame streams without throwing', () => {
    for (const stream of ['', 'not this protocol', '<template>', '<template data-web-mobile-dpu-frame="x">']) {
      let summary: WebExchangeSummary | null | undefined;
      expect(() => {
        summary = run(stream);
      }, JSON.stringify(stream).slice(0, 40)).not.toThrow();
      expect(summary ?? null).toBeNull();
    }
  });

  it('is silent after end and never throws on a late push', () => {
    const assembler = chatgptAdapter.parseStream();
    assembler.push(PRELUDE + blockFrame(block('done'), true));
    expect(assembler.end()?.responseText).toBe('done');
    expect(() => {
      assembler.push(blockFrame(block('ignored')));
    }).not.toThrow();
  });

  it('puts no raw markup into the text it recovers', () => {
    // The failure this parser exists to avoid: emitting the frame's markup as
    // though it were the reply.
    const raw = block('visible text');
    const summary = run(PRELUDE + blockFrame(raw, true));
    expect(summary?.responseText).toBe('visible text');
    expectNoEchoOf(summary?.responseText ?? '', 'data-assistant-stream-block');
    expectNoEchoOf(summary?.responseText ?? '', 'data-web-mobile-dpu-frame');
  });
});
