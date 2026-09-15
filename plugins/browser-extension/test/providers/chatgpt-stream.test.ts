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
import { matchedExchangeFor } from '../helpers/matched-exchange.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// This adapter declares no endpoint yet, so the helper supplies the only
// shape available to it — see its own note on what that stand-in does not mean.
const EXCHANGE = matchedExchangeFor(chatgptAdapter);

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

/**
 * The same block under a caller-chosen wrapper tag.
 *
 * Every other case here wraps in `<p>`, which is what the two captures
 * carried — and a `<p>` block cannot collide with the elements a rendered
 * reply puts inside it. A `<div>` block can, which is the whole point of the
 * cases that use this.
 */
function blockTagged(tag: string, inner: string, index = 0): string {
  return (
    `<${tag} data-assistant-stream-block="" data-assistant-stream-block-index="${String(index)}">` +
    `${inner}</${tag}>`
  );
}

function blockFrame(inner: string, withMessageId = false): string {
  const attrs = withMessageId ? ` data-message-id="${MESSAGE_ID}"` : '';
  return frame(`<div${attrs} data-operation-id="op-1">${inner}</div>`);
}

function run(stream: string, chunk = 17): WebExchangeSummary | null {
  const assembler = chatgptAdapter.parseStream(EXCHANGE);
  for (let i = 0; i < stream.length; i += chunk) assembler.push(stream.slice(i, i + chunk));
  return assembler.end();
}

// A block's own rendered content carries same-named elements routinely, and
// the close tag that ends the block is then not the first one after it. Taking
// the first cut the snapshot short and reported the result as complete: no
// shape miss, no parse failure, just a shorter reply than the user saw.
describe('chatgpt anonymous stream — a same-named element inside the block', () => {
  it('keeps the text after a nested element with the wrapper-s tag name', () => {
    const summary = run(
      PRELUDE +
        blockFrame(
          blockTagged(
            'div',
            'Here is the code: <div class="code-block"><pre>console.log(1)</pre></div> and that is it.',
          ),
          true,
        ),
    );
    expect(summary?.responseText).toBe('Here is the code: console.log(1) and that is it.');
  });

  it('keeps the text after a table whose cells nest the same tag again', () => {
    // Two levels deep, so a fix that merely skipped ONE nested pair would
    // still cut this one short.
    const summary = run(
      PRELUDE +
        blockFrame(
          blockTagged(
            'div',
            'Before' +
              '<table><tr><td><div>one</div></td><td><div>two</div></td></tr></table>' +
              'After',
          ),
          true,
        ),
    );
    expect(summary?.responseText).toBe('Beforeonetwo' + 'After');
  });

  it('does not treat a longer tag name as the same element', () => {
    // A VOID element sharing the wrapper's prefix, which is the shape that
    // cannot cancel itself: `<br>` has no close tag, so a depth count matching
    // on a prefix goes up and never comes back down, and the block is dropped
    // whole. A paired longer-named element (`<divider></divider>` inside a
    // `<div>`) balances by accident and proves nothing here — checked by
    // mutation, which is why this case is written with `<br>` instead.
    const summary = run(PRELUDE + blockFrame(blockTagged('b', 'a<br>b'), true));
    expect(summary?.responseText).toBe('ab');
  });

  it('contributes nothing for a block whose own close tag has not arrived', () => {
    // Unchanged behaviour, kept here beside the depth count: a half-arrived
    // block is dropped rather than swallowing the rest of the frame.
    const summary = run(
      PRELUDE +
        frame(
          `<div data-message-id="${MESSAGE_ID}" data-operation-id="op-1">` +
            '<div data-assistant-stream-block="" data-assistant-stream-block-index="0">' +
            'half a reply<div>and a nested open',
        ),
    );
    expect(summary?.responseText).toBeUndefined();
  });
});

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
      PRELUDE +
      blockFrame(block('Hi! How can I help'), true) +
      blockFrame(block('Hi! How can I help you today?'));
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
      PRELUDE +
        blockFrame(block('a &lt; b &amp;&amp; c &gt; d &quot;q&quot; &#39;s&#39; &#x2713;'), true),
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
      PRELUDE +
      blockFrame(block('Hi! How can I help'), true) +
      blockFrame(block('Hi! How can I help you today?'));
    const expected = run(stream, stream.length);
    for (const size of [1, 2, 5, 31, 256]) {
      expect(run(stream, size), `chunk size ${String(size)}`).toEqual(expected);
    }
  });

  it('survives garbage, empty and non-frame streams without throwing', () => {
    for (const stream of [
      '',
      'not this protocol',
      '<template>',
      '<template data-web-mobile-dpu-frame="x">',
    ]) {
      let summary: WebExchangeSummary | null | undefined;
      expect(
        () => {
          summary = run(stream);
        },
        JSON.stringify(stream).slice(0, 40),
      ).not.toThrow();
      expect(summary ?? null).toBeNull();
    }
  });

  it('is silent after end and never throws on a late push', () => {
    const assembler = chatgptAdapter.parseStream(EXCHANGE);
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

  it('strips markup that REASSEMBLES as one span is removed', () => {
    // Removing a matched span brings its neighbours together, so a single pass
    // can leave behind a tag it never saw: stripping the inner span of
    // `<<b>b>` joins the leading `<` to the trailing `b>`. Stripping therefore
    // runs to a fixpoint. Built from char codes so the source of this file
    // carries no tag-shaped literal for a scanner to read as markup.
    const lt = String.fromCharCode(60);
    const gt = String.fromCharCode(62);
    const reassembling = lt + lt + 'b' + gt + 'b' + gt + 'bold';
    const summary = run(PRELUDE + blockFrame(block(reassembling), true));
    expect(summary?.responseText).toBe('bold');
    // The property, stated over the output rather than over this one input: no
    // tag-opening survives, whatever the strip passes did on the way.
    expect(summary?.responseText ?? '').not.toMatch(/<[a-zA-Z]/);
  });

  it('recovers a tag the assistant itself wrote, which arrives escaped', () => {
    // The other side of the order above, and the reason decoding runs LAST: a
    // reply about markup is escaped by the site because it is text, so it must
    // come back as the text the user saw rather than being stripped as though
    // the site had emitted it.
    const summary = run(PRELUDE + blockFrame(block('use &lt;b&gt; for bold'), true));
    expect(summary?.responseText).toBe('use <b> for bold');
  });
});
