import { createDpuFrameAssembler } from '../stream-assembler.ts';
import {
  extractComposerText,
  firstMatch,
  setComposerText,
  watchButtonClick,
  watchEnterToSend,
} from './dom-utils.ts';
import type { ExchangeAssembler, ProviderAdapter, WebExchangeSummary } from './types.ts';

// Best-effort, layered fallback selectors — chatgpt.com's DOM has carried
// #prompt-textarea and data-testid="send-button" across several redesigns,
// but neither is guaranteed for whatever build is live when this loads. A
// miss here means findComposer()/findSendButton() return null and this
// adapter silently does nothing (fail-open) rather than misfiring on the
// wrong element. These selectors track the live site best-effort and can go
// stale with a redesign — verify against the real site before relying on
// block/redact actually firing.
const COMPOSER_SELECTORS = [
  '#prompt-textarea',
  'form [contenteditable="true"][role="textbox"]',
  'form [contenteditable="true"]',
];
const SEND_BUTTON_SELECTORS = ['[data-testid="send-button"]', 'button[aria-label*="send" i]'];

function findSendButton(): HTMLElement | null {
  return firstMatch(SEND_BUTTON_SELECTORS);
}

// The five named references HTML defines, plus numeric ones. Assistant text
// reaches this ESCAPED, because it arrived as element content in a markup
// stream — a reply containing `<`, `&` or a quote is on the wire as an entity
// and would otherwise be stored with the escape still in it.
const NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
};

function decodeEntities(text: string): string {
  if (!text.includes('&')) return text;
  return text.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, body: string) => {
    if (body.startsWith('#')) {
      const hex = body.charAt(1) === 'x' || body.charAt(1) === 'X';
      const digits = hex ? body.slice(2) : body.slice(1);
      const code = Number.parseInt(digits, hex ? 16 : 10);
      // A reference outside Unicode, or one naming a surrogate half, is left
      // as it arrived rather than turned into a replacement character.
      if (!Number.isInteger(code) || code < 0 || code > 0x10ffff) return whole;
      if (code >= 0xd800 && code <= 0xdfff) return whole;
      return String.fromCodePoint(code);
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
  });
}

/**
 * The text of one assistant block, from the markup between its tags.
 *
 * Two things are stripped and both were observed rather than anticipated. A
 * `<?marker name="…">` PROCESSING INSTRUCTION sits INSIDE the block, marking
 * where the stream will continue — left in, it lands in the middle of the
 * reply. Ordinary tags are stripped too, so a block that ever carries inline
 * markup contributes its text rather than its markup.
 */
function textOfBlock(inner: string): string {
  return decodeEntities(
    inner
      // Processing instructions. These do NOT begin with a tag name, so the
      // element pattern below does not reach them.
      .replace(/<\?[^>]*>/g, '')
      // Elements, opening and closing. Deliberately narrower than `<[^>]*>`:
      // a bare `<` that begins no tag is text, and eating to the next `>`
      // would swallow the reply between them.
      .replace(/<\/?[a-zA-Z][^>]*>/g, ''),
  );
}

function attributeOf(html: string, name: string): string | undefined {
  const match = new RegExp(`\\b${name}="([^"]*)"`).exec(html);
  const value = match?.[1];
  return value === undefined || value === '' ? undefined : value;
}

// A block element: the marker attribute carries no value, and the ordinal
// lives in its own `-index` attribute beside it. Matching on the marker's own
// quote is what keeps `-index` from matching here as well.
const BLOCK_OPEN = /<([a-zA-Z][a-zA-Z0-9-]*)\b([^>]*\bdata-assistant-stream-block="[^"]*"[^>]*)>/g;

/**
 * One anonymous chatgpt.com turn, assembled from declarative-partial-update
 * frames.
 *
 * WHAT WAS OBSERVED, on two complete anonymous turns:
 *
 * - The assistant text is the block element's CONTENT. The marker attribute
 *   `data-assistant-stream-block` carries an EMPTY value on the wire, so it
 *   could not be the text even in principle, and the ordinal is a separate
 *   `-index` attribute.
 * - Frames carry CUMULATIVE SNAPSHOTS of a block, not appends: a later frame's
 *   text for one index has the earlier frame's text as a PREFIX. Concatenating
 *   would repeat the reply's own opening. So the last value for an index wins.
 * - One `data-message-id` per turn, on the frame that carries the first
 *   assistant block. It is the natural key the stored row hashes on.
 * - No model is on this path at all — no attribute carries one — so the
 *   summary reports none rather than guessing, and `usageSource` is 'none'
 *   because no token count appears either.
 *
 * WHAT WAS NOT. Both observed turns were short replies that used a single
 * block at index 0, so multi-block assembly is the documented meaning of
 * `-block-index` rather than something a capture has shown. Ordering by index
 * is what that attribute is for; if a site ever reused an index across
 * genuinely different blocks, this would keep the later one.
 */
function createChatgptAnonymousAssembler(): ExchangeAssembler {
  const frames = createDpuFrameAssembler();
  // Last text seen for each block index — a snapshot, replaced rather than
  // appended to.
  const blocks = new Map<number, string>();
  let messageId: string | undefined;
  let conversationId: string | undefined;
  let ended = false;

  function handleFrame(html: string): void {
    messageId ??= attributeOf(html, 'data-message-id');
    conversationId ??= attributeOf(html, 'data-conversation-id');

    BLOCK_OPEN.lastIndex = 0;
    for (;;) {
      const open = BLOCK_OPEN.exec(html);
      if (open === null) return;
      const [whole, tag, attributes] = open;
      if (tag === undefined || attributes === undefined) continue;
      const ordinal = attributeOf(attributes, 'data-assistant-stream-block-index') ?? '0';
      if (!/^[0-9]{1,6}$/.test(ordinal)) continue;
      // Non-greedy to the first matching close tag. These elements do not nest
      // inside one another on this stream, and a block whose close tag has not
      // arrived contributes nothing rather than the rest of the frame.
      const close = html.indexOf(`</${tag}>`, open.index + whole.length);
      if (close === -1) continue;
      blocks.set(Number(ordinal), textOfBlock(html.slice(open.index + whole.length, close)));
    }
  }

  function assembledText(): string {
    return [...blocks.keys()]
      .sort((a, b) => a - b)
      .map((index) => blocks.get(index) ?? '')
      .join('');
  }

  return {
    push(chunk: string): void {
      if (ended) return;
      for (const frame of frames.push(chunk)) handleFrame(frame);
    },
    end(): WebExchangeSummary | null {
      if (!ended) {
        for (const frame of frames.end()) handleFrame(frame);
        ended = true;
      }
      // Without a message id there is no natural key for the stored row, so a
      // half-built summary is worse than none. Deliberately NOT gated on the
      // end-of-turn control: the tap's own byte ceiling can cut a healthy long
      // reply, and reporting that truncation as a contract change would be the
      // worse error.
      if (messageId === undefined) return null;
      const text = assembledText();
      return {
        messageId,
        usageSource: 'none',
        toolCalls: [],
        ...(conversationId !== undefined ? { conversationId } : {}),
        ...(text !== '' ? { responseText: text } : {}),
      };
    },
  };
}

export const chatgptAdapter: ProviderAdapter = {
  id: 'chatgpt',
  hostnames: ['chatgpt.com', 'chat.openai.com'],
  findComposer() {
    return firstMatch(COMPOSER_SELECTORS);
  },
  findSendButton,
  extractText: extractComposerText,
  setText: setComposerText,
  watchSubmit(composer, onSubmit) {
    const unwatchEnter = watchEnterToSend(composer, onSubmit);
    const sendButton = findSendButton();
    const unwatchClick = sendButton ? watchButtonClick(sendButton, onSubmit) : undefined;
    return () => {
      unwatchEnter();
      unwatchClick?.();
    };
  },
  submit() {
    const sendButton = findSendButton();
    if (!sendButton) return false;
    sendButton.click();
    return true;
  },

  // NETWORK HALF. chatgpt.com serves this adapter's traffic over two routes
  // with nothing in common but the host, and they are at different stages.
  //
  // - The ANONYMOUS turn route (`/unauth-mweb/conversation/updates`) is
  //   PARSED: `createChatgptAnonymousAssembler` above reads its
  //   length-prefixed `<template>` frames, and the two semantics that used to
  //   block it are settled from real captures — the assistant text is the
  //   block element's content (its marker attribute is empty on the wire), and
  //   frames carry cumulative snapshots rather than appends.
  // - The AUTHENTICATED turn route's WIRE FORMAT is known (JSON request; SSE
  //   with a `delta_encoding: v1` preamble and p/o/v/c delta objects), but its
  //   PATH was never isolated — only that it sits somewhere under
  //   `/backend-api/` and is not `sentinel`. "Under /backend-api/" is not a
  //   path, so no entry is declared for it; a placeholder or a guessed route
  //   would be exactly the invented-endpoint failure this project forbids.
  //
  // `endpoints` STAYS EMPTY even for the parsed route, for the reason
  // claude.ai's did until its own capture existed: a declaring adapter owes
  // committed fixtures under test/fixtures/chatgpt/, produced only by
  // scripts/sanitize-capture.mjs from a real capture, and no sanitised capture
  // exists for this site. An empty table forwards nothing, so the parser above
  // is unreachable in production and its suite is what exercises it.
  //
  // ONE FURTHER THING BLOCKS DECLARING BOTH ROUTES AT ONCE, and it is an
  // interface limit rather than a missing observation. `parseStream()` is
  // passed no URL, so an adapter cannot tell which of its own endpoints
  // produced the stream it is reading — and these two routes do not share a
  // parser, because one is HTML frames and the other is SSE. Until the matched
  // endpoint reaches the parsers, this adapter can serve at most one of them.
  endpoints: [],
  requiredPaths: { request: [], response: [] },
  // No endpoint is declared above, so no fixture exists for the sanitiser to
  // preserve anything in — an empty array is the honest state until one does.
  protocolTokens: [],
  // The anonymous turn's own request body was never observed: the diagnostic
  // that captured the stream recorded no request half, and the form-urlencoded
  // body the survey did read belongs to the `prepare` call rather than to the
  // turn. This reads no key and never claims the shape is met — returning
  // `requiredPathsSeen: true` while reading nothing would be vacuously true,
  // and it is the one boolean the bridge trusts to detect outbound drift.
  parseRequest: () => ({ requiredPathsSeen: false }),
  parseStream: createChatgptAnonymousAssembler,
};
