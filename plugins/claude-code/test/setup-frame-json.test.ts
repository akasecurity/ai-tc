import { describe, expect, it } from 'vitest';

import { frameJsonBlock, readFrameJsonBlock } from '../src/setup-frame-json.ts';

describe('frameJsonBlock / readFrameJsonBlock', () => {
  it('round-trips a payload through the delimited block', () => {
    const payload = { worthALook: 2, options: [] };
    const block = readFrameJsonBlock(frameJsonBlock(payload));
    expect(block).toEqual(payload);
  });

  it('extracts the block even when surrounded by human-readable copy', () => {
    const stdout = `some card\n${frameJsonBlock({ a: 1 })}trailing note\n`;
    expect(readFrameJsonBlock(stdout)).toEqual({ a: 1 });
  });

  it('returns undefined when no block is present', () => {
    expect(readFrameJsonBlock('just a plain card, no frame here')).toBeUndefined();
  });

  it('returns undefined (never throws) when the block contents are malformed JSON', () => {
    const broken = '<<<AKA_FRAME_JSON\n{ not: valid json ]\nAKA_FRAME_JSON>>>\n';
    expect(readFrameJsonBlock(broken)).toBeUndefined();
  });
});
