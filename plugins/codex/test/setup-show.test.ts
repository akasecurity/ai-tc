import { describe, expect, it } from 'vitest';

import { fenced, show } from '../src/present.ts';
import { frameJsonBlock } from '../src/setup-frame-json.ts';
import { parseSurface, readShowBlocks, showBlock } from '../src/setup-show.ts';

describe('showBlock / readShowBlocks', () => {
  it('round-trips a body through the delimited block', () => {
    expect(readShowBlocks(showBlock('hello card'))).toEqual(['hello card']);
  });

  it('preserves a fenced multi-line body verbatim', () => {
    const card = '```\n● AKA\n  line two\n```';
    expect(readShowBlocks(showBlock(card))).toEqual([card]);
  });

  it('extracts every block when several are present amid other copy', () => {
    const stdout = `${showBlock('one')}Plan saved to: /tmp/x\n${showBlock('two')}`;
    expect(readShowBlocks(stdout)).toEqual(['one', 'two']);
  });

  it('returns [] when no block is present', () => {
    expect(readShowBlocks('just a status line, no markers')).toEqual([]);
  });

  it('ignores a block whose end marker is missing (never throws)', () => {
    expect(readShowBlocks('<<<AKA_SHOW\nunterminated')).toEqual([]);
  });
});

describe('parseSurface — three-region partition', () => {
  it('splits show regions, frames, and status with no overlap', () => {
    const stdout =
      show(fenced('● card headline')) +
      frameJsonBlock({ counts: { important: 2 } }) +
      '\nPlan saved to: /tmp/plan.json\n';
    const surface = parseSurface(stdout);

    expect(surface.shows).toEqual(['```\n● card headline\n```']);
    expect(surface.frames).toEqual([{ counts: { important: 2 } }]);
    // Status is the untagged remainder only — never the card text or a marker.
    expect(surface.status).toContain('Plan saved to: /tmp/plan.json');
    expect(surface.status).not.toContain('card headline');
    expect(surface.status).not.toContain('AKA_SHOW');
    expect(surface.status).not.toContain('AKA_FRAME_JSON');
  });

  it('show() delegates to showBlock (same delimiters)', () => {
    expect(show('x')).toBe('<<<AKA_SHOW\nx\nAKA_SHOW>>>\n');
  });

  it('does not leak marker-shaped text inside a frame payload into shows', () => {
    const stdout = frameJsonBlock({ note: '<<<AKA_SHOW\nx\nAKA_SHOW>>>' });
    const surface = parseSurface(stdout);

    expect(surface.frames).toEqual([{ note: '<<<AKA_SHOW\nx\nAKA_SHOW>>>' }]);
    expect(surface.shows).toEqual([]);
  });

  it('keeps untagged status text that follows an unterminated show marker', () => {
    const stdout = '<<<AKA_SHOW\nunterminated\nPlan saved to: /tmp/plan.json\n';
    const surface = parseSurface(stdout);

    expect(surface.status).toContain('Plan saved to: /tmp/plan.json');
    expect(surface.shows).toEqual([]);
  });
});
