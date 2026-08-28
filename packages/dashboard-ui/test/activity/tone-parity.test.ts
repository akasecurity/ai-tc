import { TONE_PARTS } from '@akasecurity/ui-kit';
import { describe, expect, it } from 'vitest';

import { EVENT_META } from '../../src/activity/meta.ts';

// EVENT_META spreads its tonal halves from the shared registry, so what a row
// means is now a family NAME. The names were never pinned while the pairs were
// written out here; this is where they are, so re-toning a row is a deliberate
// edit rather than something a spread quietly carries.
const EXPECTED = {
  session: 'muted',
  prompt: 'primary',
  response: 'violet',
  tool: 'muted',
  hook: 'low',
  detection: 'critical',
  share: 'teal',
  permission: 'high',
  commit: 'muted',
  error: 'critical',
  active: 'primary',
} as const;

describe('the timeline node tones', () => {
  it('covers every event kind exactly', () => {
    expect(Object.keys(EVENT_META).sort()).toEqual([...Object.keys(EXPECTED)].sort());
  });

  for (const [kind, family] of Object.entries(EXPECTED)) {
    it(`${kind} carries the ${family} pair, both halves`, () => {
      const { text, fill } = EVENT_META[kind as keyof typeof EVENT_META];
      // Both halves against ONE family: a row taking its fill from one and its
      // ink from another is the crossed pair this spread exists to prevent.
      expect({ text, fill }).toEqual({
        text: TONE_PARTS[family].text,
        fill: TONE_PARTS[family].fill,
      });
    });
  }
});
