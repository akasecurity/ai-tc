import { describe, expect, it } from 'vitest';

import { CardIcon } from '../src/card.tsx';
import { type Tone, TONE_SOFT } from '../src/tone.ts';

// `tone` is optional on a component this package ships to hosts outside this
// repo, so a stale or plain-JS caller can pass a value outside the union. An
// unguarded index yields `undefined`, `cn` drops it, and the tile renders with
// no background AND no foreground — worse than a wrong colour, because it reads
// as a layout bug rather than a data one.
function classesOf(tone?: string): string[] {
  const el = CardIcon({ tone: tone as Tone }) as { props: { className: string } };
  return el.props.className.split(' ');
}

describe('CardIcon resolves its tone', () => {
  // The positive control: without it every fallback case below would also pass
  // on a CardIcon that had stopped emitting a tonal pair at all.
  it.each(Object.keys(TONE_SOFT) as Tone[])('carries %s’s own pair', (tone) => {
    for (const cls of TONE_SOFT[tone].split(' ')) expect(classesOf(tone)).toContain(cls);
  });

  it('defaults to neutral when no tone is given', () => {
    for (const cls of TONE_SOFT.neutral.split(' ')) expect(classesOf()).toContain(cls);
  });

  // 'muted' was a real member until the neutral retone, so a stale caller can
  // still send it; the prototype members are the pair that defeats a bare
  // `?? TONE_SOFT.neutral`, since each resolves a truthy INHERITED value.
  it.each(['not-a-tone', '', 'muted', '__proto__', 'constructor', 'toString'])(
    'falls back to the neutral pair for %j',
    (tone) => {
      for (const cls of TONE_SOFT.neutral.split(' ')) expect(classesOf(tone)).toContain(cls);
    },
  );

  it('never emits an object or an empty slot as a class', () => {
    const classes = classesOf('__proto__');

    expect(classes).not.toContain('');
    expect(classes.join(' ')).not.toContain('[object');
  });
});
