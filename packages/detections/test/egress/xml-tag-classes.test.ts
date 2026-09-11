import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

// XML_TAG's linearity rests on a relationship between two character classes
// that the pattern spells SEPARATELY: the tag name's tail class, and the class
// the attribute blob is required to start with. They must stay exact
// complements of each other (within `[^<>]`). If the name class is ever widened
// — allowing `:` for namespaced tags, say — and the other is not changed in
// step, the two stop partitioning and the pattern silently starts REJECTING
// tags it used to match. That is a recall regression with no output to inspect:
// the extraction simply returns fewer hits, and every fixture that does not
// happen to use the new character stays green.
//
// So the classes are READ OUT OF THE SOURCE rather than restated here. A test
// carrying its own copies would agree with itself for ever while the pattern
// drifted away from both.
const source = readFileSync(
  fileURLToPath(new URL('../../src/egress/manifests.ts', import.meta.url)),
  'utf8',
);

const XML_TAG_LINE = /^const XML_TAG = \/(.*)\/g;$/m;

describe("XML_TAG's two character classes still partition", () => {
  const declaration = XML_TAG_LINE.exec(source)?.[1];

  it('finds the pattern it is about to take apart', () => {
    // Guards the extraction itself: a missed match makes `declaration`
    // undefined, and every assertion below would then be about nothing.
    expect(
      declaration,
      'XML_TAG is no longer declared as a single-line `const XML_TAG = /…/g;` in manifests.ts, ' +
        'so this guard can no longer read its character classes. Update the reader.',
    ).toBeDefined();
  });

  it('lets the attribute blob begin with exactly the characters the name cannot continue with', () => {
    // `[A-Za-z][<tail>]*` and `(?:[<opener>][^<>]*)?` — the tail of the name
    // class, and the class the attribute blob may open with.
    const tail = /\[A-Za-z\]\[([^\]]+)\]\*/.exec(declaration ?? '')?.[1];
    const opener = /\(\?:\[\^<>([^\]]+)\]/.exec(declaration ?? '')?.[1];
    expect(tail, 'could not read the tag-name tail class out of XML_TAG').toBeDefined();
    expect(opener, 'could not read the attribute-opener class out of XML_TAG').toBeDefined();
    // The opener is written as a NEGATED class that also excludes `<` and `>`,
    // so what it excludes beyond those must be exactly the name's tail.
    expect(
      opener,
      `XML_TAG's attribute blob may open with anything outside [^<>${String(opener)}], while a tag ` +
        `name continues with [${String(tail)}]. Those two must be complements: a character in ` +
        `both makes the split point ambiguous again and the pattern quadratic, and a character ` +
        `in neither makes the pattern reject a tag it used to match.`,
    ).toBe(tail);
  });

  it('partitions every character a tag can actually carry', () => {
    // Behavioural half, in case the two literals are written differently but
    // mean the same thing (`\w` against `A-Za-z0-9_`, say). Every character
    // outside `<>` must be accepted by exactly one of the two classes.
    const tail = /\[A-Za-z\]\[([^\]]+)\]\*/.exec(declaration ?? '')?.[1] ?? '';
    const opener = /\(\?:(\[\^<>[^\]]+\])/.exec(declaration ?? '')?.[1] ?? '';
    const tailClass = new RegExp(`^[${tail}]$`);
    const openerClass = new RegExp(`^${opener}$`);

    // Written out rather than spread from a string: spreading iterates code
    // points, which the workspace bans for the surrogate-pair confusion it
    // invites, and every entry here has to be exactly one character anyway.
    const sample = [
      // name characters
      'a',
      'z',
      'A',
      'Z',
      '0',
      '9',
      '_',
      '.',
      '-',
      // separators and attribute syntax
      ' ',
      '\t',
      '"',
      "'",
      '=',
      '/',
      // punctuation a tag can carry, including the namespace colon
      ':',
      ';',
      ',',
      '?',
      '!',
      '$',
      '%',
      '&',
      '*',
      '(',
      ')',
      '[',
      ']',
      '{',
      '}',
      '|',
      '\\',
      '@',
      '#',
      '+',
      '~',
      '^',
      '`',
      // non-ASCII, which `\w` does not cover
      'é',
      '\u4e2d',
    ];
    const both = sample.filter((c) => tailClass.test(c) && openerClass.test(c));
    const neither = sample.filter((c) => !tailClass.test(c) && !openerClass.test(c));

    expect(
      both,
      'these characters are accepted by BOTH classes, so the split between the tag name and its ' +
        'attributes is ambiguous again and the pattern can backtrack quadratically',
    ).toEqual([]);
    expect(
      neither,
      'these characters are accepted by NEITHER class, so a tag whose name is followed by one is ' +
        'no longer matched at all — the extraction silently loses those hits',
    ).toEqual([]);
  });
});
