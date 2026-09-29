// Trend bench: the slow path's cost on BENIGN input that legitimately
// carries \p{Cf} characters but no secret — a UTF-8 BOM, ZWJ inside combined
// emoji, ZWNJ inside Persian/Indic words, and soft hyphens in exported HTML.
// Like the rest of bench/, this is advisory and never gates a merge (see
// CONTRIBUTING.md); the nightly job collects it as a trend. `engine.ts`'s
// scan() comment cites this file as the evidence behind not windowing the
// slow path's second matcher pass.
import { bench, describe } from 'vitest';

import { scan } from '../src/index.ts';
import { BOM, SOFT_HYPHEN, ZWJ, ZWNJ } from '../test/helpers/format-chars.ts';
import { discoverBundledRuleFiles, loadRule } from '../test/helpers/rules.ts';

const RULES = discoverBundledRuleFiles().map(({ packDirAbs, ruleFile }) =>
  loadRule(packDirAbs, ruleFile),
);

function prose(chars: number): string {
  const words = [
    'refactor',
    'the',
    'session',
    'handler',
    'so',
    'a',
    'retry',
    'never',
    'reopens',
    'store',
    'and',
    'move',
    'walk',
    'off',
    'thread',
    'before',
    'deadline',
    'returns',
  ];
  const parts: string[] = [];
  let length = 0;
  let i = 0;
  while (length < chars) {
    const word = words[i % words.length] ?? 'the';
    parts.push(word);
    length += word.length + 1;
    i += 1;
  }
  return parts.join(' ');
}

function withLeadingBom(chars: number): string {
  return BOM + prose(chars);
}

// A family emoji (man, woman, girl, boy) is FOUR base emoji joined by THREE
// ZWJ characters — realistic chat-prompt content, not a contrived worst case.
const FAMILY_EMOJI = `\u{1F468}${ZWJ}\u{1F469}${ZWJ}\u{1F467}${ZWJ}\u{1F466}`;

function withZwjEmoji(chars: number): string {
  const base = prose(chars);
  // Splice two family-emoji sequences into the middle rather than appending
  // extra text, so this case's total length matches the other cases' and the
  // comparison is about the format characters, not about which case is
  // longer.
  const mid = Math.floor(base.length / 2);
  return `${base.slice(0, mid)} ${FAMILY_EMOJI} ${base.slice(mid)} ${FAMILY_EMOJI}`;
}

// ZWNJ inside an ordinary Persian compound word ("می‌روم", "I go").
const PERSIAN_ZWNJ_WORD = `می${ZWNJ}روم`;

function withPersianZwnj(chars: number): string {
  const parts: string[] = [];
  let length = 0;
  while (length < chars) {
    parts.push(PERSIAN_ZWNJ_WORD);
    length += PERSIAN_ZWNJ_WORD.length + 1;
  }
  return parts.join(' ');
}

function withSoftHyphens(chars: number): string {
  const base = prose(chars);
  // A soft hyphen after every ~8 characters, roughly matching how an HTML
  // export inserts them at word-wrap points.
  return base.replace(/(\S{8})/g, `$1${SOFT_HYPHEN}`);
}

const CASES: readonly (readonly [string, string])[] = [
  ['2 KB, leading BOM', withLeadingBom(2_048)],
  ['100 KB, leading BOM', withLeadingBom(100_000)],
  ['2 KB, ZWJ family emoji', withZwjEmoji(2_048)],
  ['100 KB, ZWJ family emoji', withZwjEmoji(100_000)],
  ['2 KB, Persian ZWNJ prose', withPersianZwnj(2_048)],
  ['100 KB, Persian ZWNJ prose', withPersianZwnj(100_000)],
  ['2 KB, HTML soft hyphens', withSoftHyphens(2_048)],
  ['100 KB, HTML soft hyphens', withSoftHyphens(100_000)],
];

describe('scan — benign format characters, no secret', () => {
  for (const [label, text] of CASES) {
    bench(label, () => {
      scan(text, RULES);
    });
  }
});
