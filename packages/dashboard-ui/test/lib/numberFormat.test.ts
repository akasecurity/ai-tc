import { execFileSync } from 'node:child_process';

import { describe, expect, it } from 'vitest';

import { compactCount, numberFormat } from '../../src/lib/numberFormat.ts';

/**
 * The child's own deadline, and the budget the case that spawns it runs under.
 *
 * The child's has to sit well BELOW the case's, or vitest wins the race: it kills
 * the test and reports a bare timeout, losing the try/catch that would otherwise
 * turn a slow or unstartable host into an honest skip. This package declares no
 * testTimeout, so the default is 5s — too close to a spawn that can take seconds
 * on a loaded runner — which is why the case carries an explicit budget.
 */
const CHILD_TIMEOUT_MS = 5_000;
const CASE_TIMEOUT_MS = 20_000;

/**
 * What this module formats when the HOST's default locale is something else.
 *
 * It has to be a child process: Intl resolves its default locale once, when the
 * runtime starts, so nothing a test does in-process can change it. And it has to
 * be changed at all, because on an en-US runner a pinned formatter and an
 * unpinned one produce identical output — an in-process assertion here is green
 * whether or not the locale is pinned, which is what the case this replaced
 * turned out to be.
 *
 * The child is given ONLY the two locale variables, never the parent's
 * environment: reading `process.env` is banned across this workspace, and
 * nothing the child does needs anything else (it is spawned by absolute path and
 * imports one local module). A host where that bare environment cannot start a
 * process returns null, and the caller skips rather than reddening.
 */
function formatUnder(
  lang: string,
): { pinned: string; compact: string; hostDefault: string } | null {
  const spec = new URL('../../src/lib/numberFormat.ts', import.meta.url).href;
  try {
    const out = execFileSync(
      process.execPath,
      [
        '-e',
        `import(process.argv[1]).then((m) => process.stdout.write(JSON.stringify({
           pinned: m.numberFormat.format(1234),
           compact: m.compactCount(1234),
           hostDefault: new Intl.NumberFormat().format(1234),
         })))`,
        spec,
      ],
      { env: { LANG: lang, LC_ALL: lang }, encoding: 'utf8', timeout: CHILD_TIMEOUT_MS },
    );
    return JSON.parse(out) as { pinned: string; compact: string; hostDefault: string };
  } catch {
    return null;
  }
}

describe('numberFormat', () => {
  it('groups thousands', () => {
    expect(numberFormat.format(1234)).toBe('1,234');
    expect(numberFormat.format(486)).toBe('486');
  });

  // The property that makes both formatters usable in a client component: the
  // same string on the server and in the browser. An unpinned formatter reads
  // each renderer's OWN locale, so a Node host on en-US emits `1,234` where a
  // de-DE browser hydrates `1.234` — and passing a render instant reconciles a
  // clock and does nothing for this.
  //
  // The host's own default is the CONTROL. Without it this case cannot fail on a
  // runner that already defaults to en-US, which is every runner this repo uses:
  // an in-process assertion that `numberFormat.format(1234)` is '1,234' is green
  // whether or not the locale is pinned.
  it(
    'formats the same under a host locale that is not en-US',
    { timeout: CASE_TIMEOUT_MS },
    (ctx) => {
      const de = formatUnder('de_DE.UTF-8');
      // Two ways a host cannot answer this: it could not start the child at all,
      // or it started one that ignored LANG — and on the second, a pinned and an
      // unpinned formatter agree, so there is nothing here to observe. Skipping
      // says so; a pass would claim a check that never ran. The `return` is
      // unreachable (ctx.skip throws) and is what narrows `de` below.
      if (de === null || de.hostDefault === '1,234') {
        ctx.skip(
          de === null
            ? 'this host could not start a child with a bare environment'
            : 'this host ignored LANG, so a pinned and an unpinned formatter agree here',
        );
        return;
      }
      expect(de.hostDefault).toBe('1.234');
      expect(de.pinned).toBe('1,234');
      // The compact form rides the same pin, and its decimal separator is the
      // half that would move.
      expect(de.compact).toBe('1.2k');
    },
  );
});

describe('compactCount', () => {
  it('leaves anything under a thousand alone', () => {
    expect(compactCount(0)).toBe('0');
    expect(compactCount(1)).toBe('1');
    expect(compactCount(486)).toBe('486');
    expect(compactCount(999)).toBe('999');
  });

  it('shortens thousands, millions and billions', () => {
    expect(compactCount(1000)).toBe('1k');
    expect(compactCount(1234)).toBe('1.2k');
    expect(compactCount(1496)).toBe('1.5k');
    expect(compactCount(12345)).toBe('12k');
    expect(compactCount(123456)).toBe('123k');
    expect(compactCount(1234567)).toBe('1.2m');
    expect(compactCount(1500000000)).toBe('1.5b');
  });

  it('is lowercase, where Intl is not', () => {
    // The thing being pinned: Intl emits '1.2K', and the dashboard's terse forms
    // are lowercase. Asserting the Intl output too keeps this honest if the
    // platform ever changes its casing.
    expect(new Intl.NumberFormat('en-US', { notation: 'compact' }).format(1234)).toBe('1.2K');
    expect(compactCount(1234)).toBe('1.2k');
    expect(compactCount(1234)).not.toMatch(/[A-Z]/);
  });

  // Why every caller owes an exact number somewhere else. These two round ACROSS
  // the boundary, so the short form names a magnitude the value has not reached
  // — and a reader cannot tell from '10k' that it is not ten thousand.
  it('rounds across its own boundary, which is why it is not the whole story', () => {
    expect(compactCount(9999)).toBe('10k');
    expect(compactCount(999999)).toBe('1m');
  });
});
