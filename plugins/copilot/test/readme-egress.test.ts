/**
 * The README's `[^egress]` footnote, checked against the shipped bundle.
 *
 * `plugins/claude-code/test/privacy-claims.test.ts` holds this page's locality
 * claims to their qualifier, and the device-wide sentences every scoped page
 * shares. What it cannot hold is whether the paths this page names are the ones
 * THIS plugin's built scripts can take: its artifact tier reads the Claude Code
 * bundle, and that plugin ships a judge this one does not. So the list lives
 * here, beside the scripts it describes, and runs in both directions:
 *
 *   - every path the footnote counts is in a built script, and the count word
 *     is derived from that list rather than written by hand;
 *   - every path the other front doors disclose and this bundle lacks is named
 *     nowhere in the footnote, and is absent from every built script, so a
 *     build that starts shipping one goes red until the page discloses it.
 *
 * `global-setup.ts` builds `scripts/` before any worker runs, so the bundle is
 * the one this commit produces rather than whatever a previous build left.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const PLUGIN_ROOT = fileURLToPath(new URL('../', import.meta.url));

const readme = readFileSync(join(PLUGIN_ROOT, 'README.md'), 'utf8');
const footnote = readme
  .split('\n')
  .filter((line) => /^\[\^[^\]]+]:/.test(line))
  .join(' ')
  .replace(/\s+/g, ' ');

const scriptsDir = join(PLUGIN_ROOT, 'scripts');
const bundles = readdirSync(scriptsDir)
  .filter((f) => f.endsWith('.js'))
  .map((f) => ({ name: f, text: readFileSync(join(scriptsDir, f), 'utf8') }));

/**
 * The paths this plugin's bundle can take off the machine. One today: the
 * attached control plane, whose transport is `@akasecurity/remote`'s
 * `node:https` client — bundled as a dynamic `import("https")`.
 */
const SHIPPED_PATHS = [
  { name: 'attached control plane', readme: /`aka attach`/, bundle: /import\("https"\)/ },
] as const;

/**
 * Paths another front door discloses that this bundle does not carry. The
 * footnote must not name their mechanism, and no built script may contain it.
 */
const ABSENT_PATHS = [
  {
    name: 'setup calibration judge',
    readme: /\/aka:setup|claude -p|codex exec|\bagy\b/,
    bundle: /CLAUDE_CODE_SKIP_PROMPT_HISTORY|"--ephemeral"|stream-json/,
  },
  { name: 'update notice', readme: /npm view/, bundle: /dist-tags/ },
  { name: 'supply-chain check', readme: /audit signatures/, bundle: /audit signatures/ },
] as const;

const COUNT_WORDS = ['Zero', 'One', 'Two', 'Three', 'Four'] as const;

describe('README egress footnote', () => {
  it('has bundles to read, and the search can find code known to be there', () => {
    expect(bundles.length).toBeGreaterThan(5);
    expect(bundles.some((b) => b.text.includes('runAttachedSync'))).toBe(true);
  });

  it('has an egress footnote', () => {
    expect(footnote).toContain('[^egress]:');
  });

  it('counts the paths it lists', () => {
    const word = COUNT_WORDS[SHIPPED_PATHS.length];
    expect(word).toBeDefined();
    expect(footnote).toMatch(new RegExp(`\\b${word} narrow paths? can send`, 'i'));
  });

  it.each(SHIPPED_PATHS)(
    'names the $name path, and the bundle carries it',
    ({ readme, bundle }) => {
      expect(footnote).toMatch(readme);
      expect(bundles.some((b) => bundle.test(b.text))).toBe(true);
    },
  );

  it.each(ABSENT_PATHS)('names no $name, and no built script carries one', ({ readme, bundle }) => {
    expect(footnote).not.toMatch(readme);
    expect(bundles.filter((b) => bundle.test(b.text)).map((b) => b.name)).toEqual([]);
  });

  it('says there is no judge', () => {
    expect(footnote).toMatch(/no judge step/);
  });

  // The content-retention child is spawned on a standalone machine, so it must
  // stay local-only for the count above to hold.
  it('keeps the content-retention child off the network', () => {
    const retention = bundles.find((b) => b.name === 'content-retention.js');
    expect(retention).toBeDefined();
    expect(retention?.text).not.toMatch(/import\("https?"\)/);
  });
});
