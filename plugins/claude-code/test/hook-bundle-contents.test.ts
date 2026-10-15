// What every hook script carries, read from the BUILT bundles the manifest
// names. Each hook is a fresh node process per call, so whatever a bundle holds
// is parsed and evaluated on every tool call whether or not the call needs it.
//
// The case pinned here is zod's locale catalogue. `import { z } from 'zod'`
// reaches zod's namespace through a re-export, which the bundler can only keep
// whole: every locale, the JSON-schema converters and the rest came along,
// roughly 0.5 MB per hook. `import * as z from 'zod'` lets each property access
// resolve to the one export it names, so only what the schemas use is bundled.
// A file switching back to the named form brings the whole catalogue back with
// nothing else failing, which is why this reads the artifact.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const packageRoot = fileURLToPath(new URL('../', import.meta.url));

interface HooksManifest {
  hooks: Record<string, { hooks: { command: string }[] }[]>;
}

const manifest = JSON.parse(
  readFileSync(join(packageRoot, 'hooks', 'hooks.json'), 'utf8'),
) as HooksManifest;

/**
 * The bundle behind every script a registered hook command runs. The command
 * runs `<name>.js`, a launcher that loads `<name>.body.js`, so the body is what
 * carries the hook's code.
 */
const hookScripts = [
  ...new Set(
    Object.values(manifest.hooks)
      .flat()
      .flatMap((entry) => entry.hooks)
      .flatMap(({ command }) =>
        [...command.matchAll(/scripts\/([\w-]+)\.js/g)].map((m) => `${String(m[1])}.body.js`),
      ),
  ),
];

// The bundler marks where each bundled module starts with a path comment; the
// locale files all live under one directory.
const LOCALE_MODULE = /^\/\/ .*\/zod\/v4\/locales\/([\w-]+)\.js$/gm;
const ZOD_CORE_MODULE = /^\/\/ .*\/zod\/v4\/core\/core\.js$/m;

describe('the hook bundles carry only the zod they use', () => {
  it('finds the hook scripts the manifest runs', () => {
    expect(hookScripts).toEqual(
      expect.arrayContaining(['pre-tool-use.body.js', 'post-tool-use.body.js', 'stop.body.js']),
    );
  });

  it.each(hookScripts)('%s bundles no zod locale beyond the default one', (script) => {
    const source = readFileSync(join(packageRoot, 'scripts', script), 'utf8');
    // The control: zod is bundled and its module markers are present, so an
    // absence below is a fact about the bundle rather than about a minified one.
    expect(source).toMatch(ZOD_CORE_MODULE);
    const locales = [...source.matchAll(LOCALE_MODULE)].map((m) => m[1]);
    expect(locales.filter((name) => name !== 'en')).toEqual([]);
  });
});
