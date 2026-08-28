import { readFileSync } from 'node:fs';
import { readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ATTACHED_DERIVED_FILENAMES } from '@akasecurity/persistence';
import { describe, expect, it } from 'vitest';

/**
 * The detach list's central promise, checked rather than asked for.
 *
 * `ATTACHED_DERIVED_FILENAMES` says a fifth derived file joins both detach
 * paths by being added to it. That was hand-maintained in a docblock, and the
 * shape it could not catch is the one that had already happened: a writer
 * spelling its filename as a literal is invisible to the list, so a rename
 * typechecks clean while detach stops clearing the file and the writer goes on
 * writing it under the old name — with every suite green.
 *
 * This is the runtime half. A writer under `attached/` names its file through a
 * `*_FILENAME` constant, and every such constant must BE one of the names both
 * detach surfaces clear.
 */
const attachedDir = fileURLToPath(new URL('../../src/attached/', import.meta.url));

describe('the attached runtime writes only files a detach clears', () => {
  it('exports no *_FILENAME constant the detach list does not carry', async () => {
    const modules = (await readdir(attachedDir)).filter((f) => f.endsWith('.ts'));
    // A positive control on the walk itself: an empty or mis-resolved directory
    // would satisfy every assertion below by iterating nothing.
    expect(modules.length).toBeGreaterThan(10);

    const found: [string, string, string][] = [];
    for (const file of modules) {
      // `unknown` rather than a typed annotation: a dynamic import of a
      // computed path is `any`, and narrowing it here keeps that off everything
      // below.
      const imported: unknown = await import(join(attachedDir, file));
      if (typeof imported !== 'object' || imported === null) continue;
      for (const [name, value] of Object.entries(imported)) {
        if (name.endsWith('_FILENAME') && typeof value === 'string') {
          found.push([file, name, value]);
        }
      }
    }

    // The control that matters: the three re-exporting writers are why this
    // reads green, so a refactor that stopped exporting them would leave the
    // assertion below true over an empty set.
    expect(found.length).toBeGreaterThanOrEqual(3);

    for (const [file, name, value] of found) {
      expect(ATTACHED_DERIVED_FILENAMES, `${file} exports ${name}=${value}`).toContain(value);
    }
  });

  it('has no writer naming a derived file as a literal', async () => {
    // The other direction, and the defect this suite was written for. A
    // constant that agrees with the list proves nothing about a sibling that
    // never reads it: `policy-store.ts` carried `join(dir, 'policy-cache.json')`
    // while the list sat one import away, so the rename case was unguarded for
    // exactly the file the list calls most consequential to leave behind.
    const modules = (await readdir(attachedDir)).filter((f) => f.endsWith('.ts'));
    const offenders: string[] = [];
    for (const file of modules) {
      const source = readFileSync(join(attachedDir, file), 'utf8');
      // Comments carry these names on purpose (the module headers explain what
      // each file is), so only a quoted literal counts.
      for (const name of ATTACHED_DERIVED_FILENAMES) {
        if (source.includes(`'${name}'`) || source.includes(`"${name}"`)) {
          offenders.push(`${file} spells '${name}' as a literal instead of importing its constant`);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
