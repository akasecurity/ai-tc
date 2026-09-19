/**
 * The archive names the binary release WRITES, held equal to the ones the
 * package-manager manifests NAME.
 *
 * Two files decide one thing between them: `cli/scripts/archive-sea.mjs` names
 * each archive and its single top-level directory, and
 * `tools/package-manifests/src/lib.ts` renders a Homebrew formula and a Scoop
 * manifest that point at those names. Nothing else connects them — the renderer
 * reads a SHA256SUMS that the archiver's own output produced, so a renamed
 * asset leaves both packages' suites green and every published url 404s.
 *
 * It lives here because only this package's turbo `inputs` hash both files. The
 * same check inside either one would replay a cached green while the other
 * moved.
 *
 * The comparison is of NAMES, not of source text: the two literals are written
 * differently on purpose (the archiver already holds an `isWin` flag, the
 * renderer derives the same split from the triple), so asserting the strings
 * are equal would be red on day one. Each literal is evaluated instead, with
 * the variables its own file binds, and the resulting filename compared.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { assetName, extractDirName, TRIPLES } from '../../../tools/package-manifests/src/lib.ts';

const REPO_ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const ARCHIVER_REL = 'cli/scripts/archive-sea.mjs';
const ARCHIVER = readFileSync(join(REPO_ROOT, ARCHIVER_REL), 'utf8');

const VERSION = '9.9.9';

/**
 * The text of a template literal assigned to `const <name>` in the archiver,
 * without its backticks.
 * @param {string} name
 * @returns {string}
 */
function templateLiteral(name) {
  // Anchored at a line start and required exactly once, so a commented-out or
  // quoted copy of the literal cannot stand in for the declaration.
  const found = [...ARCHIVER.matchAll(new RegExp(`^const ${name} = \`([^\`]*)\`;$`, 'gm'))];
  expect(
    found,
    `${ARCHIVER_REL} declares \`const ${name} = \\\`…\\\`\` other than exactly once`,
  ).toHaveLength(1);
  const body = found[0]?.[1] ?? '';
  expect(body, `${ARCHIVER_REL}'s ${name} template is empty`).not.toBe('');
  return body;
}

/**
 * That literal's value, with the archiver's own variables bound.
 * @param {string} literal
 * @param {Record<string, string | boolean>} scope
 * @returns {string}
 */
function evaluate(literal, scope) {
  const names = Object.keys(scope);
  // The input is a template literal read out of a tracked file in this
  // repository, evaluated so the NAME it produces can be compared rather than
  // its spelling.
  const build = new Function(...names, `return \`${literal}\`;`);
  return String(build(...names.map((key) => scope[key])));
}

/**
 * The initializer of a one-line `const <name> = …;` in the archiver.
 * @param {string} name
 * @returns {string}
 */
function initializer(name) {
  const found = [...ARCHIVER.matchAll(new RegExp(`^const ${name} = (.+);$`, 'gm'))];
  expect(found, `${ARCHIVER_REL} declares \`const ${name}\` other than exactly once`).toHaveLength(
    1,
  );
  return found[0]?.[1] ?? '';
}

/**
 * What the archiver's own `triple` and `isWin` come to on the machine that
 * builds `triple`, from the `platform` and `arch` that machine reports.
 * @param {string} triple
 * @returns {{ triple: string, isWin: boolean }}
 */
function archiverBindings(triple) {
  const dash = triple.indexOf('-');
  expect(dash, `${triple} carries no platform-arch separator`).toBeGreaterThan(0);
  const scope = { platform: triple.slice(0, dash), arch: triple.slice(dash + 1) };
  const names = Object.keys(scope);
  const values = names.map((key) => scope[/** @type {'platform' | 'arch'} */ (key)]);
  const derive = (/** @type {string} */ expression) =>
    new Function(...names, `return (${expression});`)(...values);
  return {
    triple: String(derive(initializer('triple'))),
    isWin: Boolean(derive(initializer('isWin'))),
  };
}

describe('the archive names the release writes and the manifests name', () => {
  it('reads all three templates out of the archiver', () => {
    // Without this the three cases below would each pass on an empty literal.
    expect(templateLiteral('archiveName')).toContain('${triple}');
    expect(templateLiteral('stagedName')).toContain('${triple}');
    expect(templateLiteral('line')).toContain('${archiveName}');
    expect(TRIPLES.length).toBe(4);
  });

  it("derives each build's triple and archive kind the way the renderer does", () => {
    const windows = TRIPLES.filter((triple) => archiverBindings(triple).isWin);
    expect(windows).toEqual(['win32-x64']);
    for (const triple of TRIPLES) {
      expect(archiverBindings(triple).triple, triple).toBe(triple);
    }
  });

  it('names each archive exactly as the renderer expects', () => {
    const literal = templateLiteral('archiveName');
    for (const triple of TRIPLES) {
      const written = evaluate(literal, { version: VERSION, ...archiverBindings(triple) });
      expect(written, triple).toBe(assetName(VERSION, triple));
    }
  });

  it('stages each archive under the directory the Scoop manifest extracts from', () => {
    const literal = templateLiteral('stagedName');
    for (const triple of TRIPLES) {
      const staged = evaluate(literal, { triple: archiverBindings(triple).triple });
      expect(staged, triple).toBe(extractDirName(triple));
    }
  });

  it('separates the hash from the filename with exactly two spaces', () => {
    // What the installers and Scoop's own hash extraction read off each line.
    const sha = 'a'.repeat(64);
    const archiveName = assetName(VERSION, 'win32-x64');
    const rendered = evaluate(templateLiteral('line'), { sha, archiveName });

    const nameAt = rendered.indexOf(archiveName);
    expect(nameAt, `the rendered sums line does not carry ${archiveName}`).toBeGreaterThan(-1);
    expect(rendered.startsWith(sha)).toBe(true);
    expect(rendered.slice(sha.length, nameAt)).toBe('  ');
    expect(rendered.endsWith('\n')).toBe(true);
  });
});
