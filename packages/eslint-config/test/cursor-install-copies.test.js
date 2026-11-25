import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { inputsOf, jobOf, parseWorkflow, stepNamed } from './helpers/workflow-yaml.js';

const require = createRequire(import.meta.url);
/** @type {import('typescript')} */
const ts = require('typescript');

// The Cursor plugin has no marketplace, so a user installs it by typing shell
// commands copied from whichever page they read first. The plugin README's
// "## Install" section is the reference for those commands, and three copies
// are compared against it: llms.txt, the registry hint and the Release body.
// Each copy is reduced to its install command lines and required to equal the
// reference's, so a copy edited on its own goes red here. Each copy must also
// name the uninstall command, which the copies state in prose or a fence.
//
// Only commands are compared, never the prose around them: the copies explain
// the steps at different lengths on purpose, and the commands are what a user
// pastes.

const README = 'plugins/cursor/README.md';
const LLMS = 'llms.txt';
const REGISTRY = 'packages/local-ops/src/registry.ts';
const RELEASE = '.github/workflows/release-plugin-cursor.yml';

/** The version pin the Release body carries, and nothing else may. */
const RELEASE_PIN = '@${{ steps.manifest.outputs.version }}';

const INSTALL = 'node package/scripts/install.js';
const UNINSTALL = `${INSTALL} --uninstall`;

/**
 * What marks a line as one of the install commands. `aka init` is left out:
 * the registry hint states it in prose. The uninstall line is checked on its
 * own, since only the reference carries it in a fence.
 */
const COMMAND_MARKERS = Object.freeze([
  'mkdir ',
  'npm pack @akasecurity/ai-tc-cursor',
  'tar -xzf',
  INSTALL,
]);

/** @param {string} rel */
const read = (rel) => readFileSync(join(REPO_ROOT, rel), 'utf8');

/**
 * A command line with its indentation and any shell prompt removed.
 * @param {string} line
 */
const normalize = (line) => line.trim().replace(/^[$>]\s+/u, '');

/**
 * The install command lines among `lines`, normalized, in order.
 * @param {string[]} lines
 * @returns {string[]}
 */
const commandsIn = (lines) =>
  lines
    .map(normalize)
    .filter((line) => !line.includes('--uninstall'))
    .filter((line) => COMMAND_MARKERS.some((m) => line.includes(m)));

/**
 * The text from the line `heading` opens to the next line `end` matches.
 * @param {string} text
 * @param {string} heading the exact opening line
 * @param {RegExp} end matched against each later line
 * @param {string} label
 */
function sectionOf(text, heading, end, label) {
  const lines = text.split('\n');
  const start = lines.indexOf(heading);
  expect(start, `${label} has no \`${heading}\` line`).toBeGreaterThanOrEqual(0);
  const rest = lines.slice(start + 1);
  const stop = rest.findIndex((line) => end.test(line));
  return (stop === -1 ? rest : rest.slice(0, stop)).join('\n');
}

/**
 * The lines inside fenced code blocks, indented fences included. Prose that
 * names a command in backticks is not a step and is not read.
 * @param {string} text
 * @returns {string[]}
 */
function fencedLines(text) {
  /** @type {string[]} */
  const out = [];
  let inside = false;
  for (const line of text.split('\n')) {
    if (/^\s*```/u.test(line)) {
      inside = !inside;
      continue;
    }
    if (inside) out.push(line);
  }
  expect(inside, 'a code fence is left open').toBe(false);
  return out;
}

/**
 * The value of a string literal, or of a `+` chain of them, else undefined.
 * @param {import('typescript').Expression} node
 * @returns {string | undefined}
 */
function foldStrings(node) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isParenthesizedExpression(node)) return foldStrings(node.expression);
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = foldStrings(node.left);
    const right = foldStrings(node.right);
    return left === undefined || right === undefined ? undefined : left + right;
  }
  return undefined;
}

/**
 * The `installHint` of the `AGENT_PLUGINS` entry whose `id` is `cursor`, read
 * from the registry's source text. Parsed rather than imported: this package
 * may depend on nothing in the workspace.
 * @returns {string}
 */
function registryHint() {
  const sf = ts.createSourceFile(REGISTRY, read(REGISTRY), ts.ScriptTarget.Latest, true);
  /** @type {string[]} */
  const hints = [];
  /** @param {import('typescript').Node} node */
  const visit = (node) => {
    if (ts.isObjectLiteralExpression(node)) {
      /** @type {Map<string, import('typescript').Expression>} */
      const props = new Map();
      for (const p of node.properties) {
        if (ts.isPropertyAssignment(p) && ts.isIdentifier(p.name)) {
          props.set(p.name.text, p.initializer);
        }
      }
      const idNode = props.get('id');
      const hintNode = props.get('installHint');
      if (idNode && ts.isStringLiteral(idNode) && idNode.text === 'cursor' && hintNode) {
        const hint = foldStrings(hintNode);
        expect(
          hint,
          `${REGISTRY}: the \`cursor\` installHint is no longer a string or a \`+\` chain of string literals`,
        ).toBeDefined();
        hints.push(/** @type {string} */ (hint));
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  expect(hints, `${REGISTRY} has no single \`cursor\` entry with an installHint`).toHaveLength(1);
  return hints[0];
}

/** @returns {string} */
const readmeSection = () => sectionOf(read(README), '## Install', /^## /u, README);

/** @returns {string} */
function llmsEntry() {
  const text = read(LLMS);
  const start = text.split('\n').find((line) => line.startsWith('- Cursor'));
  expect(start, `${LLMS} has no \`- Cursor\` entry`).toBeDefined();
  return sectionOf(text, /** @type {string} */ (start), /^(- |#)/u, LLMS);
}

/** @returns {string} */
function releaseBody() {
  const workflow = parseWorkflow(read(RELEASE));
  const step = stepNamed(jobOf(workflow, 'release'), 'Create GitHub Release');
  const body = inputsOf(step).body;
  expect(typeof body, `${RELEASE}: the Release step carries no body`).toBe('string');
  return /** @type {string} */ (body);
}

/** @returns {string[]} */
const referenceCommands = () => commandsIn(fencedLines(readmeSection()));

/**
 * The Release body's command lines with the version pin removed. Every `npm pack`
 * line must carry the pin, so a body that stopped pinning is red here rather
 * than quietly equal to the reference.
 * @returns {string[]}
 */
function releaseCommandsUnpinned() {
  const lines = commandsIn(fencedLines(releaseBody()));
  for (const line of lines.filter((l) => l.includes('npm pack'))) {
    expect(line, `${RELEASE}: an \`npm pack\` line does not pin the released version`).toContain(
      `npm pack @akasecurity/ai-tc-cursor${RELEASE_PIN} `,
    );
  }
  return lines.map((line) => line.split(RELEASE_PIN).join(''));
}

/**
 * Each copy's install command lines. The registry hint is printed as-is, so
 * its command lines are the indented ones.
 * @type {Record<string, () => string[]>}
 */
const COPIES = {
  [LLMS]: () => commandsIn(fencedLines(llmsEntry())),
  [REGISTRY]: () =>
    commandsIn(
      registryHint()
        .split('\n')
        .filter((line) => /^\s/u.test(line)),
    ),
  [RELEASE]: releaseCommandsUnpinned,
};

/**
 * Each copy's whole text, for the uninstall command it must name.
 * @type {Record<string, () => string>}
 */
const TEXTS = {
  [README]: readmeSection,
  [LLMS]: llmsEntry,
  [REGISTRY]: registryHint,
  [RELEASE]: releaseBody,
};

describe('Cursor install copies agree with the plugin README', () => {
  it('reads every install command out of the reference (positive control)', () => {
    const reference = referenceCommands();
    for (const marker of COMMAND_MARKERS) {
      expect(
        reference.some((line) => line.includes(marker)),
        `${README}'s Install section has no command line containing \`${marker}\``,
      ).toBe(true);
    }
  });

  it.each(Object.keys(COPIES))('%s yields command lines (positive control)', (copy) => {
    expect(COPIES[copy]().length, `${copy} yielded no install command`).toBeGreaterThan(0);
  });

  it.each(Object.keys(COPIES))('%s carries exactly the reference commands', (copy) => {
    expect(COPIES[copy](), `${copy} has drifted from ${README}`).toEqual(referenceCommands());
  });

  it.each(Object.keys(TEXTS))('%s names the uninstall command', (copy) => {
    expect(TEXTS[copy](), `${copy} does not name \`${UNINSTALL}\``).toContain(UNINSTALL);
  });

  it('pins only the Release body to a version', () => {
    expect(fencedLines(releaseBody()).some((line) => line.includes(RELEASE_PIN))).toBe(true);
    for (const copy of [README, LLMS, REGISTRY]) {
      expect(
        TEXTS[copy]()
          .split('\n')
          .filter((line) => /ai-tc-cursor@/u.test(line)),
        `${copy} pins a version; only the Release body should`,
      ).toEqual([]);
    }
  });
});
