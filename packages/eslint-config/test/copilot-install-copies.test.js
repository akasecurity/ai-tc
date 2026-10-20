import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { REPO_ROOT } from './helpers/lint-invocations.js';
import { inputsOf, jobOf, parseWorkflow, stepNamed } from './helpers/workflow-yaml.js';

const require = createRequire(import.meta.url);
/** @type {import('typescript')} */
const ts = require('typescript');

// The Copilot plugin has no marketplace, so a user installs and updates it by
// typing shell commands copied from whichever page they read first. The setup
// skill's "Install — Copilot CLI" section is the reference for those commands,
// and six copies of them are compared against it. Four carry the whole install
// and update list: the README's Copilot CLI section, llms.txt, the registry
// hint and the Release body. Two carry only the opening lines that create the
// folder and unpack the package: the skill's own VS Code section and the
// README's. Each copy is reduced to its command lines and required to equal the
// reference's lines (or, for the VS Code copies, the reference's install lines
// up to `copilot plugin install`), so a copy edited on its own goes red here.
//
// Only commands are compared, never the prose around them: the copies explain
// the steps at different lengths on purpose, and the commands are what a user
// pastes.

const SKILL = 'plugins/copilot/skills/setup/SKILL.md';
const README = 'plugins/copilot/README.md';
const LLMS = 'llms.txt';
const REGISTRY = 'packages/local-ops/src/registry.ts';
const RELEASE = '.github/workflows/release-plugin-copilot.yml';

/** The version pin the Release body carries, and nothing else may. */
const RELEASE_PIN = '@${{ steps.manifest.outputs.version }}';

/**
 * What marks a line as one of the install or update commands. `copilot plugin
 * list` and `aka init` are left out: the registry hint states the second in
 * prose and omits the first, and neither moves a file.
 */
const COMMAND_MARKERS = Object.freeze([
  'mkdir ',
  'rm -rf package',
  'npm pack @akasecurity/ai-tc-copilot',
  'tar -xzf',
  'copilot plugin install',
  'copilot plugin update',
]);

/** @param {string} rel */
const read = (rel) => readFileSync(join(REPO_ROOT, rel), 'utf8');

/**
 * A command line with its indentation and any shell prompt removed.
 * @param {string} line
 */
const normalize = (line) => line.trim().replace(/^[$>]\s+/u, '');

/**
 * The command lines among `lines`, normalized, in order.
 * @param {string[]} lines
 * @returns {string[]}
 */
const commandsIn = (lines) =>
  lines.map(normalize).filter((line) => COMMAND_MARKERS.some((m) => line.includes(m)));

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
 * The `installHint` of the `AGENT_PLUGINS` entry whose `id` is `id`, read from
 * the registry's source text. Parsed rather than imported: this package may
 * depend on nothing in the workspace.
 * @param {string} source
 * @param {string} id
 * @returns {string}
 */
function installHintOf(source, id) {
  const sf = ts.createSourceFile(REGISTRY, source, ts.ScriptTarget.Latest, true);
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
      if (idNode && ts.isStringLiteral(idNode) && idNode.text === id && hintNode) {
        const hint = foldStrings(hintNode);
        expect(
          hint,
          `${REGISTRY}: the \`${id}\` installHint is no longer a string or a \`+\` chain of string literals`,
        ).toBeDefined();
        hints.push(/** @type {string} */ (hint));
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  expect(hints, `${REGISTRY} has no single \`${id}\` entry with an installHint`).toHaveLength(1);
  return hints[0];
}

/** @returns {string[]} */
function skillCommands() {
  return commandsIn(
    fencedLines(sectionOf(read(SKILL), '## Install — Copilot CLI', /^## /u, SKILL)),
  );
}

/**
 * The reference's install lines before `copilot plugin install`: the lines that
 * create the folder and unpack the package, which is all a VS Code copy carries.
 * @returns {string[]}
 */
function vscodeReference() {
  const reference = skillCommands();
  const install = reference.findIndex((line) => line.includes('copilot plugin install'));
  expect(install, `${SKILL}'s CLI section has no \`copilot plugin install\` line`).toBeGreaterThan(
    0,
  );
  return reference.slice(0, install);
}

/** @returns {string[]} */
function skillVscodeCommands() {
  return commandsIn(
    fencedLines(sectionOf(read(SKILL), '## Install — VS Code agent mode (beta)', /^## /u, SKILL)),
  );
}

/** @returns {string[]} */
function readmeVscodeCommands() {
  return commandsIn(
    fencedLines(sectionOf(read(README), '### VS Code agent mode (beta)', /^#{2,3} /u, README)),
  );
}

/** @returns {string[]} */
function readmeCommands() {
  return commandsIn(fencedLines(sectionOf(read(README), '### Copilot CLI', /^#{2,3} /u, README)));
}

/** @returns {string[]} */
function llmsCommands() {
  const text = read(LLMS);
  const start = text.split('\n').find((line) => line.startsWith('- GitHub Copilot:'));
  expect(start, `${LLMS} has no \`- GitHub Copilot:\` entry`).toBeDefined();
  return commandsIn(fencedLines(sectionOf(text, /** @type {string} */ (start), /^(- |#)/u, LLMS)));
}

/**
 * The registry hint's command lines. The hint is printed as-is, so its command
 * lines are the indented ones.
 * @returns {string[]}
 */
function registryCommands() {
  const hint = installHintOf(read(REGISTRY), 'copilot');
  return commandsIn(hint.split('\n').filter((line) => /^\s/u.test(line)));
}

/**
 * The Release body's command lines, exactly as the body spells them.
 * @returns {string[]}
 */
function releaseCommandsPinned() {
  const workflow = parseWorkflow(read(RELEASE));
  const step = stepNamed(jobOf(workflow, 'release'), 'Create GitHub Release');
  const body = inputsOf(step).body;
  expect(typeof body, `${RELEASE}: the Release step carries no body`).toBe('string');
  return commandsIn(fencedLines(body));
}

/**
 * The Release body's command lines with the version pin removed. Every `npm pack`
 * line must carry the pin, so a body that stopped pinning, or pinned only one of
 * its two lines, is red here rather than quietly equal to the reference.
 * @param {string[]} lines
 * @returns {string[]}
 */
function unpin(lines) {
  for (const line of lines.filter((l) => l.includes('npm pack'))) {
    expect(line, `${RELEASE}: an \`npm pack\` line does not pin the released version`).toContain(
      `npm pack @akasecurity/ai-tc-copilot${RELEASE_PIN} `,
    );
  }
  return lines.map((line) => line.split(RELEASE_PIN).join(''));
}

/** @type {Record<string, () => string[]>} */
const COPIES = {
  [README]: readmeCommands,
  [LLMS]: llmsCommands,
  [REGISTRY]: registryCommands,
  [RELEASE]: () => unpin(releaseCommandsPinned()),
};

/**
 * The copies that carry only the reference's opening lines.
 * @type {Record<string, () => string[]>}
 */
const VSCODE_COPIES = {
  [`${SKILL} (VS Code)`]: skillVscodeCommands,
  [`${README} (VS Code)`]: readmeVscodeCommands,
};

describe('Copilot install copies agree with the setup skill', () => {
  it('reads install AND update commands out of the reference (positive control)', () => {
    const reference = skillCommands();
    for (const marker of COMMAND_MARKERS) {
      expect(
        reference.some((line) => line.includes(marker)),
        `${SKILL}'s CLI section has no command line containing \`${marker}\``,
      ).toBe(true);
    }
  });

  it.each(Object.keys(COPIES))('%s yields command lines (positive control)', (copy) => {
    expect(COPIES[copy]().length, `${copy} yielded no install command`).toBeGreaterThan(0);
  });

  it.each(Object.keys(COPIES))('%s carries exactly the reference commands', (copy) => {
    expect(COPIES[copy](), `${copy} has drifted from ${SKILL}`).toEqual(skillCommands());
  });

  it('reads a folder and an unpack line as the VS Code reference (positive control)', () => {
    const reference = vscodeReference();
    expect(reference.some((line) => line.includes('mkdir '))).toBe(true);
    expect(reference.some((line) => line.includes('tar -xzf'))).toBe(true);
  });

  it.each(Object.keys(VSCODE_COPIES))('%s yields command lines (positive control)', (copy) => {
    expect(VSCODE_COPIES[copy]().length, `${copy} yielded no install command`).toBeGreaterThan(0);
  });

  it.each(Object.keys(VSCODE_COPIES))('%s carries exactly the reference opening lines', (copy) => {
    expect(VSCODE_COPIES[copy](), `${copy} has drifted from ${SKILL}`).toEqual(vscodeReference());
  });

  it('pins only the Release body to a version', () => {
    expect(releaseCommandsPinned().some((line) => line.includes(RELEASE_PIN))).toBe(true);
    /** @type {Record<string, () => string[]>} */
    const unpinned = {
      [SKILL]: skillCommands,
      [README]: readmeCommands,
      [LLMS]: llmsCommands,
      [REGISTRY]: registryCommands,
      ...VSCODE_COPIES,
    };
    for (const [copy, commands] of Object.entries(unpinned)) {
      const lines = commands();
      expect(
        lines.filter((line) => /ai-tc-copilot@/u.test(line)),
        `${copy} pins a version; only the Release body should`,
      ).toEqual([]);
    }
  });
});
