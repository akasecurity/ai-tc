import { expect } from 'vitest';
import { isAlias, isMap, isScalar, isSeq, parseAllDocuments, visit as visitDocument } from 'yaml';

// A GitHub workflow read as a PARSED YAML document: jobs, then steps, then the
// keys, `with:` and `env:` mappings and `run:` scripts of each, as decoded values.
//
// The sibling reader (`workflow.js`) matches text by line and column. That is
// enough for a guard that only wants a position, and it cannot be enough for one
// that has to vouch for what a file MEANS: YAML lets the same structure be spelled
// with an escape (a double-quoted scalar may write the dollar of `${{ }}` as
// `\x24`), a quoted or flow-style key, a block scalar that merely looks like a
// key, or an alias to a mapping written elsewhere, and a reader of lines can only
// refuse the spellings it thought of. Here the spelling is gone before any check
// runs. Comments are gone too — a `#` line inside a `run: |` body is part of that
// script and stays in it, and a YAML comment is not part of anything.
//
// What it will not decode it refuses, rather than guess: a document with a parse
// error or warning (an unresolved tag, a duplicate key, a tab used as indentation),
// more than one document, a `%YAML` directive, a `%TAG` directive that names a
// handle other than `!!`, a mapping key that is not a string, a `<<` merge key, an
// alias with no anchor before it, and an alias that points at a node it sits
// inside. A `%TAG !!` that redefines the
// default prefix is not refused on its own, since nothing resolves through it
// until a tag is written; the warning for the tag that does is.
// Anchors and aliases are decoded — GitHub accepts them. A merge key is not: that
// is a YAML 1.1 extension, GitHub's parser follows 1.2, and a reader that expanded
// it would report a mapping the runner may never build.
//
// These ASSERT rather than throw, deliberately, for the reason `workflow.js` gives:
// they are called from `it` bodies, where an assertion is a test failure, and an
// assertion raised from a `describe` body is a collection error that takes every
// other case in the file with it.

/** @typedef {Record<string, unknown>} Mapping */

/**
 * The trailing comment of each scalar value in a decoded mapping, by key. Kept
 * beside the value because the pin annotation (`uses: action@<sha> # v1.2.3`) is
 * written as a comment, and the structure of a mapping carries no place for one.
 * @type {WeakMap<object, Record<string, string>>}
 */
const TRAILING_COMMENTS = new WeakMap();

/**
 * More nodes than any real workflow expands to; a chain of aliases can multiply.
 * The largest workflow in this repository decodes to under 300, so this is about
 * seventy times that, and a chain that reaches it is refused in milliseconds.
 * Raise it if a real workflow ever approaches it; the refusal below names it.
 */
const MAX_NODES = 20_000;

/**
 * @param {unknown} value
 * @returns {value is Mapping}
 */
export const isMapping = (value) =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * The node each alias in a document names: the last node carrying its anchor
 * before the alias, in document order, which is the rule `Alias.resolve`
 * applies. Built in one walk, so the library is never handed a `ToJSContext`
 * (from yaml 2.9.1 `Alias.resolve` reads `anchors` from any context it is given)
 * and each lookup is a `Map` read.
 *
 * @param {import('yaml').Document} document
 * @returns {Map<import('yaml').Alias, unknown>}
 */
function aliasTargets(document) {
  /** @type {Map<string, unknown>} */
  const anchored = new Map();
  /** @type {Map<import('yaml').Alias, unknown>} */
  const targets = new Map();
  visitDocument(document, {
    Node(_key, node) {
      if (isAlias(node)) targets.set(node, anchored.get(node.source));
      else if (node.anchor) anchored.set(node.anchor, node);
    },
  });
  return targets;
}

/**
 * @typedef {object} DecodeState
 * @property {number} budget
 * @property {Set<unknown>} open
 * @property {Map<import('yaml').Alias, unknown>} targets
 */

/**
 * The node an alias names, refusing an alias that has no anchor before it.
 * @param {import('yaml').Alias} alias
 * @param {DecodeState} state
 */
function targetOf(alias, state) {
  const target = state.targets.get(alias);
  if (target === undefined) {
    expect(target, `the alias *${alias.source} names no anchor`).toBeDefined();
  }
  return target;
}

/**
 * @param {unknown} node
 * @param {DecodeState} state
 * @returns {unknown}
 */
function decode(node, state) {
  // The assertions below are reached only on a refusal. This function runs once
  // per decoded node, and an `expect` per node is the cost of the whole walk.
  state.budget -= 1;
  if (state.budget <= 0) {
    expect(
      state.budget,
      'the workflow expands to more nodes than any real one (raise MAX_NODES in helpers/workflow-yaml.js if a real workflow now needs more)',
    ).toBeGreaterThan(0);
  }
  if (node === null || node === undefined) return null;
  if (isAlias(node)) {
    const target = targetOf(node, state);
    if (state.open.has(target)) {
      expect(false, `the alias *${node.source} refers to a node it is inside`).toBe(true);
    }
    return decode(target, state);
  }
  if (isScalar(node)) return node.value;
  if (isSeq(node)) {
    state.open.add(node);
    try {
      return node.items.map((item) => decode(item, state));
    } finally {
      state.open.delete(node);
    }
  }
  if (isMap(node)) {
    state.open.add(node);
    try {
      /** @type {Array<[string, unknown]>} */
      const entries = [];
      /** @type {Record<string, string>} */
      const comments = {};
      const seen = new Set();
      for (const pair of node.items) {
        const key = isAlias(pair.key) ? targetOf(pair.key, state) : pair.key;
        expect(
          isScalar(key) && typeof key.value === 'string',
          'a mapping key that is not a plain string — a number, a boolean, an empty key or a collection',
        ).toBe(true);
        const name = /** @type {string} */ (/** @type {import('yaml').Scalar} */ (key).value);
        expect(name, 'a `<<` merge key, which this reader does not expand').not.toBe('<<');
        expect(seen.has(name), `the key \`${name}\` appears twice in one mapping`).toBe(false);
        seen.add(name);
        entries.push([name, decode(pair.value, state)]);
        if (isScalar(pair.value) && typeof pair.value.comment === 'string') {
          comments[name] = pair.value.comment;
        }
      }
      // fromEntries defines own data properties, so a key spelled `__proto__`
      // is a key and not a prototype.
      const mapping = Object.fromEntries(entries);
      TRAILING_COMMENTS.set(mapping, comments);
      return mapping;
    } finally {
      state.open.delete(node);
    }
  }
  expect(false, 'a YAML node this reader cannot decode').toBe(true);
  return null;
}

/**
 * A workflow file's text as its decoded top-level mapping.
 *
 * @param {string} source the workflow file's text
 * @returns {Mapping}
 */
export function parseWorkflow(source) {
  const documents = parseAllDocuments(source, {
    version: '1.2',
    schema: 'core',
    uniqueKeys: true,
    merge: false,
    logLevel: 'silent',
  });
  expect(documents, 'the workflow is not exactly one YAML document').toHaveLength(1);
  const [document] = documents;
  expect(
    document.errors.map((error) => error.message),
    'the workflow is not valid YAML',
  ).toEqual([]);
  expect(
    document.warnings.map((warning) => warning.message),
    'the workflow carries YAML this reader would decode differently from the runner',
  ).toEqual([]);
  expect(document.directives.yaml.explicit, 'the workflow opens with a `%YAML` directive').toBe(
    false,
  );
  expect(
    Object.keys(document.directives.tags),
    'the workflow opens with a `%TAG` directive that names a handle other than `!!`',
  ).toEqual(['!!']);

  const root = decode(document.contents, {
    budget: MAX_NODES,
    open: new Set(),
    targets: aliasTargets(document),
  });
  expect(isMapping(root), 'the workflow is not a mapping at its top level').toBe(true);
  return /** @type {Mapping} */ (root);
}

/**
 * The jobs mapping, asserted to name at least one job.
 * @param {Mapping} workflow
 * @returns {Mapping}
 */
export function jobsOf(workflow) {
  expect(isMapping(workflow.jobs), 'the workflow declares no jobs block').toBe(true);
  const jobs = /** @type {Mapping} */ (workflow.jobs);
  expect(Object.keys(jobs).length, 'the jobs block declares no job').toBeGreaterThan(0);
  return jobs;
}

/**
 * Every job id the workflow declares, in file order.
 * @param {Mapping} workflow
 */
export const jobIds = (workflow) => Object.keys(jobsOf(workflow));

/**
 * One job.
 *
 * A job comes in two shapes and only one of them has steps: a job that CALLS a
 * reusable workflow carries `uses:` and neither `runs-on:` nor `steps:`, and
 * GitHub rejects one that carries both. Either shape is a job; a mapping with
 * neither is not, and every absence check made over it would pass vacuously.
 *
 * @param {Mapping} workflow
 * @param {string} id the job id
 * @returns {Mapping}
 */
export function jobOf(workflow, id) {
  const jobs = jobsOf(workflow);
  expect(Object.hasOwn(jobs, id), `no job \`${id}\` in the workflow`).toBe(true);
  const job = jobs[id];
  expect(isMapping(job), `\`${id}\` is not a mapping — not a job`).toBe(true);
  const body = /** @type {Mapping} */ (job);
  const isRunnerJob = Object.hasOwn(body, 'runs-on');
  const isCallerJob = Object.hasOwn(body, 'uses');
  expect(
    isRunnerJob || isCallerJob,
    `\`${id}\` declares neither a runs-on nor a uses — not a job`,
  ).toBe(true);
  if (isRunnerJob) {
    expect(Array.isArray(body.steps) && body.steps.length > 0, `\`${id}\` declares no steps`).toBe(
      true,
    );
    for (const step of /** @type {unknown[]} */ (body.steps)) {
      expect(isMapping(step), `\`${id}\` has a step that is not a mapping`).toBe(true);
    }
  }
  return body;
}

/**
 * The steps of one job, or of every job in a workflow.
 * @param {Mapping} scope a job, or the workflow itself
 * @returns {Mapping[]}
 */
export function stepsOf(scope) {
  if (Array.isArray(scope.steps)) return /** @type {Mapping[]} */ (scope.steps);
  const jobs = jobsOf(scope);
  return Object.values(jobs).flatMap((job) =>
    isMapping(job) && Array.isArray(job.steps) ? /** @type {Mapping[]} */ (job.steps) : [],
  );
}

/**
 * The one step carrying a `name:`, asserted to occur exactly once.
 *
 * Exactly one rather than the first: every assertion a caller makes over a step
 * is a presence check, and one against the WRONG step passes for the wrong
 * reason. Given a workflow rather than a job, the name has to be unique across
 * every job in it.
 *
 * @param {Mapping} scope a job, or the workflow itself
 * @param {string} name the step's `name:` value
 * @returns {Mapping}
 */
export function stepNamed(scope, name) {
  const matching = stepsOf(scope).filter((step) => step.name === name);
  expect(
    matching,
    `the workflow has no single step named \`${name}\` — everything read from it would be about nothing`,
  ).toHaveLength(1);
  return matching[0];
}

/**
 * The position of the one step a predicate selects, asserted to be exactly one.
 *
 * Both halves matter for an ordering claim: an index of -1 satisfies
 * `toBeLessThan`, which reads as an ordering check and is not one, and a second
 * match makes the position the position of whichever came first.
 *
 * @param {Mapping} job
 * @param {(step: Mapping) => boolean} match
 * @param {string} where what is being looked for, for the failure message
 */
export function stepIndexOf(job, match, where) {
  const found = stepsOf(job).flatMap((step, index) => (match(step) ? [index] : []));
  expect(found, `${where} does not occur exactly once in the job`).toHaveLength(1);
  return found[0];
}

/**
 * The position of the step with this `name:`.
 * @param {Mapping} job
 * @param {string} name
 */
export const stepIndex = (job, name) =>
  stepIndexOf(job, (step) => step.name === name, `the step named \`${name}\``);

/**
 * The position of the step whose `uses:` begins with a prefix.
 * @param {Mapping} job
 * @param {string} prefix
 */
export const usesIndex = (job, prefix) =>
  stepIndexOf(
    job,
    (step) => typeof step.uses === 'string' && step.uses.startsWith(prefix),
    `a step that uses \`${prefix}\``,
  );

/**
 * The job ids a job waits on, in whichever shape `needs:` was written. An absent
 * key returns an empty list, which is the defect a caller asserts against.
 * @param {Mapping} job
 * @returns {string[]}
 */
export function needsOf(job) {
  const { needs } = job;
  if (needs === undefined) return [];
  if (typeof needs === 'string') return [needs];
  expect(
    Array.isArray(needs) && needs.every((id) => typeof id === 'string'),
    '`needs:` is neither a job id nor a list of them',
  ).toBe(true);
  return /** @type {string[]} */ (needs);
}

/**
 * A scalar the way the runner hands it on: as text. A number or a boolean is its
 * own spelling, an empty value is empty, and anything else is not a scalar.
 * @param {unknown} value
 * @param {string} where
 * @returns {string}
 */
function scalarText(value, where) {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  expect(value === null || value === undefined, `${where} is not a scalar`).toBe(true);
  return '';
}

/**
 * The `if:` condition of a step or a job, as written, asserted present.
 *
 * A gate is a VALUE to compare rather than a spelling to match, because the
 * property is that two steps fire under the same condition. A mapping cannot
 * carry a key twice, so there is no second gate to answer about.
 *
 * @param {Mapping} node
 * @param {string} where what is being read, for the failure message
 */
export function ifOf(node, where) {
  expect(node.if ?? undefined, `${where} declares no single \`if:\` gate`).toBeDefined();
  return scalarText(node.if, `${where}'s \`if:\``);
}

/**
 * A mapping of plain values, each as the text the runner hands on.
 * @param {Mapping} node
 * @param {string} key
 * @param {string} where
 * @returns {Record<string, string>}
 */
function textMapping(node, key, where) {
  const value = node[key];
  if (value === undefined || value === null) return {};
  expect(isMapping(value), `${where} \`${key}:\` is not a mapping`).toBe(true);
  return Object.fromEntries(
    Object.entries(/** @type {Mapping} */ (value)).map(([name, entry]) => [
      name,
      scalarText(entry, `${where} \`${key}: ${name}\``),
    ]),
  );
}

/**
 * A step's `with:` mapping, whole. The WHOLE mapping is returned rather than the
 * keys a case asks about, because the property is what the step is NOT given as
 * much as what it is.
 * @param {Mapping} step
 */
export const inputsOf = (step) => textMapping(step, 'with', 'the step');

/**
 * A step's or a job's `env:` mapping, whole.
 * @param {Mapping} node
 */
export const envOf = (node) => textMapping(node, 'env', 'the node');

/**
 * The entries of a multi-line input of a step — one per non-blank line, trimmed —
 * and only those. Non-emptiness is asserted first: every check made over the list
 * is satisfied vacuously by an empty one.
 *
 * @param {Mapping} step
 * @param {string} key the input key
 * @returns {string[]}
 */
export function inputLines(step, key) {
  const inputs = inputsOf(step);
  expect(Object.hasOwn(inputs, key), `the step declares no \`${key}:\` input`).toBe(true);
  const entries = inputs[key]
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '');
  expect(entries.length, `\`${key}:\` declares no entries`).toBeGreaterThan(0);
  return entries;
}

/**
 * A step's `run:` script, decoded: what the runner writes to a file and hands to
 * the shell, comments inside it included.
 * @param {Mapping} step
 * @returns {string}
 */
export function scriptOf(step) {
  expect(
    typeof step.run === 'string' && step.run.trim() !== '',
    `the step \`${String(step.name ?? step.uses ?? '(unnamed)')}\` declares no run: script`,
  ).toBe(true);
  return /** @type {string} */ (step.run);
}

/**
 * Every `run:` script of a job, or of every job in a workflow.
 * @param {Mapping} scope
 * @returns {string[]}
 */
export const scriptsOf = (scope) =>
  stepsOf(scope)
    .filter((step) => step.run !== undefined)
    .map(scriptOf);

/**
 * A step's `uses:` as it is written: the reference, and the trailing comment when
 * there is one (`actions/x@<sha> # v1.2.3`). The comment is the version a pinned
 * SHA resolves to, which is why it is part of what a pin check reads.
 * @param {Mapping} step
 * @returns {string}
 */
export function usesOf(step) {
  expect(typeof step.uses === 'string', 'the step declares no uses:').toBe(true);
  const note = TRAILING_COMMENTS.get(step)?.uses;
  return note === undefined ? /** @type {string} */ (step.uses) : `${step.uses} #${note}`;
}

/**
 * Every mapping key at any depth, in file order.
 * @param {unknown} value
 * @returns {string[]}
 */
export function keysIn(value) {
  /** @type {string[]} */
  const found = [];
  const visit = (/** @type {unknown} */ node) => {
    if (Array.isArray(node)) node.forEach(visit);
    else if (isMapping(node)) {
      for (const [key, child] of Object.entries(node)) {
        found.push(key);
        visit(child);
      }
    }
  };
  visit(value);
  return found;
}

/**
 * Whether a key of this name appears anywhere under a value. Case-insensitive:
 * the direction that errs towards reporting.
 * @param {unknown} value
 * @param {string} name
 */
export const hasKey = (value, name) =>
  keysIn(value).some((key) => key.toLowerCase() === name.toLowerCase());

/**
 * Every string under a value — keys and values — in file order.
 * @param {unknown} value
 * @returns {string[]}
 */
export function stringsIn(value) {
  /** @type {string[]} */
  const found = [];
  const visit = (/** @type {unknown} */ node) => {
    if (typeof node === 'string') found.push(node);
    else if (Array.isArray(node)) node.forEach(visit);
    else if (isMapping(node)) {
      for (const [key, child] of Object.entries(node)) {
        found.push(key);
        visit(child);
      }
    }
  };
  visit(value);
  return found;
}

/**
 * Every `${{ … }}` expression in a text, in order.
 *
 * Read the way GitHub reads one rather than with a lazy `}}` match: a string
 * literal inside an expression may itself contain `}}`, and `format('}}',
 * secrets.X)` is one expression that a lazy match splits in two, leaving
 * `secrets.X` outside both. Quotes are tracked, with `''` as the escape that
 * toggles twice.
 *
 * @param {string} text
 * @returns {string[]}
 */
export function expressionsIn(text) {
  /** @type {string[]} */
  const found = [];
  let from = 0;
  for (;;) {
    const start = text.indexOf('${{', from);
    if (start === -1) return found;
    let end = start + 3;
    let inString = false;
    for (; end < text.length; end += 1) {
      if (text[end] === "'") inString = !inString;
      else if (!inString && text[end] === '}' && text[end + 1] === '}') {
        end += 2;
        break;
      }
    }
    found.push(text.slice(start, end));
    from = end;
  }
}

/**
 * Every expression under a value, read from the DECODED strings: an expression
 * spelled through an escape or across a folded line is the expression the runner
 * evaluates, and a `#` line inside a `run:` body is script text it substitutes
 * into. A YAML comment is neither, so a sentence about an expression is not one.
 * @param {unknown} value
 * @returns {string[]}
 */
export const expressionsOf = (value) => stringsIn(value).flatMap(expressionsIn);

/**
 * The permission scopes a `permissions:` value grants at `write`, as written.
 * `write-all` stands for every scope, and `read-all` for none.
 *
 * @param {unknown} permissions the value of a `permissions:` key, possibly absent
 * @returns {string[]}
 */
export function writeScopes(permissions) {
  if (permissions === undefined || permissions === null) return [];
  if (typeof permissions === 'string') {
    return permissions.trim().toLowerCase() === 'write-all' ? ['write-all'] : [];
  }
  expect(isMapping(permissions), '`permissions:` is neither a mapping nor a shorthand').toBe(true);
  return Object.entries(/** @type {Mapping} */ (permissions))
    .filter(
      ([scope, level]) =>
        scalarText(level, `\`permissions: ${scope}\``).trim().toLowerCase() === 'write',
    )
    .map(([scope]) => scope);
}
