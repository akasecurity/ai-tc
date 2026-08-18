import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import { REPO_ROOT, trackedFiles } from './helpers/lint-invocations.js';

const require = createRequire(import.meta.url);
/** @type {import('typescript')} */
const ts = require('typescript');

// The host CLIs share the `<bin> plugin …` SHAPE and not the verbs: Claude Code
// takes `plugin install`/`plugin update`, Codex takes `plugin add` for both. A
// verb spelled into a string somewhere other than the verb table is a command
// one of the hosts rejects outright — `codex plugin install aka-codex@ai-tc`
// answers "unrecognized subcommand", and every Codex install and update through
// that path fails.
//
// That bug did NOT live in the module that owns the table, and the suite next to
// that module could not have caught it: it was hardcoded strings at four call
// sites (`cli/src/commands/update.ts`, `cli/src/commands/plugins.ts`,
// `packages/local-ops/src/apply.ts`, `web-ui/app/(app)/updates/page.tsx`), and
// a guard reading `installCommands` against `installSteps` is green throughout
// — both sides read the same table, so it can only fail if someone stops
// calling the renderer.
//
// So the invariant is a property of the TREE, not of one module: outside the
// table, nothing spells a host plugin verb. This lives here rather than in
// `local-ops` because only this task's turbo `inputs` hash the whole workspace
// — the same check inside `local-ops` would replay a cached green while a new
// hardcoded string appeared in `cli/src` or `web-ui/app`.
//
// This guard is BEST-EFFORT, and its silence means "found nothing", never
// "there is nothing". It reads literal text, so it bounds the literal
// spellings and nothing else: a verb reached through a variable or built by a
// helper is invisible to it — `` `claude plugin ${VERB} ${ref}` `` with
// `const VERB = 'update'` reproduces the original defect at the same call site
// and passes. Chasing identifiers is a different tool and is not worth its
// cost here; the case below pins the bound so a reader knows what a green run
// is worth, and so widening the guard later is a deliberate edit.
const VERB_TABLE = 'packages/local-ops/src/cli-plugin-manager.ts';

// Hosts whose verbs come from the table. `agy` is deliberately absent:
// Antigravity has no marketplace and no `cliBin` binding — `agy plugin install`
// takes a local directory path — so the registry's `installHint` is the
// documented "installed by other means" case rather than a drifting copy of a
// verb this module owns.
const MANAGED_BINS = ['claude', 'codex'];

// A bin named literally, or reached through ANY interpolation — the second form
// is how the defect was actually written (`` `${cliBin} plugin update ${ref}` ``)
// and it is the one a search for "codex plugin" never finds. Matching any
// `${…}` rather than trying to recognise bin-ish names is deliberate: nothing
// but a host binary precedes `plugin <verb>`, and a pattern that reasoned about
// the identifier missed `cliBin` outright, because `\bBin\b` finds no boundary
// inside it. `marketplace` is absent from the verb list, so the one genuinely
// shared subcommand stays legal everywhere.
const BIN = String.raw`(?:${MANAGED_BINS.join('|')}|\$\{[^}]*\})`;
const HOST_PLUGIN_VERB = new RegExp(String.raw`${BIN}\s+plugin\s+(?:install|update|add|remove)\b`);

/**
 * Every string and template literal in a TS/TSX source, as text — the pieces a
 * template arrives in AND the whole expression rejoined, since either form can
 * be the one that matches. Parsing rather than scanning the raw bytes is what
 * keeps this guard usable: the same words appear in prose all over this repo —
 * including in the comment above — and a text search flags each one, which is
 * how a guard ends up disabled.
 *
 * One parse per file, not one per shape. Parsing is nearly the whole cost of
 * this suite, so walking the tree twice doubled it for no additional coverage.
 * @param {string} source
 * @param {string} path
 * @returns {{ text: string, line: number }[]}
 */
function stringsIn(source, path) {
  const sf = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true);
  /** @type {{ text: string, line: number }[]} */
  const found = [];
  /** @param {import('typescript').Node} node */
  const visit = (node) => {
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node)
    ) {
      found.push({
        text: node.text,
        line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1,
      });
    }
    // A template literal's pieces reach the branch above split at each `${…}`,
    // so `` `${cliBin} plugin update ${ref}` `` arrives as " plugin update "
    // and never matches on its own. Rejoin the pieces with a placeholder that
    // keeps the interpolation visible to the pattern.
    if (ts.isTemplateExpression(node)) {
      const text =
        node.head.text +
        node.templateSpans.map((s) => `\${${s.expression.getText(sf)}}${s.literal.text}`).join('');
      found.push({ text, line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1 });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return found;
}

const SOURCES = trackedFiles().filter(
  (f) =>
    (f.endsWith('.ts') || f.endsWith('.tsx')) &&
    !f.endsWith('.d.ts') &&
    f !== VERB_TABLE &&
    // Tests assert on these strings by design — that is what pins the table.
    !/(^|\/)(test|tests|bench)\//.test(f),
);

// Reading and parsing every candidate source is filesystem- and parser-bound,
// so on a contended runner it costs many times what it does on a developer
// machine — measured at 254 ms here against 5.7 s on a CI runner, past vitest's
// 5 s per-test default, which is what reddened this suite on three legs at once.
// Walk once in a `beforeAll` under the hook's own budget; the test below is then
// a fast assertion on the result and keeps the tight per-test default, which
// still guards it. Mirrors effective-config.test.js's RESOLVE_TIMEOUT_MS and
// no-network.test.js's CONFIG_LOAD_TIMEOUT_MS, for the same reason — this
// package deliberately sets no package-wide testTimeout.
const SCAN_TIMEOUT_MS = 120_000;

describe('no shipped source spells a host plugin verb outside the verb table', () => {
  /** Every offending literal found in the tracked tree, collected once below. */
  /** @type {string[]} */
  const offenders = [];
  /** How many sources the walk actually parsed — see 'finds sources to audit'. */
  let parsed = 0;

  beforeAll(() => {
    for (const rel of SOURCES) {
      const source = readFileSync(join(REPO_ROOT, rel), 'utf8');
      if (!/plugin/.test(source)) continue;
      parsed += 1;
      for (const { text, line } of stringsIn(source, rel)) {
        if (HOST_PLUGIN_VERB.test(text)) offenders.push(`${rel}:${line} — ${text.trim()}`);
      }
    }
  }, SCAN_TIMEOUT_MS);

  it('finds sources to audit', () => {
    // Without this the whole suite passes on an empty list — the exact vacuous
    // green a filter typo produces. `parsed` covers the same failure one step
    // later: an empty offender list means nothing only if the walk reached the
    // parser, which a prefilter that stopped matching would silently prevent.
    expect(SOURCES.length).toBeGreaterThan(100);
    expect(SOURCES).not.toContain(VERB_TABLE);
    expect(parsed).toBeGreaterThan(0);
  });

  it('holds across the tracked tree', () => {
    expect(
      offenders,
      `A host plugin verb is spelled outside ${VERB_TABLE}. The hosts do not share verbs, so a ` +
        'hardcoded one is a command the other host rejects. Derive it from ' +
        '`createCliPluginManager(bin)` instead — `installCommands`/`updateCommands` for the op, ' +
        '`installRecipe`/`updateRecipe` for copy a user runs by hand.',
    ).toEqual([]);
  });

  it('would catch the defect it was written for', () => {
    // The guard is only worth its green if it can go red, and both spellings of
    // the original bug have to trip it: the literal one, and the interpolated
    // one that a search for "codex plugin" never finds.
    const planted = [
      'const hint = `${cliBin} plugin update ${ref}`;',
      "const hint = 'claude plugin install ' + ref;",
      'const hint = `codex plugin add ${ref}`;',
      'installCommands[agent.id] = `claude plugin install ${ref}`;',
    ];
    for (const line of planted) {
      const hits = stringsIn(line, 'planted.ts').filter((l) => HOST_PLUGIN_VERB.test(l.text));
      expect(hits, `expected to flag: ${line}`).not.toEqual([]);
    }
  });

  it('bounds the literal spellings only — a verb held in a variable is invisible', () => {
    // Not an endorsement: this is the guard's blind spot, asserted so it is
    // written down rather than discovered. A `.skip` would report as skipped
    // and prove nothing; pinning the actual behaviour means widening the
    // scanner to chase identifiers goes red HERE, next to the header sentence
    // that would then need retracting.
    const hoisted = ["const VERB = 'update';", 'const hint = `claude plugin ${VERB} ${ref}`;'];
    for (const line of hoisted) {
      const hits = stringsIn(line, 'hoisted.ts').filter((l) => HOST_PLUGIN_VERB.test(l.text));
      expect(hits, `blind spot changed — the header says this is invisible: ${line}`).toEqual([]);
    }
  });

  it('does not flag prose, or the host that has no verb table', () => {
    const benign = [
      // A comment naming the verbs — this file and several others do it.
      '// `claude plugin install` and `codex plugin add` are not interchangeable',
      // Antigravity: no marketplace, no cliBin, documented as installed by
      // other means. Its hint is not a drifting copy of anything.
      "const hint = '  agy plugin install ./package\\n';",
      // The marketplace verb is common to both hosts and is not in the pattern.
      'const prep = `${bin} plugin marketplace add ${source}`;',
    ];
    for (const line of benign) {
      const hits = stringsIn(line, 'benign.ts').filter((l) => HOST_PLUGIN_VERB.test(l.text));
      expect(hits, `should not flag: ${line}`).toEqual([]);
    }
  });
});
