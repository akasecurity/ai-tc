import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { lintableTrackedFiles, REPO_ROOT } from './helpers/lint-invocations.js';

// A file published by renaming a freshly written sibling over it does not keep
// its own permission bits: the bits that survive are the TEMP file's, because
// rename moves an inode rather than its contents. A write that names no `mode`
// creates that temp at the process umask — 0644 on a default host — so the
// rename hands a 0600 file to group and other.
//
// The property this guard holds is "rewrites an existing file without
// preserving its mode", NOT "passes no mode". The difference matters in both
// directions:
//
//   - A writer that creates a NEW file has no prior mode to destroy, so
//     passing no mode is correct there. `packages/setup-wizard/src/remediation/
//     rotation-checklist.ts` is exactly that, and the negative control below
//     pins it: it writes with no mode and this guard must stay silent about it.
//   - A writer that publishes over a file AKA itself owns should force a
//     constant (owner-only), not copy whatever bits were there. Preserving is
//     right only for a file the USER owns — a transcript.
//
// So the guard derives the publish sites from the tracked tree and pins each
// one's decision in `EXPECTED`. A new rename-publish site fails here until its
// row is added, which forces the author to decide preserve-vs-constant rather
// than defaulting to the umask. Scoping a sweep by directory, or by host, is
// what let this class survive two earlier passes over it.

const TREE_WALK_TIMEOUT_MS = 30_000;

/** Arguments of the call whose `(` sits at `open`, split on top-level commas. */
function callArgs(text, open) {
  let depth = 0;
  let start = open + 1;
  const args = [];
  for (let i = open; i < text.length; i += 1) {
    const ch = text[i];
    if (ch === '(' || ch === '[' || ch === '{') depth += 1;
    else if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
      if (depth === 0) {
        args.push(text.slice(start, i).trim());
        return args;
      }
    } else if (ch === ',' && depth === 1) {
      args.push(text.slice(start, i).trim());
      start = i + 1;
    }
  }
  return null; // unbalanced — not a call this guard can read
}

/**
 * Every `name(...)` call in `text`, with its arguments and its offset.
 *
 * A trailing comma before the `)` is dropped: the tree is prettier-formatted, so
 * nearly every multi-line call has one, and keeping it as an empty final
 * argument would make every options object read as absent.
 */
function calls(text) {
  const found = [];
  for (const match of text.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)) {
    const open = match.index + match[0].length - 1;
    const args = callArgs(text, open);
    // A call whose arguments cannot be balanced is KEPT with `args: null`, not
    // dropped. The depth scan does not skip string, template or comment
    // contents, so an opener inside a literal runs the scan off the end of the
    // file — and dropping that call silently would take a rename-publish site
    // out of the derivation without failing anything, which is the one outcome
    // a detection guard must not have. `publishSites` reports it instead.
    //
    // A stray CLOSER inside a literal is the case this cannot catch: the scan
    // ends early with plausible-looking arguments, and a rename whose source
    // has no writer is indistinguishable from a move, which is the predicate
    // itself. Such a site reads as a move and is skipped.
    if (args !== null && args.at(-1) === '') args.pop();
    found.push({ name: match[1], args, index: match.index });
  }
  return found;
}

// Calls that put bytes in a file. A rename whose source was never written by one
// of these is a MOVE: it carries an existing inode, and its mode with it.
// `writeExclusiveOwnerOnlySync` is this repo's own owner-only wrapper, kept here
// so a publish through it reads as a publish rather than as a move.
const WRITERS = new Set([
  'writeFileSync',
  'writeFile',
  'appendFileSync',
  'copyFileSync',
  'cpSync',
  'writeExclusiveOwnerOnlySync',
]);

const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;

/**
 * How a write decides the mode of the inode it creates.
 *
 * `preserved` — taken from a stat of the destination (`… .mode & 0o777`).
 * `constant`  — an explicit octal or a `*_MODE` constant.
 * `no-mode`   — nothing passed, so the inode lands at the process umask.
 */
function modeDecision(text, write) {
  const options = write.args?.at(-1) ?? '';
  const key = /(?:^|[,{\s])mode\s*(?::\s*([^,}]+))?(?=\s*[,}])/.exec(options);
  if (key === null) return 'no-mode';
  const expression = (key[1] ?? 'mode').trim();
  if (/\.mode\s*&\s*0o777/.test(expression)) return 'preserved';
  if (IDENTIFIER.test(expression)) {
    const bound = new RegExp(`\\b${expression}\\b[^;\\n]*\\.mode\\s*&\\s*0o777`);
    if (bound.test(text)) return 'preserved';
  }
  return /^0o[0-7]+$/.test(expression) || /_MODE$/.test(expression) ? 'constant' : 'unreadable';
}

/**
 * The rename-publish sites in one file: a `rename`/`renameSync` whose SOURCE is
 * an identifier some call in the same file wrote. A rename whose source nothing
 * wrote is a MOVE — it carries an existing inode, and its mode with it — so it
 * is not a publish and not this guard's business.
 */
function publishSites(text) {
  const all = calls(text);
  const sites = [];
  for (const call of all) {
    if (call.name !== 'rename' && call.name !== 'renameSync') continue;
    if (call.args === null) {
      sites.push({ source: '<unparsed>', decision: 'unparsed' });
      continue;
    }
    const source = call.args[0];
    if (source === undefined || !IDENTIFIER.test(source)) continue;
    // The NEAREST preceding write of this binding, not the first one in the
    // file: a module can publish two different files through two `tmp`
    // bindings of the same name (`cli/src/commands/extension.ts` does), and a
    // file-wide search would collapse them onto whichever came first.
    const writes = all.filter(
      (other) => WRITERS.has(other.name) && other.args !== null && other.args[0] === source,
    );
    const write =
      writes.filter((other) => other.index < call.index).at(-1) ??
      writes.find((other) => other.index > call.index);
    if (write === undefined) continue;
    sites.push({
      source,
      decision:
        write.name === 'writeFileSync' || write.name === 'writeFile'
          ? modeDecision(text, write)
          : `via ${write.name}`,
    });
  }
  return sites;
}

const isShippedSource = (file) =>
  !file.includes('/test/') &&
  !file.includes('/bench/') &&
  !/\.(test|bench|spec)\./.test(file) &&
  !file.startsWith('test/');

function observedSites() {
  const observed = {};
  for (const file of lintableTrackedFiles().filter(isShippedSource)) {
    const text = readFileSync(join(REPO_ROOT, file), 'utf8');
    if (!/\brename(?:Sync)?\s*\(/.test(text)) continue;
    const sites = publishSites(text);
    for (const [at, site] of sites.entries()) {
      // The binding name alone is not unique within a file; the ordinal is what
      // keeps two same-named publish sites apart.
      const key = sites.length === 1 ? `${file}#${site.source}` : `${file}#${site.source}@${at}`;
      observed[key] = site.decision;
    }
  }
  return observed;
}

/**
 * Every rename-publish site in the shipped tree and what each does about the
 * destination's mode, keyed `<file>#<binding>` (with an ordinal when one file
 * has several). A site missing from this table, or carrying a different
 * decision, fails the case below — which is the point: the author decides
 * preserve-vs-constant in review rather than inheriting the umask.
 */
const EXPECTED = {
  // The native-messaging launcher (executable, 0o755) and its manifest
  // (owner-only): Chrome runs the first and reads the second, both AKA's own
  // files, so their bits are AKA's to set rather than to copy.
  'cli/src/commands/extension.ts#tmp@0': 'constant',
  'cli/src/commands/extension.ts#tmp@1': 'constant',

  // The rewriters of a file the USER owns — a transcript. These must PRESERVE:
  // the remediation runs because the file held a secret, so publishing it wider
  // than it was would be the fix making the file more readable than it was.
  'cli/src/lib/transcript-rewrite.ts#tmpPath': 'preserved',
  'plugins/antigravity/src/remediation/redact.ts#tmpPath': 'preserved',
  'plugins/claude-code/src/history/tail-scrub.ts#tmpPath': 'preserved',
  'plugins/claude-code/src/remediation/redact.ts#tmpPath': 'preserved',
  'plugins/codex/src/remediation/redact.ts#tmpPath': 'preserved',

  // Files AKA owns under `~/.aka`. A constant is right here, and preserving
  // would be wrong: whatever bits a store file drifted to are not a target.
  'packages/persistence/src/paths.ts#tmp': 'via writeExclusiveOwnerOnlySync',
  'packages/plugin-runtime/src/attached/forward-policy.ts#tmp': 'constant',
  'packages/plugin-sdk/src/account/claude-session.ts#tmp': 'constant',
  'plugins/claude-code/src/hooks/message-display-transform.ts#tmp': 'constant',
  'plugins/claude-code/src/mod/handoff.ts#tmp': 'constant',
  'plugins/claude-code/src/protocol/marker.ts#tmp': 'constant',
  'plugins/codex/src/protocol/marker.ts#tmp': 'constant',
};

/** The shape this defect class has every time: a temp written with no mode. */
const UNHARDENED = `
  const tmpPath = \`\${filePath}.aka-redact.tmp\`;
  try {
    writeFileSync(tmpPath, content);
    renameSync(tmpPath, filePath);
  } catch {}
`;

/** The same rewrite with the destination's own bits carried onto the temp. */
const HARDENED = `
  const tmpPath = tempPathFor(filePath);
  const mode = statSync(filePath).mode & 0o777;
  try {
    writeFileSync(tmpPath, content, { mode, flag: 'wx' });
    renameSync(tmpPath, filePath);
  } catch {}
`;

describe('a rewrite published by rename decides the destination mode deliberately', () => {
  it(
    'pins every rename-publish site in the shipped tree',
    () => {
      expect(observedSites()).toEqual(EXPECTED);
    },
    TREE_WALK_TIMEOUT_MS,
  );

  it(
    'finds no site that publishes at the process umask',
    () => {
      const adrift = Object.entries(observedSites()).filter(
        ([, decision]) =>
          decision === 'no-mode' || decision === 'unreadable' || decision === 'unparsed',
      );
      expect(adrift).toEqual([]);
    },
    TREE_WALK_TIMEOUT_MS,
  );

  // Positive control: the table above is only worth something if the derivation
  // can still see the defect. Both snippets are the real thing — the first is
  // the code this class shipped as, the second is what replaced it.
  it('reads the unhardened shape as publishing at the umask', () => {
    expect(publishSites(UNHARDENED)).toEqual([{ source: 'tmpPath', decision: 'no-mode' }]);
    expect(publishSites(HARDENED)).toEqual([{ source: 'tmpPath', decision: 'preserved' }]);
  });

  // Negative control, and the whole reason the property is "rewrites an
  // existing file without preserving its mode" rather than "passes no mode":
  // this writer passes none and is correct, because it creates a new file and
  // so has no prior mode to destroy. The derivation has to stay silent about it
  // for the reason that it renames nothing — not because its write looks fine.
  // A rename the derivation cannot read must fail loudly rather than vanish:
  // a site missing from `observed` would leave the pin green over a writer it
  // never saw. An opener inside a string argument is the case that gets there —
  // the depth scan does not skip literals, so it runs off the end of the file.
  it('reports a rename whose arguments it cannot balance', () => {
    expect(publishSites("renameSync(tmp, '(');\n")).toEqual([
      { source: '<unparsed>', decision: 'unparsed' },
    ]);
  });

  it('says nothing about a writer that creates a new file', () => {
    const file = 'packages/setup-wizard/src/remediation/rotation-checklist.ts';
    const text = readFileSync(join(REPO_ROOT, file), 'utf8');
    const write = calls(text).find((call) => call.name === 'writeFileSync');
    expect(write).toBeDefined();
    expect(modeDecision(text, write)).toBe('no-mode');
    expect(publishSites(text)).toEqual([]);
  });

  // A rename that MOVES a file carries its inode, and its mode with it, so it
  // is not a publish. The snapshot module is nothing but such moves.
  it('does not count a move as a publish', () => {
    const file = 'packages/persistence/src/internal/snapshot.ts';
    const text = readFileSync(join(REPO_ROOT, file), 'utf8');
    expect(/\brenameSync\s*\(/.test(text)).toBe(true);
    expect(publishSites(text)).toEqual([]);
  });
});
