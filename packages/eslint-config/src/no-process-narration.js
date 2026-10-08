// @ts-check
// Bans development-process narration in code comments: plan and spec paths,
// unit/task/section numbers, PR and review-response numbers, commit SHAs and
// dates. A reader at HEAD cannot act on any of it, and it rots the moment the
// plan moves — the history belongs in the planning repo and in git.
//
// Comment CONTENT is not reachable from an AST selector, so `no-restricted-syntax`
// cannot express this; it needs a rule that walks the comment table.

/**
 * Each entry is a named probe so the report says which kind of narration it
 * found. Ordered most- to least-specific: the first match wins per comment.
 *
 * A probe earns its place by PRECISION, not reach. Three kinds were tuned down
 * after a first pass over the real tree fired on `claude-3-5-sonnet-20241022`
 * (a model id, read as a SHA), on `STATUS_DLL_INIT_FAILED (exit 3221225794)`,
 * on "the 2026-01-01 fixtures" (test data being described, not a decision
 * date) and on "what CLAUDE.md §4 promises" (a pointer at the live conventions
 * file, which is exactly where this rule sends people). A ban that cries wolf
 * gets a disable directive, and then it means nothing.
 * @type {ReadonlyArray<{ name: string, re: RegExp, unless?: RegExp }>}
 */
const PROBES = [
  { name: 'a plan or spec path', re: /[\w/-]*plans\/20\d\d-[\w.-]+/ },
  { name: 'an LLD reference', re: /\bLLD\b/ },
  { name: 'a unit number', re: /\bUnits?\s\d+(?:\.\d+)?\b/ },
  { name: 'a task number', re: /\btasks?\s\d+\.\d+\b/ },
  {
    // `§` pointing at the repo's own conventions file is a live cross-reference,
    // not narration; `§` pointing at a plan is what this catches.
    name: 'a document section number',
    re: /§+\s?[\d.]+/,
    // A § belonging to a conventions file, a README, or an EXTERNAL standard is a
    // live cross-reference a reader can follow — only a § into a plan is narration.
    unless:
      /\b(?:AGENTS|CLAUDE|GEMINI|CONTRIBUTING|README|INTERNALS)(?:\.md)?\b|\b(?:RFC|ISO|IEC|ECMA|IETF|W3C|WHATWG|Unicode|TC39|POSIX|NIST|OWASP)\b/,
  },
  { name: 'a review-response number', re: /\breview\sresponses?\s?\d*|\brr\d\b/i },
  // A numeric-only `#nnn` is an issue ref; `#000`-style repeats and `#nnnnnn`
  // are colour shorthands and are left alone (a real colour carries letters).
  {
    name: 'a PR or issue number',
    re: /\b(?:ai-tc|enterprise)\s?#\d+|\bPR\s\d+(?:\/\d+)?\b|(?<![\w#])#(?!(\d)\1{2}\b|\d{6}\b)\d{2,5}(?!\w)/,
  },
  { name: 'a decision or finding label', re: /\bD-?\d\d\b|\bF-\d\d\b|\bINV-\d+\b|\bE\d\d\b/ },
  // A SHA must carry at least one hex LETTER, and — unless it is spelled
  // `oss@<sha>` — sit next to a word that makes it a COMMIT. Hex-looking
  // literals are everywhere in test prose: a fake bearer token
  // (`test-token-abc123456789`), a UUID prefix (`f1f1f1f1…`), an illustrative
  // tenant-id hash. Each of those is example DATA a reader needs, and the first
  // sweep to use this rule hit all three.
  {
    name: 'a commit SHA',
    re: /\boss@(?=[0-9a-f]{8,40}\b)(?=[0-9a-f]*[a-f])[0-9a-f]{8,40}\b|\b(?:commit|sha|pinned?|bump(?:ed)?|revision|rebased?|cherry-picked|merged)\b[^.;]{0,40}?\b(?=[0-9a-f]{8,40}\b)(?=[0-9a-f]*[a-f])[0-9a-f]{8,40}\b|\b(?=[0-9a-f]{8,40}\b)(?=[0-9a-f]*[a-f])[0-9a-f]{8,40}\b[^.;]{0,30}?\b(?:commit|bump|tree|revision)\b/,
  },
  // A date is narration only next to a process cue. Bare dates describe fixture
  // data, retention windows and sample output far more often than decisions.
  {
    name: 'a dated decision',
    re: /\b(?:decided|decision|owner\sdecision|bump(?:ed)?|review(?:ed)?|shipped|landed|merged|superseded|as\sof|measured|ratified|agreed)\b[^.;]{0,60}\b20\d\d-\d\d(?:-\d\d)?\b(?![-\d]*T)|\b20\d\d-\d\d(?:-\d\d)?\b(?![-\d]*T)[^.;]{0,30}\b(?:decision|bump|review|ratified|owner)\b/i,
  },
];

/** Comments that are instructions to a machine, not prose for a reader. */
const MACHINE_READ =
  /eslint-(?:disable|enable)|ts-(?:expect-error|ignore|nocheck)|@ts-|biome-ignore|prettier-ignore|(?:istanbul|c8|v8)\signore|@license|SPDX-|^\s*@\w+/;

/**
 * @typedef {object} NarrationOptions
 * @property {string} [conventionsFile] Repo-local conventions file to name in the message.
 * @property {string[]} [allowPatterns] Regex sources exempting a whole comment.
 * @property {string[]} [disableProbes] Probe names to switch off.
 */

/** @type {import('eslint').Rule.RuleModule} */
export const noProcessNarration = {
  meta: {
    type: 'suggestion',
    docs: {
      description: 'Disallow development-process narration in code comments.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          // Repo-local conventions file to name in the message.
          conventionsFile: { type: 'string' },
          // Regex sources exempting a whole comment (e.g. a generated banner).
          allowPatterns: { type: 'array', items: { type: 'string' } },
          // Probe names to switch off where a package has a standing reason.
          disableProbes: { type: 'array', items: { type: 'string' } },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      narration:
        'This comment carries {{kind}} ("{{match}}"). Development-process history belongs in the planning repo and in git, not at HEAD — state the durable reason instead, or move the context to a folder README.md. See {{file}} "Code comments".',
    },
  },
  create(context) {
    // ESLint types `context.options` as `any[]`; `meta.schema` above validates the shape.
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment -- see above
    const opts = /** @type {NarrationOptions} */ (context.options[0] ?? {});
    const file = opts.conventionsFile ?? 'AGENTS.md';
    const allow = (opts.allowPatterns ?? []).map((p) => new RegExp(p));
    const off = new Set(opts.disableProbes ?? []);
    const probes = PROBES.filter((p) => !off.has(p.name));
    const source = context.sourceCode;

    return {
      Program() {
        for (const comment of source.getAllComments()) {
          const text = comment.value;
          if (MACHINE_READ.test(text) || allow.some((re) => re.test(text))) continue;
          for (const probe of probes) {
            if (probe.unless?.test(text)) continue;
            const m = probe.re.exec(text);
            if (!m) continue;
            context.report({
              loc: /** @type {import('eslint').AST.SourceLocation} */ (comment.loc),
              messageId: 'narration',
              data: { kind: probe.name, match: m[0], file },
            });
            break;
          }
        }
      },
    };
  },
};

/** Flat-config plugin object carrying the rule. */
export const commentNarrationPlugin = {
  rules: { 'no-process-narration': noProcessNarration },
};
