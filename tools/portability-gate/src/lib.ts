// Pure scanning logic for the cross-platform portability gate: a lightweight,
// non-parsing scanner over the tracked test and bench trees looking for six
// known failure shapes — a hardcoded file:/// URL (POSIX-only, breaks on Windows),
// a bare GNU `timeout` shell command (absent on macOS), a path comparison
// with no case normalization (macOS/Windows are case-insensitive, Linux is
// not), a worker/concurrency test with no explicit timeout, a PATH built
// with a literal ':' (Windows joins with ';'), and a platform guard that ends a
// test body with a bare `return` (reported as a PASS on every platform that
// cannot run it). The CLI entry (check-portability.ts) owns all I/O — git
// ls-files, reading file contents — so the unit suite can drive this with
// canned file lists.
//
// Rules 1-3 and 5 describe primitives, not test structure, so they apply to every
// source file in a test or bench tree — the helpers, fixtures-in-code, worker
// entrypoints and benchmark drivers that carry the worker/platform/path code a
// spec file usually only calls. Rules 4 and 6 are about what a TEST reports, so
// both stay scoped to spec files, which a `.bench.ts` is not. isRelevantPath is
// the single definition of what the scan reaches; the CLI entry imports it
// rather than keeping a second copy, since a filter that pre-selects paths and
// a filter that scans them are one decision.
//
// This is a heuristic text scanner, not a real parser. It tokenizes just far
// enough to tell code from string/template literals and comments (and to give
// regex literals opaque treatment, since a quote inside a character class —
// e.g. /["']/ — would otherwise be misread as the start of a string), then
// pattern-matches within each. Rules 1 and 2 are mechanical and reliable:
// they only fire on characters that are unambiguously part of a string
// literal. Rules 3, 4, 5 and 6 are best-effort: they cannot see a comparison split
// across lines or routed through an intermediate variable, and rule 3 in
// particular only catches two path-producing expressions compared directly on
// one line. Rule 5 needs the word PATH to be code on the separator's own line
// or on the line its literal opens, so a separator held in a named constant, or
// a PATH assembled several statements away from the ':' it is joined with, goes
// unseen. Rule 6 locates its guard on the masked text, so a comment between the
// guard and the `return` does NOT hide it; what it cannot see is a condition
// carrying a call (the condition class stops at the first `)`) or a guard moved
// into a helper the test calls. Rule 6 is also the one rule here that
// OVER-reports: it matches text, not scope, so a `return` under a platform guard
// inside a nested callback — a loop `continue`, which neither ends the test nor
// skips an assertion — is reported as though it were the defect. Treat their
// silence as "found nothing," not "there is nothing."

export interface ScannedFile {
  path: string;
  content: string;
}

export type RuleId =
  | 'hardcoded-file-url'
  | 'bare-timeout-command'
  | 'path-comparison-case'
  | 'concurrency-missing-timeout'
  | 'path-separator-literal'
  | 'platform-guard-early-return'
  | 'platform-guard-stale-allowance';

export interface RuleInfo {
  title: string;
  help: string;
}

export const RULES: Record<RuleId, RuleInfo> = {
  'hardcoded-file-url': {
    title: 'Hardcoded file:/// URL',
    help: 'use pathToFileURL() instead of a literal file:/// string — a hand-written absolute-path URL is POSIX-only and breaks on Windows.',
  },
  'bare-timeout-command': {
    title: 'GNU timeout in a shell command',
    help: "the timeout coreutil is not on macOS by default; the command exits 127 immediately, which reads like a hung test rather than a missing binary. Use vitest's own testTimeout/hookTimeout instead.",
  },
  'path-comparison-case': {
    title: 'Path comparison without case normalization',
    help: 'macOS and Windows filesystems are case-insensitive, Linux is not — add .toLowerCase() before comparing two paths directly, or confirm the comparison is deliberately case-sensitive.',
  },
  'concurrency-missing-timeout': {
    title: 'Concurrency/worker test with no explicit timeout',
    help: "a test that spawns a worker or waits on concurrent I/O can outrun vitest's 5s default under CI load. Either raise testTimeout/hookTimeout for the whole package (see plugins/claude-code/vitest.config.ts) or pass an explicit timeout to this test.",
  },
  'path-separator-literal': {
    title: "PATH joined or split on a literal ':'",
    help: "Windows joins PATH with ';', so a ':'-joined value is one malformed entry there and a prepended bin dir is not on PATH at all. Use path.delimiter. This one fails OPEN, which is why it is worth a rule: a test shim that does not land is not an ENOENT — resolution walks on and runs the REAL installed binary, so the suite reaches a live tool while still looking hermetic (see plugins/*/test/helpers/path-shim.ts).",
  },
  'platform-guard-early-return': {
    title: 'Platform guard that ends the test body with a bare return',
    help: "a returning test is a PASSING test, so on every platform the guard excludes this case reports as covered while reaching no assertion at all — and the property it exists to pin can then be deleted with CI still green. Say so instead: take the test context and call ctx.skip('<why this platform cannot run it>') at the top of the body. Where the test does still assert something on the guarded platform, keep it running and gate only the platform-specific assertions — `if (process.platform !== 'win32') expect(…)` — since a skip there throws away a real result.",
  },
  'platform-guard-stale-allowance': {
    title: 'Grandfathered platform-guard allowance is larger than the file',
    help: 'a file carrying fewer guards than its recorded allowance leaves room for new ones to land unnoticed, which is the hole the allowance exists to close. Lower the number in GRANDFATHERED_PLATFORM_GUARDS to what the file now carries, or delete the entry once it carries none.',
  },
};

// Files that already carried rule 6's shape when it was written, with the exact
// number of guards each may keep. It held three suites when the rule landed, all
// six of their guards have since been converted, and it is now EMPTY — so rule 6
// reports every guard in every spec file, with nothing exempt.
//
// The mechanism stays because the map is the only way to add a rule of this kind
// to a tree that already carries its shape: a backlog nobody can clear in one go
// is exempted here rather than turned into a wall of violations that gets
// switched off instead. Filling it again is a deliberate edit, and the ratchet
// below is what makes it a shrinking one.
//
// One consequence of the map being empty: `platform-guard-stale-allowance` can no
// longer fire on a real scan at all — every allowance resolves to 0, and its
// condition is `lines.length < 0`. That is a ratchet with nothing left to ratchet,
// NOT dead code, and its coverage now rests entirely on the injected-map cases in
// the unit suite. Deleting it because no real file reaches it would remove the
// half of the ratchet that stops an exemption growing back the day one is added.
//
// An allowance is an exact COUNT, pinned in both directions: exceeding it is a
// violation, and falling below it is one too (`platform-guard-stale-allowance`),
// so converting a guard means lowering the number in the same commit. A file
// that reaches zero leaves the map entirely.
//
// That makes the NUMBER a ratchet, never the set of guards behind it. A commit
// converting one guard and adding another holds the count at the allowance and
// passes both rules, so a new guard CAN land in an exempt file when it arrives
// paired with a conversion. Closing that needs guard identity — either a line
// number, which shifts on any unrelated edit, or the enclosing test name — so
// the count stands and the limit is written down instead. The exposure is the
// map: a file with no allowance reports every guard in it, which is now every
// file.
//
// An allowance is keyed by PATH, so a rename leaves it behind: the entry then
// covers nothing and the file arrives with an allowance of zero, which reports
// every guard in it. That is loud and correct. A DELETED file's entry is the one
// case nothing reports — it is dead weight rather than a hole, since it can only
// ever exempt a path the scan never sees.
export const GRANDFATHERED_PLATFORM_GUARDS: Readonly<Record<string, number>> = {};

export interface Violation {
  rule: RuleId;
  file: string;
  line: number;
  message: string;
}

interface StringSegment {
  text: string;
  line: number;
  start: number;
}

interface TokenizeResult {
  codeMasked: string;
  strings: StringSegment[];
}

// A '/' is a regex literal opener rather than division only in certain
// syntactic positions; this is the standard (if approximate) lookbehind used
// by lightweight lexers. It does not need to be exact — getting it wrong just
// means a regex is scanned as code (or vice versa), and the two callers that
// consume codeMasked (rules 3 and 4) only look for path/comparison/concurrency
// tokens that are vanishingly unlikely to appear inside a regex body.
const REGEX_PRECEDING =
  /(?:^|[(,=:!&|?{[;+\-*%^~<>]|\breturn|\btypeof|\binstanceof|\bnew|\bdelete|\bvoid|\bthrow|\byield|\bcase|\bdo|\belse|\bin|\bof)\s*$/;

// Tokenizes just enough to separate code from strings/templates and
// comments/regex bodies. codeMasked is always the same length as source, with
// every non-code character replaced by a space (newlines preserved), so a
// line number or index computed against it is a real line number in source.
function tokenize(source: string): TokenizeResult {
  const masked: string[] = [];
  const strings: StringSegment[] = [];
  let line = 1;
  let i = 0;
  const n = source.length;
  let codeTail = '';

  const emitMasked = (ch: string): void => {
    masked.push(ch === '\n' ? '\n' : ' ');
    if (ch === '\n') line++;
  };
  const emitCode = (ch: string): void => {
    masked.push(ch);
    if (ch === '\n') {
      line++;
      codeTail = '';
    } else {
      codeTail = (codeTail + ch).slice(-20);
    }
  };

  while (i < n) {
    const ch = source.charAt(i);
    const next = source.charAt(i + 1);

    if (ch === '/' && next === '/') {
      while (i < n && source.charAt(i) !== '\n') {
        emitMasked(source.charAt(i));
        i++;
      }
      continue;
    }

    if (ch === '/' && next === '*') {
      emitMasked(ch);
      emitMasked(next);
      i += 2;
      while (i < n && !(source.charAt(i) === '*' && source.charAt(i + 1) === '/')) {
        emitMasked(source.charAt(i));
        i++;
      }
      if (i < n) {
        emitMasked(source.charAt(i));
        emitMasked(source.charAt(i + 1));
        i += 2;
      }
      continue;
    }

    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch;
      const startLine = line;
      const startIndex = i;
      let content = '';
      emitMasked(ch);
      i++;
      while (i < n && source.charAt(i) !== quote) {
        const c = source.charAt(i);
        if (c === '\\' && i + 1 < n) {
          const escaped = source.charAt(i + 1);
          content += c + escaped;
          emitMasked(c);
          emitMasked(escaped);
          i += 2;
          continue;
        }
        content += c;
        emitMasked(c);
        i++;
      }
      if (i < n) {
        emitMasked(source.charAt(i));
        i++;
      }
      strings.push({ text: content, line: startLine, start: startIndex });
      continue;
    }

    if (ch === '/' && REGEX_PRECEDING.test(`${codeTail} `)) {
      let j = i + 1;
      let inClass = false;
      let closed = false;
      while (j < n) {
        const c = source.charAt(j);
        if (c === '\\') {
          j += 2;
          continue;
        }
        if (c === '[') inClass = true;
        else if (c === ']') inClass = false;
        else if (c === '/' && !inClass) {
          closed = true;
          break;
        } else if (c === '\n') {
          break;
        }
        j++;
      }
      if (closed) {
        while (i <= j) {
          emitMasked(source.charAt(i));
          i++;
        }
        while (i < n && /[a-z]/i.test(source.charAt(i))) {
          emitMasked(source.charAt(i));
          i++;
        }
        continue;
      }
      // No closing '/' before EOL — not actually a regex literal (e.g. a
      // division). Fall through and let it emit as ordinary code below.
    }

    emitCode(ch);
    i++;
  }

  return { codeMasked: masked.join(''), strings };
}

function lineAt(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source[i] === '\n') line++;
  }
  return line;
}

const TIMEOUT_CMD_RE = /(?:^|[;&|]\s*)\s*timeout\s+\S/;

const PATH_CALL_RE = /\bpath\.(?:resolve|join|normalize|dirname|basename|relative)\(/;
const COMPARISON_RE = /===|!==|\.toBe\(|\.toEqual\(/;

// Deliberately scoped to async/non-blocking primitives: a worker thread or an
// async spawn genuinely races against the rest of the test under parallel CI
// load, which is the failure mode this rule exists for. A *Sync call (execFileSync,
// spawnSync) blocks the test thread until it returns — if it is slow, the test
// is slow, which is a different problem than "outran the timeout while something
// else was still running" and produces far noisier signal for far less reason
// (e.g. a one-line `git ls-files` probe is exactly as "synchronous subprocess" as
// a slow `npm install`, and the function name alone cannot tell them apart).
const CONCURRENCY_RE =
  /\bnew\s+Worker\b|\bworker_threads\b|Promise\.(?:all|race|allSettled)\(|\bspawn\(|\bfork\(/;
// The leading lookbehind is what keeps this off a member call. `\b` alone
// matches the `test(` in `RE.test(`, because `.` is a non-word character and
// so opens a word boundary — and that is not merely noisy, it mislocates the
// scan: the match starts mid-body, so the block runs from there to the
// enclosing call's close paren and never reaches the real call's trailing
// timeout argument. A correctly written test carrying `}, 30_000)` is then
// reported as having no timeout, at the line of the `.test(` call.
const TEST_CALL_RE = /(?<![.\w])(?:it|test)\s*\(/g;

// A JS identifier, optionally reached through a member expression, so a
// timeout held in a named constant (CASE_TIMEOUT_MS) or on an object
// (timeouts.worker) reads as a timeout rather than as an absent one.
const IDENTIFIER = String.raw`[A-Za-z_$][\w$]*(?:\.[\w$]+)*`;
// A numeric literal including underscore separators — 20_000 is the same
// value as 20000 and just as deliberate.
const NUMERIC = String.raw`\d[\d_]*`;

// The trailing argument of an it()/test() call is the per-test timeout and
// nothing else, so an identifier there is taken at face value. The end anchor
// is what keeps that safe: a block only ends in `, <arg>)` when that arg is
// the call's own last argument, never when it is an argument to something
// nested inside the callback.
const INLINE_TIMEOUT_RE = new RegExp(String.raw`,\s*(${IDENTIFIER}|${NUMERIC})\s*,?\s*\)\s*;?\s*$`);
// An explicitly keyed `timeout:` needs no plausibility floor — naming the key
// is the deliberate act.
const OPTIONS_TIMEOUT_RE = new RegExp(String.raw`\btimeout\s*:\s*(?:${NUMERIC}|${IDENTIFIER})`);

// Below this a trailing numeric argument is more likely a count or an index
// than a timeout; a real one is at least a substantial fraction of a second.
const MIN_PLAUSIBLE_TIMEOUT_MS = 100;

function hasInlineTimeout(block: string): boolean {
  const argument = INLINE_TIMEOUT_RE.exec(block)?.[1];
  if (argument === undefined) return false;
  if (!/^\d/.test(argument)) return true;
  return Number(argument.replaceAll('_', '')) >= MIN_PLAUSIBLE_TIMEOUT_MS;
}

function findMatchingClose(codeMasked: string, openIndex: number): number {
  let depth = 0;
  for (let i = openIndex; i < codeMasked.length; i++) {
    const c = codeMasked[i];
    if (c === '(' || c === '{' || c === '[') depth++;
    else if (c === ')' || c === '}' || c === ']') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return codeMasked.length - 1;
}

// The string immediately after `it(`/`describe(`/`test(` is a human-readable
// name, not a runtime value — a test titled "flags a hardcoded file:/// URL"
// or "does not shell out to timeout 5" is describing the bug in prose, not
// committing it. Excluded from rules 1 and 2 only: it is still real code for
// rules 3 and 4, which do not key on string content in the first place.
const DESCRIPTION_CALL_RE = /\b(?:it|describe|test)\s*\($/;

function isTestDescriptionString(codeMasked: string, stringStart: number): boolean {
  const before = codeMasked.slice(Math.max(0, stringStart - 40), stringStart);
  return DESCRIPTION_CALL_RE.test(before.trimEnd());
}

function checkHardcodedFileUrl(
  file: ScannedFile,
  codeMasked: string,
  strings: StringSegment[],
): Violation[] {
  return strings
    .filter((s) => s.text.includes('file:///') && !isTestDescriptionString(codeMasked, s.start))
    .map((s) => ({
      rule: 'hardcoded-file-url' as const,
      file: file.path,
      line: s.line,
      message: `Hardcoded "file:///" URL in a string literal — ${RULES['hardcoded-file-url'].help}`,
    }));
}

function checkBareTimeoutCommand(
  file: ScannedFile,
  codeMasked: string,
  strings: StringSegment[],
): Violation[] {
  return strings
    .filter((s) => TIMEOUT_CMD_RE.test(s.text) && !isTestDescriptionString(codeMasked, s.start))
    .map((s) => ({
      rule: 'bare-timeout-command' as const,
      file: file.path,
      line: s.line,
      message: `Shell command invokes "timeout" — ${RULES['bare-timeout-command'].help}`,
    }));
}

function checkPathComparisonCase(file: ScannedFile, codeMasked: string): Violation[] {
  const violations: Violation[] = [];
  for (const [index, line] of codeMasked.split('\n').entries()) {
    if (PATH_CALL_RE.test(line) && COMPARISON_RE.test(line) && !line.includes('.toLowerCase()')) {
      violations.push({
        rule: 'path-comparison-case',
        file: file.path,
        line: index + 1,
        message: `Path comparison with no ".toLowerCase()" on the line — ${RULES['path-comparison-case'].help}`,
      });
    }
  }
  return violations;
}

// A PATH the code builds or takes apart itself. `\bPATH\b` is deliberately
// case-sensitive and boundary-anchored: it reaches `PATH:`, `env.PATH` and
// `process.env.PATH`, and stays off `filePath` (no boundary, wrong case) and
// `SCRIPTS_PATH` (an underscore is a word character, so no boundary either).
const PATH_TOKEN_RE = /\bPATH\b/;
// The two shapes a POSIX-only separator takes. A template interpolating either
// side of a bare colon (`${dir}:${rest}`), and a lone ':' as a whole string,
// which is what a .join(':')/.split(':') argument or a concatenation reads as.
// A colon anywhere else in a longer literal is left alone — that is a path, a
// URL or a label far more often than a separator.
const PATH_JOIN_TEMPLATE = '}:${';
const LONE_COLON = ':';

// Every line a separator literal actually occupies. A template literal can span
// lines, and s.line is only where it OPENS — so a PATH built across lines has
// its `}:${` on a line the segment's start never names. Reporting (and testing
// for the PATH token at) the opening line alone both misses those and points the
// reader at the wrong line when it does fire.
function separatorLines(segment: StringSegment): number[] {
  if (segment.text === LONE_COLON) return [segment.line];
  const lines: number[] = [];
  let searchFrom = 0;
  for (;;) {
    const at = segment.text.indexOf(PATH_JOIN_TEMPLATE, searchFrom);
    if (at === -1) break;
    // +1 for the opening quote, which is not part of text.
    const newlines = segment.text.slice(0, at).split('\n').length - 1;
    lines.push(segment.line + newlines);
    searchFrom = at + PATH_JOIN_TEMPLATE.length;
  }
  return lines;
}

function checkPathSeparatorLiteral(
  file: ScannedFile,
  codeMasked: string,
  strings: StringSegment[],
): Violation[] {
  const codeLines = codeMasked.split('\n');
  // The PATH token has to be code on the separator's own line or on the line the
  // literal opens (a single-line build is both), so a colon-joined string with
  // nothing to do with the environment variable stays quiet — and a `PATH` that
  // appears only inside a comment or a test description is masked out and so
  // does not count as naming one.
  const namesPath = (line: number): boolean => PATH_TOKEN_RE.test(codeLines[line - 1] ?? '');
  const flagged = new Set<number>();
  for (const segment of strings) {
    if (!segment.text.includes(PATH_JOIN_TEMPLATE) && segment.text !== LONE_COLON) continue;
    for (const line of separatorLines(segment)) {
      if (namesPath(line) || namesPath(segment.line)) flagged.add(line);
    }
  }
  // One violation per line however many literals sit on it: two reports of the
  // same defect at the same place is noise a reader has to reconcile.
  return [...flagged]
    .sort((a, b) => a - b)
    .map((line) => ({
      rule: 'path-separator-literal' as const,
      file: file.path,
      line,
      message: `PATH built or split on a literal ":" — ${RULES['path-separator-literal'].help}`,
    }));
}

// Located on codeMasked, so a `process.platform` named in a comment or quoted in
// a test description is not a candidate at all.
const PLATFORM_GUARD_RE = /\bif\s*\(\s*process\.platform\b/g;
// Matched on codeMasked, then the RETURNED EXPRESSION is read back out of the
// raw source. Both halves are load-bearing and they pull in opposite directions:
//
//   - Structure has to come from the masked text, because a comment is blanked
//     to spaces there. Read the raw source for structure instead and a block
//     that explains itself first —
//     `if (…) {\n  // no POSIX modes here\n  return;\n}` — stops matching, which
//     is the defect wearing the most natural comment anyone would write.
//   - Whether anything is RETURNED has to come from the raw source, because a
//     literal is blanked to spaces in the masked text. Read the masked text for
//     that instead and `return '<reason>';` reads as bare — a helper handing its
//     caller a skip reason, flagged as a test bailing out. That is not
//     hypothetical: it is
//     packages/plugin-sdk/test/performance/project-files-walk.test.ts.
//
// codeMasked is the same length as the source, so the capture's offsets index
// both alike. Returning a VALUE is the helper signal, so `return undefined;`
// is deliberately NOT flagged — a helper typed `(): string | undefined` returns
// it legitimately, and a test body bailing out that way is a spelling nobody
// reaches for.
//
// `[^)\n]*` holds the condition to one line and to no nested parens, so
// `process.platform === 'win32' || process.platform === 'linux'` matches while a
// condition carrying a call does not. The consequent is a `return` either
// trailing on the same line or alone in a block — a block that does anything
// first (`ctx.skip(reason); return;`, the fixed form) is not a match, because
// that statement is code and survives masking.
// Sticky rather than anchored: `y` matches at lastIndex, which lets the guard be
// located in place instead of slicing a fresh copy of the file tail per match.
const PLATFORM_EARLY_RETURN_RE =
  /if\s*\(\s*process\.platform\s*[!=]==?[^)\n]*\)\s*(?:\{\s*return([^;{}]*);\s*\}|return([^;\n]*);)/dy;

function checkPlatformGuardEarlyReturn(
  file: ScannedFile,
  codeMasked: string,
  allowance: number,
): Violation[] {
  const lines: number[] = [];
  PLATFORM_GUARD_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = PLATFORM_GUARD_RE.exec(codeMasked)) !== null) {
    PLATFORM_EARLY_RETURN_RE.lastIndex = match.index;
    const consequent = PLATFORM_EARLY_RETURN_RE.exec(codeMasked);
    if (consequent === null) continue;
    const groups = consequent.indices;
    // The `d` flag is what makes the raw-source read below possible at all, so a
    // missing `indices` is a broken rule rather than a clean file — skipping
    // here would disable rule 6 across the whole tree with lint still green.
    if (groups === undefined) {
      throw new Error(
        'platform-guard-early-return: regex lost its `d` flag, so no guard can be read',
      );
    }
    const span = groups[1] ?? groups[2];
    if (span === undefined) continue;
    const returned = file.content.slice(span[0], span[1]);
    if (returned.trim() !== '') continue;
    lines.push(lineAt(codeMasked, match.index));
  }

  if (lines.length < allowance) {
    return [
      {
        rule: 'platform-guard-stale-allowance',
        file: file.path,
        line: 1,
        message: `Allowance of ${String(allowance)} but the file carries ${String(lines.length)} — ${RULES['platform-guard-stale-allowance'].help}`,
      },
    ];
  }
  // The allowance covers the guards that were already here, so the ones past it
  // are the new ones. Reporting the tail rather than the head puts the violation
  // on a line the author just wrote.
  return lines.slice(allowance).map((line) => ({
    rule: 'platform-guard-early-return' as const,
    file: file.path,
    line,
    message: `Platform guard returns instead of skipping — ${RULES['platform-guard-early-return'].help}`,
  }));
}

function checkConcurrencyMissingTimeout(
  file: ScannedFile,
  codeMasked: string,
  packageHasTestTimeout: boolean,
): Violation[] {
  if (packageHasTestTimeout) return [];
  const violations: Violation[] = [];
  TEST_CALL_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = TEST_CALL_RE.exec(codeMasked)) !== null) {
    const openParen = codeMasked.indexOf('(', match.index);
    if (openParen === -1) continue;
    const close = findMatchingClose(codeMasked, openParen);
    const block = codeMasked.slice(openParen, close + 1);
    if (!CONCURRENCY_RE.test(block)) continue;
    if (hasInlineTimeout(block) || OPTIONS_TIMEOUT_RE.test(block)) continue;
    violations.push({
      rule: 'concurrency-missing-timeout',
      file: file.path,
      line: lineAt(codeMasked, match.index),
      message: `Test spawns a worker/concurrency primitive with no explicit timeout, and the package sets no testTimeout override — ${RULES['concurrency-missing-timeout'].help}`,
    });
  }
  return violations;
}

// A spec file: the unit rule 4 walks, wherever it sits in the tree.
const SPEC_FILE_RE = /\.test\.(?:ts|tsx|js|mjs|cts|mts)$/;
// Any source file under a directory named "test", "bench" or "eval" — the
// helpers, worker entrypoints, fixture corpora, benchmark drivers and prompt
// contracts rules 1-3 apply to. A benchmark carries the same subject matter as
// a spec (chdir descent, symlink loops, PATH_MAX ceilings that differ between
// platforms), so it is covered by where it sits rather than by whichever shared
// fixture it happens to call.
//
// `eval` is here for that same reason and was added after it cost something: a
// native separator leaked out of `relative()` into a value compared against
// posix literals in `plugins/claude-code/eval/prompt-contract.ts`, which three
// test files import — test-support code by every measure except the name of its
// directory. Nothing scanned it, because `eval/` matched neither this list nor
// SPEC_FILE_RE. The rule that would have caught it already existed.
//
// The cut is by extension alone, so a fixture that deliberately holds
// a bad pattern is only exempt while it is data (.txt, .json); written as real
// .ts under one of these trees it is scanned like anything else, which is why
// this package keeps its own violation fixtures at .txt.
//
// Spelled as a substring search rather than as one regex. The regex form
// `(?:^|\/)test\/.*\.(?:ts|…)$` gives the engine a viable start position at
// every `/test/` segment and rescans the tail from each, so a path that does
// not match costs time quadratic in the number of segments. Reaching that
// needs a committed path, since the input is git ls-files output — but this
// gate runs on every push, so it stays linear by construction.
const TREE_DIR_NAMES = ['test', 'bench', 'eval'] as const;
const SOURCE_EXT_RE = /\.(?:ts|tsx|js|mjs|cts|mts)$/;

function isTreeFile(path: string): boolean {
  if (!SOURCE_EXT_RE.test(path)) return false;
  return TREE_DIR_NAMES.some((dir) => path.startsWith(`${dir}/`) || path.includes(`/${dir}/`));
}

const VITEST_CONFIG_SUFFIX = '/vitest.config.ts';
const VITEST_CONFIG_RE = /(?:^|\/)vitest\.config\.ts$/;

// Everything the scan needs handed to it: the files it applies rules to, plus
// every vitest.config.ts, which is how rule 4 resolves a package-level
// testTimeout override. The CLI entry filters on this before reading any file
// content, so a repo-wide walk touches only what matters.
export function isRelevantPath(path: string): boolean {
  return SPEC_FILE_RE.test(path) || isTreeFile(path) || VITEST_CONFIG_RE.test(path);
}

interface PackageTimeoutInfo {
  dir: string;
  hasTestTimeout: boolean;
}

function derivePackageTimeouts(files: ScannedFile[]): PackageTimeoutInfo[] {
  return files
    .filter((f) => VITEST_CONFIG_RE.test(f.path))
    .map((f) => ({
      dir: f.path.endsWith(VITEST_CONFIG_SUFFIX)
        ? f.path.slice(0, -VITEST_CONFIG_SUFFIX.length)
        : '',
      hasTestTimeout: /\btestTimeout\s*:/.test(f.content),
    }));
}

// The package whose vitest.config.ts directory is the longest matching
// ancestor of the file — i.e. the nearest one, in case a future package ever
// nests under another.
function owningPackageHasTimeout(filePath: string, packages: PackageTimeoutInfo[]): boolean {
  let best: PackageTimeoutInfo | undefined;
  for (const pkg of packages) {
    const isAncestor = pkg.dir === '' ? true : filePath.startsWith(`${pkg.dir}/`);
    if (isAncestor && (!best || pkg.dir.length > best.dir.length)) best = pkg;
  }
  return best?.hasTestTimeout ?? false;
}

export interface ScanOptions {
  // Defaults to GRANDFATHERED_PLATFORM_GUARDS. Overridden by the unit suite so
  // rule 6's allowance arithmetic is driven with synthetic paths rather than by
  // asserting the contents of the real exempt files, which would put a second,
  // stale copy of that list in the tests.
  grandfatheredPlatformGuards?: Readonly<Record<string, number>>;
}

// Which allowance map a scan runs under: the caller's, else the shipped one.
// Split out so that binding is assertable by IDENTITY, which is the only way to
// reach it while the shipped map is empty — an empty map and a missing default
// produce byte-identical violations, so nothing about the scan's OUTPUT can
// separate them.
//
// Be precise about how far that reaches, because the gap it leaves is exactly
// the one it looks like it closed. The identity test pins that THIS function
// reads the constant. It does not pin that `scanTree` still calls this function:
// rewrite the call below to `options.grandfatheredPlatformGuards ?? {}` and the
// whole suite stays green, for the same unobservability reason. What covers that
// is the source assertion in the unit suite, which is reaching for the shape this
// repo uses where behaviour cannot get there (see plugin-sdk's data-dir.test.ts).
// Re-filling the map retires both workarounds: an exemption that exempts
// something is observable again, and a behavioural case should replace them.
export function resolveGrandfatheredGuards(options: ScanOptions): Readonly<Record<string, number>> {
  return options.grandfatheredPlatformGuards ?? GRANDFATHERED_PLATFORM_GUARDS;
}

// files is the whole set the caller found worth handing in — vitest configs
// are needed to resolve rule 4's package-level override and are silently
// skipped by the SPEC_FILE_RE filter below, so passing every tracked file is
// fine and expected.
export function scanTree(files: ScannedFile[], options: ScanOptions = {}): Violation[] {
  const grandfathered = resolveGrandfatheredGuards(options);
  const packages = derivePackageTimeouts(files);
  const violations: Violation[] = [];
  for (const file of files) {
    const isSpec = SPEC_FILE_RE.test(file.path);
    if (!isSpec && !isTreeFile(file.path)) continue;
    const { codeMasked, strings } = tokenize(file.content);
    violations.push(
      ...checkHardcodedFileUrl(file, codeMasked, strings),
      ...checkBareTimeoutCommand(file, codeMasked, strings),
      ...checkPathComparisonCase(file, codeMasked),
      ...checkPathSeparatorLiteral(file, codeMasked, strings),
      ...(isSpec
        ? [
            ...checkConcurrencyMissingTimeout(
              file,
              codeMasked,
              owningPackageHasTimeout(file.path, packages),
            ),
            ...checkPlatformGuardEarlyReturn(file, codeMasked, grandfathered[file.path] ?? 0),
          ]
        : []),
    );
  }
  return violations.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

export function formatReport(violations: Violation[]): string {
  if (violations.length === 0) return 'Portability check passed: no violations found.';
  const lines = [`Portability check failed: ${String(violations.length)} violation(s).`, ''];
  for (const v of violations) {
    lines.push(`${v.file}:${String(v.line)} [${v.rule}]`, `  ${v.message}`, '');
  }
  return lines.join('\n').trimEnd();
}
