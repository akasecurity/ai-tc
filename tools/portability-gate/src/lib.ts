// Pure scanning logic for the cross-platform portability gate: a lightweight,
// non-parsing scanner over the tracked test tree looking for four known
// failure shapes — a hardcoded file:/// URL (POSIX-only, breaks on Windows),
// a bare GNU `timeout` shell command (absent on macOS), a path comparison
// with no case normalization (macOS/Windows are case-insensitive, Linux is
// not), and a worker/concurrency test with no explicit timeout. The CLI entry
// (check-portability.ts) owns all I/O — git ls-files, reading file contents —
// so the unit suite can drive this with canned file lists.
//
// This is a heuristic text scanner, not a real parser. It tokenizes just far
// enough to tell code from string/template literals and comments (and to give
// regex literals opaque treatment, since a quote inside a character class —
// e.g. /["']/ — would otherwise be misread as the start of a string), then
// pattern-matches within each. Rules 1 and 2 are mechanical and reliable:
// they only fire on characters that are unambiguously part of a string
// literal. Rules 3 and 4 are best-effort: they cannot see a comparison split
// across lines or routed through an intermediate variable, and rule 3 in
// particular only catches two path-producing expressions compared directly on
// one line. Treat their silence as "found nothing," not "there is nothing."

export interface ScannedFile {
  path: string;
  content: string;
}

export type RuleId =
  | 'hardcoded-file-url'
  | 'bare-timeout-command'
  | 'path-comparison-case'
  | 'concurrency-missing-timeout';

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
};

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
const TEST_CALL_RE = /\b(?:it|test)\s*\(/g;
const INLINE_TIMEOUT_RE = /,\s*\d{3,}\s*,?\s*\)\s*;?\s*$/;
const OPTIONS_TIMEOUT_RE = /\btimeout\s*:\s*\d+/;

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
    if (INLINE_TIMEOUT_RE.test(block) || OPTIONS_TIMEOUT_RE.test(block)) continue;
    violations.push({
      rule: 'concurrency-missing-timeout',
      file: file.path,
      line: lineAt(codeMasked, match.index),
      message: `Test spawns a worker/concurrency primitive with no explicit timeout, and the package sets no testTimeout override — ${RULES['concurrency-missing-timeout'].help}`,
    });
  }
  return violations;
}

const TEST_FILE_RE = /\.test\.(?:ts|tsx|js)$/;
const VITEST_CONFIG_SUFFIX = '/vitest.config.ts';
const VITEST_CONFIG_RE = /(?:^|\/)vitest\.config\.ts$/;

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

// files is the whole set the caller found worth handing in — vitest configs
// are needed to resolve rule 4's package-level override and are silently
// skipped by the TEST_FILE_RE filter below, so passing every tracked file is
// fine and expected.
export function scanTree(files: ScannedFile[]): Violation[] {
  const packages = derivePackageTimeouts(files);
  const violations: Violation[] = [];
  for (const file of files) {
    if (!TEST_FILE_RE.test(file.path)) continue;
    const { codeMasked, strings } = tokenize(file.content);
    violations.push(
      ...checkHardcodedFileUrl(file, codeMasked, strings),
      ...checkBareTimeoutCommand(file, codeMasked, strings),
      ...checkPathComparisonCase(file, codeMasked),
      ...checkConcurrencyMissingTimeout(
        file,
        codeMasked,
        owningPackageHasTimeout(file.path, packages),
      ),
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
