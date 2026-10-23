// Protected paths: which file paths a tool call names that the user has marked
// off-limits, and which path-like words a shell command carries.
//
// ENTRY DIALECT. Each entry of the user's list is one of:
//
//   - an absolute folder or file: `/srv/data`, `~/Documents`, `C:\Users\me\Vault`.
//     It protects that path and everything beneath it. `~` and `~/…` expand to
//     the home directory; `~user` is not expanded.
//   - a glob, absolute or not. Segments are separated by `/` or `\`. Inside a
//     segment `*` matches any run of characters and `?` exactly one; a segment
//     that is exactly `**` matches any number of whole segments, including none.
//     Nothing else is special: `[a-z]`, `{a,b}` and a leading `!` are ordinary
//     characters, and there is no negation.
//   - an entry that is not absolute is floating: it is read as `**/<entry>`, so
//     `passwords*.txt`, `.ssh/*.pem` and `secrets` match at any depth.
//
// An entry protects a path when it matches the path or any ancestor of it, so a
// pattern that names a folder covers everything inside. Matching ignores case.
// Both sides are normalized first: `\` becomes `/`, repeated separators
// collapse, and `.` and `..` segments are resolved before anything is compared.
// A relative candidate is placed against the working directory.
//
// SYMLINKS. When the caller supplies `realpath`, a candidate is also checked
// under the path it resolves to, and a literal entry under the path it
// resolves to, so a link into a protected folder and a protected folder that is
// itself a link are both caught. Without it only the spelled path is checked.
//
// WHAT THIS CANNOT SEE in a shell command (bashPathCandidates): a variable
// other than a leading `$HOME`, a path assembled by a subshell or by string
// concatenation, a glob the shell expands (`cat ~/Documents/pass*` is compared
// as spelled), brace expansion, a directory the command changes into first
// (`cd dir && cat file` resolves `file` against the session's directory), a
// path read from a file or from standard input, and anything an interpreter
// builds at run time. It also reports words that are not paths. It is a
// best-effort screen over the command text, never a sandbox.

import { realpathSync } from 'node:fs';
import { join } from 'node:path';

import { MAX_PROTECTED_PATH_ENTRY_CHARS } from '@akasecurity/schema';

// A real file name is at most 255 bytes, so a longer segment cannot name an
// existing file and is never matched. This also bounds the cost of a glob.
const MAX_SEGMENT_CHARS = 255;
const MAX_CANDIDATE_CHARS = 4096;
const MAX_CANDIDATE_SEGMENTS = 1024;
const MAX_CANDIDATES = 2000;
// Work bound for one matching call. Running out stops the search and keeps what
// was found: a screen that cannot finish must not hold the hook past its time.
const MATCH_STEP_BUDGET = 4_000_000;

export interface ProtectedPathEnv {
  /** The home directory `~` expands to. */
  home?: string | undefined;
  /** What a relative candidate is placed against. */
  cwd?: string | undefined;
  /** Resolves links in an absolute path; see the module comment. */
  realpath?: ((absolute: string) => string | undefined) | undefined;
}

export interface CompiledProtectedPaths {
  /** Lowercased segment patterns; the first is a root token for an absolute rule. */
  readonly rules: readonly (readonly string[])[];
}

interface Normalized {
  /** Original-case segments, led by a root token (`/` or a drive) when absolute. */
  segments: string[];
  absolute: boolean;
}

function hasWildcard(text: string): boolean {
  return text.includes('*') || text.includes('?');
}

function normalize(raw: string, env: Pick<ProtectedPathEnv, 'home' | 'cwd'>): Normalized | null {
  if (raw.length > MAX_CANDIDATE_CHARS || raw.includes('\u0000')) return null;
  let text = raw.trim().replaceAll('\\', '/');
  if (text === '') return null;
  if (text === '~' || text.startsWith('~/')) {
    if (env.home === undefined || env.home === '') return null;
    text = `${env.home.replaceAll('\\', '/')}${text.slice(1)}`;
  }
  const fromCwd = (): string | null => {
    if (env.cwd === undefined) return null;
    const cwd = env.cwd.replaceAll('\\', '/');
    return /^(?:\/|[A-Za-z]:(?:\/|$))/.test(cwd) ? `${cwd}/${text}` : null;
  };
  let absolute = /^(?:\/|[A-Za-z]:(?:\/|$))/.test(text);
  if (!absolute) {
    const placed = fromCwd();
    if (placed !== null) {
      text = placed;
      absolute = true;
    }
  }
  let root: string | null = null;
  let rest = text;
  if (absolute) {
    const drive = /^([A-Za-z]:)(?:\/|$)/.exec(text);
    if (drive?.[1] !== undefined) {
      root = drive[1];
      rest = text.slice(2);
    } else {
      root = '/';
    }
  }
  const segments: string[] = [];
  for (const part of rest.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (segments.length > 0 && segments[segments.length - 1] !== '..') segments.pop();
      else if (root === null) segments.push('..');
      continue;
    }
    segments.push(part);
  }
  if (segments.length > MAX_CANDIDATE_SEGMENTS) return null;
  return { segments: root === null ? segments : [root, ...segments], absolute };
}

function render(normalized: Normalized): string {
  const [first, ...rest] = normalized.segments;
  if (!normalized.absolute || first === undefined) return normalized.segments.join('/');
  return first === '/' ? `/${rest.join('/')}` : `${first}/${rest.join('/')}`;
}

function segmentMatches(pattern: string, text: string, budget: { steps: number }): boolean {
  if (text.length > MAX_SEGMENT_CHARS) return false;
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    budget.steps -= 1;
    if (budget.steps < 0) return false;
    if (p < pattern.length && pattern[p] === '*') {
      star = p;
      p += 1;
      mark = t;
    } else if (p < pattern.length && (pattern[p] === '?' || pattern[p] === text[t])) {
      p += 1;
      t += 1;
    } else if (star !== -1) {
      p = star + 1;
      mark += 1;
      t = mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p += 1;
  return p === pattern.length;
}

// Whether `rule` matches some prefix of `segments`. Only `**` branches, so the
// failed (rule, segment) positions are memoized and the walk stays polynomial.
function ruleMatches(
  rule: readonly string[],
  segments: readonly string[],
  budget: { steps: number },
): boolean {
  const failed = new Set<number>();
  const width = segments.length + 1;
  const walk = (r: number, s: number): boolean => {
    if (r === rule.length) return true;
    budget.steps -= 1;
    if (budget.steps < 0) return false;
    const key = r * width + s;
    if (failed.has(key)) return false;
    let ok: boolean;
    if (rule[r] === '**') {
      ok = walk(r + 1, s) || (s < segments.length && walk(r, s + 1));
    } else {
      const part = rule[r] ?? '';
      const seg = segments[s];
      ok = seg !== undefined && segmentMatches(part, seg, budget) && walk(r + 1, s + 1);
    }
    if (!ok) failed.add(key);
    return ok;
  };
  return walk(0, 0);
}

function lowered(segments: readonly string[]): string[] {
  return segments.map((s) => s.toLowerCase());
}

/**
 * Compiles the user's entries. A blank entry, one with a NUL, one longer than
 * the schema allows, or one with a segment longer than a file name can be is
 * skipped rather than refused: a bad entry must not disable the others.
 */
export function compileProtectedPaths(
  entries: readonly string[],
  env: Pick<ProtectedPathEnv, 'home' | 'realpath'>,
): CompiledProtectedPaths {
  const rules: string[][] = [];
  for (const entry of entries) {
    if (entry.length > MAX_PROTECTED_PATH_ENTRY_CHARS) continue;
    const normalized = normalize(entry, { home: env.home });
    if (normalized === null) continue;
    if (normalized.segments.some((s) => s.length > MAX_SEGMENT_CHARS)) continue;
    const base = normalized.absolute ? normalized.segments : ['**', ...normalized.segments];
    if (base.length === 0) continue;
    rules.push(lowered(base));
    if (env.realpath !== undefined && normalized.absolute && !hasWildcard(entry)) {
      const real = env.realpath(render(normalized));
      const resolved = real === undefined ? null : normalize(real, {});
      if (resolved?.absolute === true) {
        const segments = lowered(resolved.segments);
        if (segments.join('/') !== lowered(normalized.segments).join('/')) rules.push(segments);
      }
    }
  }
  return { rules };
}

/**
 * The normalized form of every candidate that touches a protected path, once
 * each and in the order first seen. A candidate that cannot be placed (a
 * relative one with no working directory) is checked as spelled, which only a
 * floating entry can match.
 */
export function protectedPathMatches(
  compiled: CompiledProtectedPaths,
  candidates: readonly string[],
  env: ProtectedPathEnv,
): string[] {
  if (compiled.rules.length === 0) return [];
  const budget = { steps: MATCH_STEP_BUDGET };
  const found = new Set<string>();
  for (const raw of candidates.slice(0, MAX_CANDIDATES)) {
    if (budget.steps < 0) break;
    const normalized = normalize(raw, env);
    if (normalized === null) continue;
    const variants = [lowered(normalized.segments)];
    if (env.realpath !== undefined && normalized.absolute) {
      const real = env.realpath(render(normalized));
      const resolved = real === undefined ? null : normalize(real, {});
      if (resolved?.absolute === true) variants.push(lowered(resolved.segments));
    }
    const hit = variants.some((segments) =>
      compiled.rules.some((rule) => ruleMatches(rule, segments, budget)),
    );
    if (hit) found.add(render(normalized));
  }
  return [...found];
}

/**
 * `path` with every link resolved. When the tail does not exist yet, the
 * nearest ancestor that does is resolved and the rest appended, so a file about
 * to be created beneath a link is placed correctly. Never throws.
 */
export function realpathBestEffort(path: string): string {
  const rest: string[] = [];
  let current = path;
  for (let depth = 0; depth < 64; depth += 1) {
    try {
      const real = realpathSync(current);
      return rest.length === 0 ? real : join(real, ...rest.reverse());
    } catch {
      const slash = Math.max(current.lastIndexOf('/'), current.lastIndexOf('\\'));
      if (slash <= 0) return path;
      rest.push(current.slice(slash + 1));
      current = current.slice(0, slash);
    }
  }
  return path;
}

// ---------------------------------------------------------------------------
// Shell commands

const MAX_COMMAND_CHARS = 65_536;
const MAX_WORDS = 4000;
const MAX_NESTING = 3;

interface Word {
  text: string;
  /** The first word of a command, which names the program rather than a file. */
  program: boolean;
}

const OPERATORS = new Set([';', '|', '&', '(', ')', '`', '\n']);
const ESCAPABLE = new Set([' ', '\t', "'", '"', '\\', '$', ';', '|', '&', '<', '>', '(', ')', '`']);

function tokenize(command: string): Word[] {
  const words: Word[] = [];
  let current = '';
  let inWord = false;
  let expectProgram = true;
  let redirect = false;
  const end = (): void => {
    if (!inWord) return;
    inWord = false;
    const text = current;
    current = '';
    if (redirect) {
      words.push({ text, program: false });
      redirect = false;
      return;
    }
    if (expectProgram) {
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(text)) return;
      expectProgram = false;
      words.push({ text, program: true });
      return;
    }
    words.push({ text, program: false });
  };
  for (let i = 0; i < command.length && words.length < MAX_WORDS; i += 1) {
    const ch = command[i] ?? '';
    if (ch === "'") {
      inWord = true;
      const close = command.indexOf("'", i + 1);
      const stop = close === -1 ? command.length : close;
      current += command.slice(i + 1, stop);
      i = stop;
    } else if (ch === '"') {
      inWord = true;
      let j = i + 1;
      while (j < command.length && command[j] !== '"') {
        const inner = command[j] ?? '';
        const next = command[j + 1];
        if (inner === '\\' && next !== undefined && '"\\$`'.includes(next)) {
          current += next;
          j += 2;
        } else {
          current += inner;
          j += 1;
        }
      }
      i = j;
    } else if (ch === '\\') {
      const next = command[i + 1];
      inWord = true;
      if (next !== undefined && ESCAPABLE.has(next)) {
        current += next;
        i += 1;
      } else {
        current += '\\';
      }
    } else if (ch === ' ' || ch === '\t' || ch === '\r') {
      end();
    } else if (ch === '<' || ch === '>') {
      end();
      redirect = true;
    } else if (OPERATORS.has(ch)) {
      end();
      expectProgram = true;
      redirect = false;
    } else {
      inWord = true;
      current += ch;
    }
  }
  end();
  return words;
}

function expandHome(word: string, home: string | undefined): string {
  if (home === undefined || home === '') return word;
  if (word === '$HOME' || word === '${HOME}') return home;
  if (word.startsWith('$HOME/')) return `${home}${word.slice(5)}`;
  if (word.startsWith('${HOME}/')) return `${home}${word.slice(7)}`;
  return word;
}

function wordCandidates(word: Word, home: string | undefined): string[] {
  const text = word.text;
  const out: string[] = [];
  const add = (value: string): void => {
    const unwrapped = value.startsWith('@') ? value.slice(1) : value;
    if (unwrapped !== '' && unwrapped !== '$' && unwrapped !== '--') {
      out.push(expandHome(unwrapped, home));
    }
  };
  if (text.startsWith('-')) {
    const equals = text.indexOf('=');
    if (equals !== -1) add(text.slice(equals + 1));
    const attached = /^-[A-Za-z]([^=].*)$/.exec(text);
    const value = attached?.[1];
    if (value !== undefined && /^[@~/]/.test(value)) add(value);
    return out;
  }
  if (word.program && !text.includes('/')) return out;
  add(text);
  const equals = text.indexOf('=');
  if (equals !== -1) add(text.slice(equals + 1));
  return out;
}

function collect(command: string, home: string | undefined, depth: number, out: Set<string>): void {
  for (const word of tokenize(command)) {
    for (const candidate of wordCandidates(word, home)) {
      if (out.size >= MAX_CANDIDATES) return;
      out.add(candidate);
    }
    // A word holding whitespace came out of quotes: a command handed to a
    // shell, a path with a space, or a substitution. Read it as a command too.
    if (depth < MAX_NESTING && /\s/.test(word.text)) collect(word.text, home, depth + 1, out);
  }
}

/**
 * The words of a shell command that could be file paths, spelled as written
 * apart from a leading `$HOME`. The program name and option flags are left out,
 * but the value of an option (`--data=@file`, `-T file`, `-F name=@file`) and a
 * redirect target are kept. See the module comment for what this cannot see.
 */
export function bashPathCandidates(command: string, env: { home?: string | undefined }): string[] {
  const out = new Set<string>();
  collect(command.slice(0, MAX_COMMAND_CHARS), env.home, 0, out);
  return [...out];
}
