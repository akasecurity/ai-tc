// The file contents a Bash command writes, so they can be scanned as the code
// they are. A command line is not source: the regions of a command that hold an
// extracted payload (`BashPayload.start`/`end`) are where its code_flaw findings
// drop (`writtenRegions`, see the detections engine), and what the command
// writes (a heredoc into a file, a quoted echo/printf into a file) is scanned
// separately as a `code_change`, under the file it names when it names one, so
// extension-scoped rules apply to it. Everything outside those regions, and the
// whole command when extraction is incomplete, keeps the rule family.
//
// Regions exist only for a command that is, in full, ONE statement: an optional
// leading `cd <word> &&` or `mkdir -p <words> &&`, then one plain heredoc writer
// or one quoted echo/printf writer to exactly one plain-path target, with no
// other text anywhere. Anything else keeps every rule on its whole text: that
// is intended, since another statement may run what was written, and a reader
// of more shapes has not converged.
//
// Only a body written to a file counts: a heredoc fed to an interpreter or a
// client (`python - <<EOF > out.txt`, `psql <<EOF`) is a command's input, not a
// file written, and stays unextracted. Any form this reader does not take
// stays unextracted too, which keeps the rules on for it. Kept free of I/O so it
// unit-tests without a hook process.

export interface BashPayload {
  /**
   * The file the command writes this text to, as written in the command.
   * Absent when a file is written but its name is not known from the text
   * (`> "$F"`): the body is then scanned as code with no extension scope.
   */
  path?: string;
  text: string;
  /** The span of the command this payload came from, in command coordinates. */
  start: number;
  end: number;
}

export interface BashExtraction {
  payloads: BashPayload[];
  /**
   * A cap was hit or a heredoc could not be read, so the payloads are not
   * every written file of the command. Then no payload is returned and the
   * command is scanned whole with all rules.
   */
  incomplete: boolean;
}

// `line` with the inside of every quoted span blanked to `_`, quote marks and
// length kept, so a `>` or `tee` inside quotes is not read as a redirect and an
// index into the result is an index into `line`.
function blankQuoted(line: string): string {
  let out = '';
  let quote = '';
  for (let i = 0; i < line.length; i++) {
    const c = line.charAt(i);
    if (quote === '') {
      if (c === '\\' && i + 1 < line.length) {
        out += '__';
        i++;
      } else {
        out += c;
        if (c === "'" || c === '"') quote = c;
      }
    } else if (c === quote) {
      out += c;
      quote = '';
    } else if (c === '\\' && quote === '"' && i + 1 < line.length) {
      out += '__';
      i++;
    } else {
      out += '_';
    }
  }
  return out;
}

// A stdout redirect: `>`, `>>`, `>|`, `1>`, `&>`; not `2>`, `>&2`. The target
// is quoted or bare.
const REDIRECT =
  /(?<![\w&])(\d*|&)(>>?\|?)(?!&)[ \t]*(?:'([^']+)'|"([^"]+)"|([^\s'"|;&<>()]+))(?=[\s;&|<>]|$)/dg;

// The commands whose heredoc input goes to the file a redirect or `tee` names
// (`:` and `true` discard it, so they are not writers).
// Any other command word (`python`, `psql`, `ssh`) takes the body as its input.
const WRITERS = new Set(['cat', 'tee']);

// A redirect with its target that may follow a heredoc operator (an fd dup was
// rejected before this is read).
const AFTER_REDIRECT = /(?<![\w&])(?:\d*|&)>>?\|?[ \t]*(?:'[^']*'|"[^"]*"|[^\s'"|;&<>()]+)/g;

// What the stage `before` (its words up to the heredoc operator, or the whole
// stage) is: 'tee' with the span of its one file word, another plain writer
// ('other'), or undefined for anything else (an interpreter, an empty or
// unparsed stage, a writer with arguments beyond the few it is read with).
// Every word is checked, not only the first: `cat` takes no argument but `-`,
// `tee` an optional `-a` and exactly one file. Redirects are skipped here and
// counted by the caller. The tee file is the word parsed here, never a second
// reading of the text, so it is the word the target count and the name share.
function writerOf(
  before: string,
): { kind: 'tee'; file: { start: number; end: number } } | { kind: 'other' } | undefined {
  let skipArg = false;
  let command: string | undefined;
  const args: { w: string; start: number; end: number }[] = [];
  for (const m of before.matchAll(/[^ \t]+/g)) {
    const w = m[0];
    if (skipArg) {
      skipArg = false;
      continue;
    }
    if (/^(?:\d*|&)>>?\|?[^<>]*$/.test(w)) {
      skipArg = /^(?:\d*|&)>>?\|?$/.test(w);
      continue;
    }
    // A `>`, `<` or `&` inside a word is a redirect glued to it, which is not
    // counted as one: the word is not read.
    if (/[<>&]/.test(w)) return undefined;
    if (command === undefined) command = w;
    else args.push({ w, start: m.index, end: m.index + w.length });
  }
  if (command === undefined || !WRITERS.has(command)) return undefined;
  if (command === 'tee') {
    // `-a` only before the file word: BSD tee stops reading options at the first
    // word, so a later `-a` is a second file.
    let file = args.length === 1 ? args[0] : undefined;
    if (args.length === 2 && args[0]?.w === '-a') file = args[1];
    if (file === undefined || file.w.startsWith('-')) return undefined;
    return { kind: 'tee', file: { start: file.start, end: file.end } };
  }
  if (command === 'cat') return args.every((a) => a.w === '-') ? { kind: 'other' } : undefined;
  return undefined;
}

interface Target {
  start: number;
  end: number;
}

// The file a segment writes: its last stdout redirect or its `tee` file, read
// outside quotes. `seen` is whether it names any file-like target at all (a
// `/dev/null` redirect alone is not a file written).
function segmentTarget(
  seg: string,
  blank: string,
  teeFile: Target | undefined,
): { path: string | undefined; seen: boolean } {
  const found: { at: number; span: Target }[] = [];
  for (const m of blank.matchAll(REDIRECT)) {
    const prefix = m[1] ?? '';
    const span = m.indices?.[3] ?? m.indices?.[4] ?? m.indices?.[5];
    if (span === undefined) continue;
    if (prefix !== '' && prefix !== '1' && prefix !== '&') continue;
    const value = seg.slice(span[0], span[1]);
    if (isDevice(value)) continue;
    found.push({ at: m.index, span: { start: span[0], end: span[1] } });
  }
  if (teeFile !== undefined) {
    if (!isDevice(seg.slice(teeFile.start, teeFile.end)))
      found.push({ at: teeFile.start, span: teeFile });
  }
  const last = found.sort((a, b) => a.at - b.at).at(-1);
  if (last === undefined) return { path: undefined, seen: false };
  const value = seg.slice(last.span.start, last.span.end);
  return { path: nameable(value) ? value : undefined, seen: true };
}

// The device names that are not a file written. Any other /dev path, or a path
// with a `..` segment, counts as a file.
function isDevice(path: string): boolean {
  return /^\/dev\/(?:null|stdout|stderr|stdin|tty|fd\/\d+)$/.test(path);
}

function hasDotDot(path: string): boolean {
  return path.split('/').includes('..');
}

// A file name read from the text itself: no expansion decides it at run time.
function nameable(path: string): boolean {
  return !/[$`*?[{\\~]/.test(path) && !path.startsWith('&') && !isDevice(path);
}

// <<, not <<<; the delimiter bare (with `-` and `.`), backslash-escaped or quoted.
const OPERATOR = /<<(-?)[ \t]*(?:'([^'\n]+)'|"([^"\n]+)"|\\?([A-Za-z0-9_][\w.-]*))(?=[ \t<>]|$)/y;

// echo/printf of one quoted string straight into a file, at command position,
// and nothing after it but the end of the command. A printf whose string holds
// a conversion is a format, not the text written, and is not read.
const QUOTED_WRITE =
  /(echo|printf)[ \t]+(?:-[A-Za-z]+[ \t]+)*(?:'([^']*)'|"((?:[^"\\]|\\.)*)")[ \t]*>>?[ \t]*(?:'([^']+)'|"([^"]+)"|([^\s'"|;&<>()]+))(?=[ \t]*$)/dy;

// A QUOTED_WRITE match read as a payload, or undefined when it is not one.
function quotedWrite(m: RegExpExecArray | null): BashPayload | undefined {
  if (m === null) return undefined;
  const text = m[2] ?? m[3];
  const path = m[4] ?? m[5] ?? m[6];
  if (text === undefined || text === '' || path === undefined) return undefined;
  // A flag (`echo -e`, `-n`, `printf -v`) changes what is written.
  if (/^(?:echo|printf)[ \t]+-/.test(m[0])) return undefined;
  // printf reads escapes and conversions in its format, and some shells' echo
  // (zsh, dash, bash with xpg_echo) reads escapes too: no backslash in either.
  if (text.includes('\\')) return undefined;
  if (m[1] === 'printf' && text.includes('%')) return undefined;
  // A double-quoted string is expanded: a `$` or backtick in it, or a backslash
  // escape, makes the file hold something other than the literal read here.
  if (m[3] !== undefined && /[$`\\]/.test(m[3])) return undefined;
  if (isDevice(path) || path.startsWith('&') || hasDotDot(path)) return undefined;
  // Plain path characters only: no expansion, glob or brace decides the name.
  if (!/^[\w./@%+,:-]+$/.test(path)) return undefined;
  // The region is the text inside the quotes, the same span that is scanned as
  // the payload: a match touching the echo word, the quotes, the redirect or
  // the target stays on the command scan.
  const inside = m.indices?.[2] ?? m.indices?.[3];
  if (inside === undefined) return undefined;
  return {
    path,
    text,
    start: inside[0],
    end: inside[1],
  };
}

// Bounds on one command's extraction, so a long command cannot turn it into a
// cost the scan deadline never sees. Past any of them nothing is extracted (the
// command is then scanned whole, with all rules).
const MAX_COMMAND_CHARS = 256 * 1024;
// A line holding a heredoc marker is read by several patterns, so it is bounded
// on its own.
const MAX_MARKER_LINE_CHARS = 4096;

interface Pending {
  delimiter: string;
  stripTabs: boolean;
}

const none = (): BashExtraction => ({ payloads: [], incomplete: true });

// The optional leading statement: `cd <word> && ` or `mkdir [-p] <words> && `,
// words of plain path characters that do not start with `-`, single spaces; `-p`
// is the only flag, so `mkdir -m 777 d &&` is no prefix and the command has none.
const PLAIN = '[\\w./@%+,:][\\w./@%+,:-]*';
const PREFIX = new RegExp(`^(?:(?:cd ${PLAIN}|mkdir(?: -p)? ${PLAIN}(?: ${PLAIN})*) && )?`);

// Whether `line` ends outside any quote, read as blankQuoted reads it.
function endsOutsideQuote(line: string): boolean {
  let quote = '';
  for (let i = 0; i < line.length; i++) {
    const c = line.charAt(i);
    if (quote === '') {
      if (c === '\\') i++;
      else if (c === "'" || c === '"') quote = c;
    } else if (c === quote) {
      quote = '';
    } else if (c === '\\' && quote === '"') {
      i++;
    }
  }
  return quote === '';
}

// Only tab and printable ASCII: bash splits words at nothing else here.
function plainAscii(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code !== 9 && (code < 32 || code > 126)) return false;
  }
  return true;
}

export function bashWrittenPayloads(command: string): BashExtraction {
  if (command.length > MAX_COMMAND_CHARS) return none();
  const text = command.endsWith('\n') ? command.slice(0, -1) : command;
  const base = PREFIX.exec(text)?.[0].length ?? 0;
  const rest = text.slice(base);
  return quotedStatement(rest, base) ?? heredocStatement(rest, base) ?? none();
}

// `echo '...' > file` and nothing else. The region is the quoted text only (see
// quotedWrite), like a heredoc body: the rest of the statement keeps its rules.
function quotedStatement(rest: string, base: number): BashExtraction | undefined {
  if (!/^(?:echo|printf)[ \t]/.test(rest)) return undefined;
  QUOTED_WRITE.lastIndex = 0;
  const m = QUOTED_WRITE.exec(rest);
  const w = quotedWrite(m);
  if (w === undefined) return none();
  return {
    payloads: [{ ...w, start: w.start + base, end: w.end + base }],
    incomplete: false,
  };
}

// One heredoc writer: a marker line, its body, and the delimiter line last.
function heredocStatement(rest: string, base: number): BashExtraction | undefined {
  const nl = rest.indexOf('\n');
  if (nl === -1 || !rest.slice(0, nl).includes('<<')) return undefined;
  const line = rest.slice(0, nl);
  if (line.length > MAX_MARKER_LINE_CHARS || !plainAscii(line) || !endsOutsideQuote(line)) {
    return none();
  }
  const blank = blankQuoted(line);
  // One command: no list, comment, group, substitution, background or fd dup.
  if (/&&|\|\||[;#(){}`]/.test(blank) || blank.replace(/&>>?/g, '').includes('&')) return none();
  if (blank.includes('<<<') || blank.indexOf('<<') !== blank.lastIndexOf('<<')) return none();
  const opAt = blank.indexOf('<<');
  OPERATOR.lastIndex = opAt;
  const om = OPERATOR.exec(line);
  const delimiter = om?.[2] ?? om?.[3] ?? om?.[4];
  if (om === null || delimiter === undefined) return none();
  // Bash unquotes the delimiter word (`"A\\$"` is `A$`), so a quoted delimiter is
  // read only when it is plain characters: any `\\`, `$` or backtick in it, and
  // the body could end where this reader does not see it.
  if (!/^[A-Za-z0-9_.-]+$/.test(delimiter)) return none();
  const escaped = om[0].includes('\\');
  const literal = om[2] !== undefined || om[3] !== undefined || escaped;
  if ((line.match(/\\/g) ?? []).length !== (escaped ? 1 : 0)) return none();
  const opEnd = opAt + om[0].length;
  // Every `>`, `<` and `&` on the line must belong to the heredoc operator or to
  // a redirect the target count below sees: one glued to a word (`a.txt>e.py`)
  // is a file written that nothing here would name.
  let accounted = blank.slice(0, opAt) + ' '.repeat(opEnd - opAt) + blank.slice(opEnd);
  for (const m of blank.matchAll(REDIRECT)) {
    accounted =
      accounted.slice(0, m.index) +
      ' '.repeat(m[0].length) +
      accounted.slice(m.index + m[0].length);
  }
  if (/[<>&]/.test(accounted)) return none();
  const body = readBody(rest, nl + 1, { delimiter, stripTabs: om[1] === '-' });
  if (!body.terminated || body.next < rest.length) return none();

  // The pipeline: the heredoc's stage is the first, the writer, and nothing
  // after it reads its stdout except one last `tee`.
  const stages: Target[] = [];
  let from = 0;
  // `>|` is split here too: its target lands in a second stage that is not a tee,
  // so a clobbering redirect is never extracted (safe, and never reaches REDIRECT).
  for (const m of blank.matchAll(/\|/g)) {
    stages.push({ start: from, end: m.index });
    from = m.index + 1;
  }
  stages.push({ start: from, end: blank.length });
  const own = stages[0];
  if (own === undefined || opAt > own.end) return none();
  const ownWriter = writerOf(blank.slice(own.start, opAt));
  if (ownWriter === undefined) return none();
  // After the operator and its delimiter only redirects may follow.
  if (blank.slice(opEnd, own.end).replace(AFTER_REDIRECT, ' ').trim() !== '') return none();
  let tstage = own;
  let teeFile: Target | undefined = ownWriter.kind === 'tee' ? ownWriter.file : undefined;
  if (stages.length === 2) {
    // `cat <<EOF | tee f`: the file is the last stage's, if that is a tee.
    const last = stages[1];
    const lastWriter = last === undefined ? undefined : writerOf(blank.slice(last.start, last.end));
    if (last === undefined || lastWriter?.kind !== 'tee' || teeFile !== undefined) return none();
    tstage = last;
    teeFile = lastWriter.file;
  } else if (stages.length !== 1) {
    return none();
  }
  if (teeFile !== undefined) {
    // The file word is one bare word or exactly one quoted string.
    const word = blank.slice(tstage.start + teeFile.start, tstage.start + teeFile.end);
    if (!/^(?:'_+'|"_+"|[^'"]+)$/.test(word)) return none();
    if (/^['"]/.test(word)) teeFile = { start: teeFile.start + 1, end: teeFile.end - 1 };
  }
  // Exactly one file is written: a second redirect (any fd), or a tee file
  // besides a redirect, would give the body a name the path attribution does
  // not carry.
  let targets = teeFile === undefined ? 0 : 1;
  for (const m of blank.matchAll(REDIRECT)) {
    const at = m.indices?.[3] ?? m.indices?.[4] ?? m.indices?.[5];
    if (at !== undefined && !isDevice(line.slice(at[0], at[1]))) targets++;
  }
  if (targets !== 1) return none();
  const found = segmentTarget(
    line.slice(tstage.start, tstage.end),
    blank.slice(tstage.start, tstage.end),
    teeFile,
  );
  if (!found.seen || (found.path !== undefined && hasDotDot(found.path))) return none();
  const raw = body.bodyStart >= body.bodyEnd ? '' : rest.slice(body.bodyStart, body.bodyEnd);
  // `<<-` strips the leading tabs of every body line: the payload is what the
  // shell writes, the region stays the raw span.
  const text = om[1] === '-' ? raw.replace(/^\t+/gm, '') : raw;
  // An unquoted body is expanded by the shell: a `$`, a backtick or a backslash
  // (`\\\\` becomes `\\`, backslash-newline joins lines) means the file holds
  // something other than the text read here.
  if (!literal && /[$`\\]/.test(text)) return none();
  if (text.includes('\r')) return none();
  // An empty body writes an empty file: a plain writer with nothing to scan.
  if (text === '') return { payloads: [], incomplete: false };
  return {
    payloads: [
      {
        ...(found.path === undefined ? {} : { path: found.path }),
        text,
        start: base + body.bodyStart,
        end: base + body.bodyEnd,
      },
    ],
    incomplete: false,
  };
}

// The body of one heredoc starting at `pos`: up to the first line equal to the
// delimiter. `next` is where the shell resumes.
function readBody(
  command: string,
  pos: number,
  p: Pending,
): { bodyStart: number; bodyEnd: number; next: number; terminated: boolean } {
  const bodyStart = Math.min(pos, command.length);
  let at = bodyStart;
  while (at <= command.length) {
    let e = command.indexOf('\n', at);
    if (e === -1) e = command.length;
    const l = command.slice(at, e);
    if ((p.stripTabs ? l.replace(/^\t+/, '') : l) === p.delimiter) {
      return {
        bodyStart,
        bodyEnd: Math.max(at - 1, bodyStart),
        next: Math.min(e + 1, command.length),
        terminated: true,
      };
    }
    if (e === command.length) break;
    at = e + 1;
  }
  return { bodyStart, bodyEnd: command.length, next: command.length, terminated: false };
}
