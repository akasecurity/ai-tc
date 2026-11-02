// The file contents a Bash command writes, so they can be scanned as the code
// they are. A command line is not source: the regions of a command that hold an
// extracted payload (`BashPayload.start`/`end`) are where its code_flaw findings
// drop (`writtenRegions`, see the detections engine), and what the command
// writes (a heredoc into a file, a quoted echo/printf into a file) is scanned
// separately as a `code_change`, under the file it names when it names one, so
// extension-scoped rules apply to it. Everything outside those regions, and the
// whole command when extraction is incomplete, keeps the rule family.
//
// Regions exist only for a command that is, in full, a flat sequence of
// statements (newline, `;`, `&&`) that are each a plain writer or one of a few
// inert statements (`cd`, `mkdir`, `touch`, `true`, `:`). A command that mixes a
// write with any other statement keeps every rule on its whole text: that is
// intended, since the other statement may run what was written.
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
const TEE =
  /\btee[ \t]+(?:-[A-Za-z]+[ \t]+)*(?:'([^']+)'|"([^"]+)"|([^\s'"|;&<>()-][^\s'"|;&<>()]*))(?=[\s;&|<>]|$)/d;

// A decoder or encoder on the marker line means the body is not the file's
// text as written, so it is not scanned as code.
const TRANSFORMED = /(?<![\w./-])(?:base64|xxd|openssl)(?![\w./])|\bb64decode\b/;

// The commands whose heredoc input goes to the file a redirect or `tee` names.
// Any other command word (`python`, `psql`, `ssh`) takes the body as its input.
const WRITERS = new Set(['cat', 'tee', ':', 'true']);

// The statements besides a writer that leave a command flat: they run nothing
// the command wrote and change nothing a writer relies on. Words are plain, or
// quoted with no expansion.
const WORD = `(?:[\\w./~@%+,:-]+|'[^']*'|"[^"$\`\\\\]*")`;
const INERT = new RegExp(`^(?:(?:cd|mkdir|touch|true|:)(?:[ \\t]+${WORD})*)$`);

// A redirect (with its target, or an fd dup) that may follow a heredoc operator.
const AFTER_REDIRECT =
  /(?<![\w&])(?:\d*|&)>>?\|?[ \t]*(?:'[^']*'|"[^"]*"|[^\s'"|;&<>()]+)|(?<![\w&])\d*>&\d*-?/g;

// What the stage `before` (its words up to the heredoc operator, or the whole
// stage) is: 'tee', another plain writer ('other'), or undefined for anything
// else (an interpreter, an empty or unparsed stage, a writer with arguments
// beyond the few it is read with). Every word is checked, not only the first:
// `cat` takes no argument but `-`, `tee` an optional `-a` and exactly one file,
// `:` and `true` none. Redirects are skipped here and counted by the caller.
function writerOf(before: string): 'tee' | 'other' | undefined {
  const words = before
    .trim()
    .split(/[ \t]+/)
    .filter(Boolean);
  let skipArg = false;
  let command: string | undefined;
  const args: string[] = [];
  for (const w of words) {
    if (skipArg) {
      skipArg = false;
      continue;
    }
    if (/^\d*>/.test(w) || w.startsWith('&>')) {
      skipArg = /^(?:\d*|&)>>?\|?$/.test(w);
      continue;
    }
    if (command === undefined) command = w;
    else args.push(w);
  }
  if (command === undefined || !WRITERS.has(command)) return undefined;
  if (command === 'tee') {
    const files = args.filter((w) => w !== '-a');
    return files.length === 1 && !files.some((w) => w.startsWith('-')) ? 'tee' : undefined;
  }
  if (command === 'cat') return args.every((w) => w === '-') ? 'other' : undefined;
  return args.length === 0 ? 'other' : undefined;
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
  useTee: boolean,
): { path: string | undefined; seen: boolean; spans: Target[] } {
  const found: { at: number; span: Target }[] = [];
  const spans: Target[] = [];
  for (const m of blank.matchAll(REDIRECT)) {
    const prefix = m[1] ?? '';
    const span = m.indices?.[3] ?? m.indices?.[4] ?? m.indices?.[5];
    if (span === undefined) continue;
    spans.push({ start: span[0], end: span[1] });
    if (prefix !== '' && prefix !== '1' && prefix !== '&') continue;
    const value = seg.slice(span[0], span[1]);
    if (isDevice(value)) continue;
    found.push({ at: m.index, span: { start: span[0], end: span[1] } });
  }
  const tee = useTee ? TEE.exec(blank) : null;
  const teeSpan = tee?.indices?.[1] ?? tee?.indices?.[2] ?? tee?.indices?.[3];
  if (teeSpan !== undefined) {
    spans.push({ start: teeSpan[0], end: teeSpan[1] });
    if (!isDevice(seg.slice(teeSpan[0], teeSpan[1]))) {
      found.push({ at: tee?.index ?? 0, span: { start: teeSpan[0], end: teeSpan[1] } });
    }
  }
  const last = found.sort((a, b) => a.at - b.at).at(-1);
  if (last === undefined) return { path: undefined, seen: false, spans };
  const value = seg.slice(last.span.start, last.span.end);
  return { path: nameable(value) ? value : undefined, seen: true, spans };
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
  return !/[$`*?[{\\]/.test(path) && !path.startsWith('&') && !isDevice(path);
}

// The part of the marker line holding one command, between `;`, `&&`, `||` and
// a lone `&`; pipes stay in it.
function segmentBounds(blank: string, at: number): Target {
  const sep = /;|&&|\|\||(?<![<>&])&(?![>&])/g;
  let start = 0;
  let end = blank.length;
  for (const m of blank.matchAll(sep)) {
    if (m.index < at) start = m.index + m[0].length;
    else {
      end = m.index;
      break;
    }
  }
  return { start, end };
}

// <<, not <<<; the delimiter bare (with `-` and `.`), backslash-escaped or quoted.
const OPERATOR = /<<(-?)[ \t]*(?:'([^'\n]+)'|"([^"\n]+)"|\\?([A-Za-z0-9_][\w.-]*))/y;

// echo/printf of one quoted string straight into a file, at command position,
// and nothing after it but the end of the command. A printf whose string holds
// a conversion is a format, not the text written, and is not read.
const QUOTED_WRITE =
  /(echo|printf)[ \t]+(?:-[A-Za-z]+[ \t]+)*(?:'([^']*)'|"((?:[^"\\]|\\.)*)")[ \t]*>>?[ \t]*(?:'([^']+)'|"([^"]+)"|([^\s'"|;&<>()]+))(?=[ \t]*(?:$|[;\n]|&&)|[ \t]+#)/y;

// A QUOTED_WRITE match read as a payload, or undefined when it is not one.
function quotedWrite(m: RegExpExecArray | null): BashPayload | undefined {
  if (m === null) return undefined;
  const text = m[2] ?? m[3];
  const path = m[4] ?? m[5] ?? m[6];
  if (text === undefined || text === '' || path === undefined) return undefined;
  // A flag (`echo -e`, `-n`, `printf -v`) changes what is written.
  if (/^(?:echo|printf)[ \t]+-/.test(m[0])) return undefined;
  // printf reads escapes and conversions in its format.
  if (m[1] === 'printf' && /[\\%]/.test(text)) return undefined;
  // A double-quoted string is expanded: a `$` or backtick in it, or a backslash
  // escape, makes the file hold something other than the literal read here.
  if (m[3] !== undefined && /[$`\\]/.test(m[3])) return undefined;
  if (isDevice(path) || path.startsWith('&') || hasDotDot(path)) return undefined;
  // Plain path characters only: no expansion, glob or brace decides the name.
  if (!/^[\w./~@%+,:-]+$/.test(path)) return undefined;
  return {
    path,
    text,
    start: m.index,
    end: m.index + m[0].length,
  };
}

// Bounds on one command's extraction, so a long command cannot turn it into a
// cost the scan deadline never sees. Past any of them the extraction is
// incomplete (the command is then scanned whole, with all rules).
const MAX_HEREDOCS = 64;
const MAX_PAYLOADS = 32;
const MAX_COMMAND_CHARS = 256 * 1024;
// A line holding a heredoc marker is read by several patterns, so it is bounded
// on its own: past this the extraction is incomplete.
const MAX_MARKER_LINE_CHARS = 4096;

interface Pending {
  opAt: number;
  opEnd: number;
  delimiter: string;
  stripTabs: boolean;
  /** Quoted or backslash-escaped delimiter: the body is not expanded. */
  literal: boolean;
}

interface Body {
  pending: Pending;
  bodyStart: number;
  bodyEnd: number;
  lineStart: number;
  lineEnd: number;
  terminated: boolean;
}

export function bashWrittenPayloads(command: string): BashExtraction {
  const none: BashExtraction = { payloads: [], incomplete: true };
  if (command.length > MAX_COMMAND_CHARS) return none;
  const bodies: Body[] = [];
  const quoted: BashPayload[] = [];
  let atCommand = true;
  // The statements of the command at depth 0 (split at a newline, `;`, `&&`),
  // heredoc bodies excluded, and whether anything but a flat sequence was seen.
  const stmts: Target[] = [];
  let stmtStart = 0;
  let commentAt = -1;
  let nonFlat = false;
  const endStmt = (at: number, next: number): void => {
    stmts.push({ start: stmtStart, end: commentAt >= 0 ? commentAt : at });
    commentAt = -1;
    stmtStart = next;
  };
  let incomplete = false;
  let pending: Pending[] = [];
  let quote = '';
  let seen = 0;
  const n = command.length;
  // One pass, as the shell reads it: quotes and comments are tracked so a
  // `<<` inside them is text, and the bodies of the heredocs opened on a line
  // are skipped at its end, so a marker inside a body is text too.
  let i = 0;
  while (i < n) {
    const c = command.charAt(i);
    if (quote === '') {
      // Bash splits words at a space, tab or newline only: any other control or
      // non-ASCII character outside quotes is not read here.
      const code = c.charCodeAt(0);
      if (code !== 9 && code !== 10 && (code < 32 || code > 126)) nonFlat = true;
    }
    if (quote !== '') {
      // A double-quoted string is expanded: a substitution in it runs code.
      if (quote === '"' && (c === '`' || (c === '$' && command.charAt(i + 1) === '('))) {
        nonFlat = true;
      }
      if (c === '\\' && quote === '"') i += 2;
      else {
        if (c === quote) quote = '';
        i++;
      }
      continue;
    }
    if (atCommand) {
      if (c === ' ' || c === '\t') {
        i++;
        continue;
      }
      atCommand = false;
      if (c === 'e' || c === 'p') {
        QUOTED_WRITE.lastIndex = i;
        const w = quotedWrite(QUOTED_WRITE.exec(command));
        if (w !== undefined) {
          quoted.push(w);
          if (quoted.length > MAX_PAYLOADS) return none;
          i += w.end - w.start;
          continue;
        }
      }
    }
    if (c === '\\') {
      // A line continuation joins the next line to this one, which this reader
      // does not follow.
      if (command.charAt(i + 1) === '\n' || command.startsWith('\r\n', i + 1)) incomplete = true;
      i += 2;
    } else if (c === '$' && command.charAt(i + 1) === "'") {
      // ANSI-C quoting: its escapes are not read here.
      incomplete = true;
      i += 2;
    } else if (c === ';') {
      endStmt(i, i + 1);
      atCommand = true;
      i++;
    } else if (c === '|') {
      // A pipe stays inside its statement; `||` is not a flat sequence.
      if (command.charAt(i + 1) === '|') {
        nonFlat = true;
        i++;
      }
      i++;
    } else if (c === '&') {
      if (command.charAt(i + 1) === '&') {
        endStmt(i, i + 2);
        atCommand = true;
        i += 2;
      } else {
        // `>&`, `&>` are redirects; a lone `&` backgrounds the command.
        if (!/[<>]/.test(command.charAt(i - 1)) && command.charAt(i + 1) !== '>') nonFlat = true;
        i++;
      }
    } else if (c === '(' || c === ')' || c === '{' || c === '}' || c === '`') {
      // A group, subshell, substitution or function body.
      nonFlat = true;
      i++;
    } else if (c === "'" || c === '"') {
      quote = c;
      i++;
    } else if (c === '#' && (i === 0 || /[ \t\n]/.test(command.charAt(i - 1)))) {
      commentAt = i;
      const e = command.indexOf('\n', i);
      i = e === -1 ? n : e;
    } else if (c === '\n') {
      let pos = i + 1;
      const lineStart = command.lastIndexOf('\n', i - 1) + 1;
      for (const p of pending) {
        const body = readBody(command, pos, p);
        bodies.push({ ...body, pending: p, lineStart, lineEnd: i });
        if (!body.terminated) incomplete = true;
        // An unquoted body joins a line ending in a backslash to the next: the
        // delimiter and a substitution can be spelled across lines.
        if (!p.literal && /\\\r?\n/.test(command.slice(body.bodyStart, body.next))) {
          incomplete = true;
        }
        pos = body.next;
      }
      pending = [];
      atCommand = true;
      endStmt(i, pos);
      i = pos;
    } else if (c === '<' && command.charAt(i + 1) === '<') {
      if (command.charAt(i + 2) === '<') {
        i += 3;
        continue;
      }
      OPERATOR.lastIndex = i;
      const m = OPERATOR.exec(command);
      const delimiter = m?.[2] ?? m?.[3] ?? m?.[4];
      if (m === null || delimiter === undefined) {
        // `<<$X`, `<<(`: a heredoc this reader cannot follow.
        incomplete = true;
        i += 2;
        continue;
      }
      if (++seen > MAX_HEREDOCS) return none;
      pending.push({
        opAt: i,
        opEnd: i + m[0].length,
        delimiter,
        stripTabs: m[1] === '-',
        literal: m[2] !== undefined || m[3] !== undefined || m[0].includes('\\'),
      });
      i += m[0].length;
    } else {
      i++;
    }
  }
  // Operators on a last line with no newline have no body to read.
  if (incomplete || pending.length > 0) return none;
  endStmt(n, n);

  const payloads: BashPayload[] = [];
  const writerOps = new Set<number>();
  for (const b of bodies) {
    const lineEnd = b.lineEnd;
    if (lineEnd - b.lineStart > MAX_MARKER_LINE_CHARS) return none;
    const rawLine = command.slice(b.lineStart, lineEnd);
    const rawBlank = blankQuoted(rawLine);
    // A `#` comment on the marker line is not part of the command.
    const comment = /(?<=^|[ \t])#/.exec(rawBlank);
    const markerLine = comment === null ? rawLine : rawLine.slice(0, comment.index);
    const blankLine = comment === null ? rawBlank : rawBlank.slice(0, comment.index);
    const rel = b.pending.opAt - b.lineStart;
    if (rel < 0) return none;
    const { start, end } = segmentBounds(blankLine, rel);
    const seg = markerLine.slice(start, end);
    const blank = blankLine.slice(start, end);
    // A substitution or subshell on the command runs code of its own.
    if (/[(`]/.test(blank)) continue;
    // A duplicated fd (`>&2`, `1>&2`, `<&3`) sends the output somewhere else.
    if (/[<>]&/.test(blank)) continue;
    // The pipeline: the heredoc's stage is the writer, and nothing after it
    // reads its stdout except one last `tee`.
    const stages: Target[] = [];
    let from = 0;
    for (const m of blank.matchAll(/\|/g)) {
      stages.push({ start: from, end: m.index });
      from = m.index + 1;
    }
    stages.push({ start: from, end: blank.length });
    const k = stages.findIndex((st) => st.start <= rel - start && rel - start <= st.end);
    // Whatever runs before the heredoc's stage in a pipeline is not read here.
    if (k !== 0) continue;
    const own = stages[k];
    if (own === undefined) continue;
    const kind = writerOf(blank.slice(own.start, rel - start));
    if (kind === undefined) continue;
    // After the operator and its delimiter only redirects may follow: a word
    // there (`<<EOF python3`) is the command that runs the body.
    const after = blank.slice(b.pending.opEnd - b.lineStart - start, own.end);
    if (after.replace(AFTER_REDIRECT, ' ').trim() !== '') continue;
    let tstage = own;
    let useTee = kind === 'tee';
    if (k === stages.length - 2) {
      // `cat <<EOF | tee f`: the file is the last stage's, if that is a tee.
      const last = stages[k + 1];
      if (last === undefined || writerOf(blank.slice(last.start, last.end)) !== 'tee') continue;
      if (useTee) continue;
      tstage = last;
      useTee = true;
    } else if (k !== stages.length - 1) {
      continue;
    }
    // Exactly one file is written in the whole segment: a second redirect (any
    // fd), or a tee file besides a redirect, would give the body a name the
    // path attribution does not carry.
    let targets = useTee ? 1 : 0;
    for (const m of blank.matchAll(REDIRECT)) {
      const at = m.indices?.[3] ?? m.indices?.[4] ?? m.indices?.[5];
      if (at !== undefined && !isDevice(seg.slice(at[0], at[1]))) targets++;
    }
    if (targets !== 1) continue;
    const found = segmentTarget(
      seg.slice(tstage.start, tstage.end),
      blank.slice(tstage.start, tstage.end),
      useTee,
    );
    if (found.path !== undefined && hasDotDot(found.path)) return none;
    const target = {
      ...found,
      spans: found.spans.map((t) => ({ start: t.start + tstage.start, end: t.end + tstage.start })),
    };
    if (!target.seen) continue;
    // A target's own name (`base64.py`) is not a transform of the body.
    let words = blank;
    for (const t of target.spans) {
      words = words.slice(0, t.start) + ' '.repeat(t.end - t.start) + words.slice(t.end);
    }
    if (TRANSFORMED.test(words)) continue;
    const text = (b.bodyStart >= b.bodyEnd ? '' : command.slice(b.bodyStart, b.bodyEnd)).replace(
      /\r$/,
      '',
    );
    // An unquoted body is expanded by the shell: a `$` (parameter, arithmetic or
    // command substitution) or a backtick in it means the file holds something
    // other than the text read here, so the body is not the file's text, and
    // the heredoc is not a plain writer (the whole command then has no regions).
    if (!b.pending.literal && /[$`]/.test(text)) continue;
    writerOps.add(b.pending.opAt);
    if (text === '') continue;
    payloads.push({
      ...(target.path === undefined ? {} : { path: target.path }),
      text,
      start: b.bodyStart,
      end: b.bodyEnd,
    });
    if (payloads.length > MAX_PAYLOADS) return none;
  }
  payloads.push(...quoted);
  if (payloads.length > MAX_PAYLOADS) return none;
  if (payloads.length === 0) return { payloads, incomplete: false };
  // Regions only for a command that is, in full, a flat sequence of plain
  // writers and a few inert statements: one other statement (a command that
  // may run what was written, a function or alias that changes a writer, a
  // group) and the whole command keeps every rule.
  if (nonFlat) return none;
  const quotedAt = new Set(quoted.map((q) => q.start));
  for (const st of stmts) {
    const text = command.slice(st.start, st.end).trim();
    if (text === '' || INERT.test(text)) continue;
    const lead =
      st.start +
      (command.slice(st.start, st.end).length - command.slice(st.start, st.end).trimStart().length);
    if (quotedAt.has(lead)) continue;
    const ops = bodies.filter((b) => b.pending.opAt >= st.start && b.pending.opAt < st.end);
    if (ops.length > 0 && ops.every((b) => writerOps.has(b.pending.opAt))) continue;
    return none;
  }
  return { payloads, incomplete: false };
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
