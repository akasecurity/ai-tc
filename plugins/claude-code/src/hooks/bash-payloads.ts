// The file contents a Bash command writes, so they can be scanned as the code
// they are. A command line is not source: when a payload is extracted from a
// command, that command's own capture skips code_flaw rules
// (`commandWritesScanned`, see ruleApplies in the detections engine), and what
// the command writes (a heredoc into a file, a quoted echo/printf into a file)
// is scanned separately as a `code_change` under the file it names, so
// extension-scoped rules apply to it. A command with no extracted payload keeps
// the rule family on the command line itself.
//
// Only a payload with a named file target counts. A heredoc fed to an
// interpreter or a client (`python - <<EOF`, `psql <<EOF`) is a command's
// input, not a file written. Kept free of I/O so it unit-tests without a hook
// process.

export interface BashPayload {
  /** The file the command writes this text to, as written in the command. */
  path: string;
  text: string;
}

// `> f`, `>> f`, `tee f`, `tee -a f`, optionally quoted. `>&2` and `2>` stay out.
const TARGET =
  /(?:(?<![0-9&>])>>?|\btee\s+(?:-a\s+)?)\s*(?:'([^']+)'|"([^"]+)"|([^\s'"|;&<>()]+))/d;

// A decoder or encoder on the marker line means the body is not the file's
// text as written, so it is not scanned as code.
const TRANSFORMED = /\b(?:base64|b64decode|xxd|openssl)\b/;

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

// The file a marker line redirects to, read outside quotes.
function redirectTarget(line: string): string | undefined {
  const m = TARGET.exec(blankQuoted(line));
  const span = m?.indices?.[1] ?? m?.indices?.[2] ?? m?.indices?.[3];
  return span === undefined ? undefined : line.slice(span[0], span[1]);
}

const HEREDOC = /<<(-?)\s*(?:'([A-Za-z_]\w*)'|"([A-Za-z_]\w*)"|([A-Za-z_]\w*))/g;

// echo/printf of one quoted string straight into a file. A printf whose string
// holds a conversion is a format, not the text written, and is not read.
const QUOTED_WRITE =
  /\b(echo|printf)\s+(?:-[A-Za-z]+\s+)*(?:'([^']*)'|"((?:[^"\\]|\\.)*)")\s*>>?\s*(?:'([^']+)'|"([^"]+)"|([^\s'"|;&<>()]+))/g;

function writable(path: string): boolean {
  return !path.startsWith('/dev/') && !path.startsWith('&') && !path.startsWith('$(');
}

// Bounds on one command's extraction, so a long command cannot turn it into a
// cost the scan deadline never sees: at most this many heredoc markers are
// examined and payloads returned, and only the first MAX_COMMAND_CHARS of the
// command are read for quoted writes.
const MAX_HEREDOCS = 64;
const MAX_PAYLOADS = 32;
const MAX_COMMAND_CHARS = 256 * 1024;

export function bashWrittenPayloads(command: string): BashPayload[] {
  const out: BashPayload[] = [];
  // One pass: after a heredoc the search resumes past its body, so a marker
  // inside a body is text, not a second heredoc (as the shell reads it).
  const heredoc = new RegExp(HEREDOC.source, 'g');
  let seen = 0;
  for (let m = heredoc.exec(command); m !== null; m = heredoc.exec(command)) {
    if (++seen > MAX_HEREDOCS || out.length >= MAX_PAYLOADS) break;
    const delimiter = m[2] ?? m[3] ?? m[4];
    if (delimiter === undefined) continue;
    const lineStart = command.lastIndexOf('\n', m.index) + 1;
    let lineEnd = command.indexOf('\n', m.index);
    if (lineEnd === -1) lineEnd = command.length;
    const bodyStart = Math.min(lineEnd + 1, command.length);
    const stripTabs = m[1] === '-';
    // End of the body: the first line equal to the delimiter.
    let pos = bodyStart;
    let bodyEnd = command.length;
    let next = command.length;
    while (pos <= command.length) {
      let e = command.indexOf('\n', pos);
      if (e === -1) e = command.length;
      // A CRLF body ends its delimiter line with `\r`.
      const l = command.slice(pos, e > pos && command[e - 1] === '\r' ? e - 1 : e);
      if ((stripTabs ? l.replace(/^\t+/, '') : l) === delimiter) {
        bodyEnd = Math.max(pos - 1, bodyStart);
        next = Math.min(e + 1, command.length);
        break;
      }
      if (e === command.length) break;
      pos = e + 1;
    }
    heredoc.lastIndex = Math.max(next, heredoc.lastIndex);
    const markerLine = command.slice(lineStart, lineEnd);
    if (TRANSFORMED.test(markerLine)) continue;
    const path = redirectTarget(markerLine);
    if (path === undefined || !writable(path)) continue;
    const text = (bodyStart >= bodyEnd ? '' : command.slice(bodyStart, bodyEnd)).replace(/\r$/, '');
    if (text !== '') out.push({ path, text });
  }
  const head = command.length > MAX_COMMAND_CHARS ? command.slice(0, MAX_COMMAND_CHARS) : command;
  for (const m of head.matchAll(QUOTED_WRITE)) {
    if (out.length >= MAX_PAYLOADS) break;
    const text = m[2] ?? m[3];
    const path = m[4] ?? m[5] ?? m[6];
    if (m[1] === 'printf' && text?.replace(/%%/g, '').includes('%')) continue;
    if (text === undefined || text === '' || path === undefined || !writable(path)) continue;
    out.push({ path, text });
  }
  return out;
}
