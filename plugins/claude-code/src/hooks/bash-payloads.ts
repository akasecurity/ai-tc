// The file contents a Bash command writes, so they can be scanned as the code
// they are. A command line is not source: code_flaw rules skip a `tool_use`
// capture (see ruleApplies in the detections engine), and what the command
// writes (a heredoc into a file, a quoted echo/printf into a file) is scanned
// separately as a `code_change` under the file it names, so extension-scoped
// rules apply to it.
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
const TARGET = /(?:(?<![0-9&>])>>?|\btee\s+(?:-a\s+)?)\s*(?:'([^']+)'|"([^"]+)"|([^\s'"|;&<>()]+))/;

const HEREDOC = /<<(-?)\s*(?:'([A-Za-z_]\w*)'|"([A-Za-z_]\w*)"|([A-Za-z_]\w*))/g;

// echo/printf of one quoted string straight into a file.
const QUOTED_WRITE =
  /\b(?:echo|printf)\s+(?:-[A-Za-z]+\s+)*(?:'([^']*)'|"((?:[^"\\]|\\.)*)")\s*>>?\s*(?:'([^']+)'|"([^"]+)"|([^\s'"|;&<>()]+))/g;

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
      const l = command.slice(pos, e);
      if ((stripTabs ? l.replace(/^\t+/, '') : l) === delimiter) {
        bodyEnd = Math.max(pos - 1, bodyStart);
        next = Math.min(e + 1, command.length);
        break;
      }
      if (e === command.length) break;
      pos = e + 1;
    }
    heredoc.lastIndex = Math.max(next, heredoc.lastIndex);
    const target = TARGET.exec(command.slice(lineStart, lineEnd));
    const path = target?.[1] ?? target?.[2] ?? target?.[3];
    if (path === undefined || !writable(path)) continue;
    const text = bodyStart >= bodyEnd ? '' : command.slice(bodyStart, bodyEnd);
    if (text !== '') out.push({ path, text });
  }
  const head = command.length > MAX_COMMAND_CHARS ? command.slice(0, MAX_COMMAND_CHARS) : command;
  for (const m of head.matchAll(QUOTED_WRITE)) {
    if (out.length >= MAX_PAYLOADS) break;
    const text = m[1] ?? m[2];
    const path = m[3] ?? m[4] ?? m[5];
    if (text === undefined || text === '' || path === undefined || !writable(path)) continue;
    out.push({ path, text });
  }
  return out;
}
