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

export function bashWrittenPayloads(command: string): BashPayload[] {
  const out: BashPayload[] = [];
  for (const m of command.matchAll(HEREDOC)) {
    const delimiter = m[2] ?? m[3] ?? m[4];
    if (delimiter === undefined || m.index === undefined) continue;
    const lineStart = command.lastIndexOf('\n', m.index) + 1;
    let lineEnd = command.indexOf('\n', m.index);
    if (lineEnd === -1) lineEnd = command.length;
    const line = command.slice(lineStart, lineEnd);
    const target = TARGET.exec(line);
    const path = target?.[1] ?? target?.[2] ?? target?.[3];
    if (path === undefined || !writable(path)) continue;
    const bodyStart = lineEnd + 1;
    const lines = command.slice(bodyStart).split('\n');
    const body: string[] = [];
    for (const l of lines) {
      if ((m[1] === '-' ? l.replace(/^\t+/, '') : l) === delimiter) break;
      body.push(l);
    }
    const text = body.join('\n');
    if (text !== '') out.push({ path, text });
  }
  for (const m of command.matchAll(QUOTED_WRITE)) {
    const text = m[1] ?? m[2];
    const path = m[3] ?? m[4] ?? m[5];
    if (text === undefined || text === '' || path === undefined || !writable(path)) continue;
    out.push({ path, text });
  }
  return out;
}
