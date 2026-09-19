// The launcher Chrome executes for the native-messaging host: a one-line script
// that execs a fixed argv and passes Chrome's own arguments through.

// Every argv entry is attacker-free but not syntax-free: each comes from an
// install location, which can hold characters the launcher's interpreter would
// act on. Wrapping in double quotes is not enough on either platform.
//
// POSIX sh still expands $, `…` and \ inside double quotes. Single quotes
// suppress all three, and the one character they cannot hold is escaped by
// closing the quote, emitting \' and reopening ('\'').
function posixQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

// cmd.exe expands %VAR% inside double quotes, and % is legal in a Windows path
// (a directory literally named `100%`), so a quoted path can still be rewritten
// before it reaches the program. `%%` is the batch-file escape for a literal %.
// A Windows path cannot contain " at all, so that case needs no handling.
function cmdQuote(value: string): string {
  return `"${value.replaceAll('%', '%%')}"`;
}

const POSIX_HEADER = '#!/bin/sh\n';
const CMD_HEADER = '@echo off\r\n';

export function launcherScript(argv: readonly string[], platform: NodeJS.Platform): string {
  if (platform === 'win32') {
    return `${CMD_HEADER}${argv.map(cmdQuote).join(' ')} %*\r\n`;
  }
  return `${POSIX_HEADER}exec ${argv.map(posixQuote).join(' ')} "$@"\n`;
}

// Splits a run of posixQuote'd words back into their values, or null when the
// run is not in that form.
function parsePosixWords(line: string): string[] | null {
  const words: string[] = [];
  let i = 0;
  while (i < line.length) {
    let word = '';
    let read = false;
    while (i < line.length && line[i] !== ' ') {
      if (line[i] === "'") {
        const end = line.indexOf("'", i + 1);
        if (end === -1) return null;
        word += line.slice(i + 1, end);
        i = end + 1;
      } else if (line.startsWith("\\'", i)) {
        word += "'";
        i += 2;
      } else {
        return null;
      }
      read = true;
    }
    if (!read) return null;
    words.push(word);
    i += 1;
  }
  return words;
}

// Splits a run of cmdQuote'd words back into their values, or null when the run
// is not in that form.
function parseCmdWords(line: string): string[] | null {
  const words: string[] = [];
  let i = 0;
  while (i < line.length) {
    if (line[i] !== '"') return null;
    const end = line.indexOf('"', i + 1);
    if (end === -1) return null;
    words.push(line.slice(i + 1, end).replaceAll('%%', '%'));
    i = end + 1;
    if (i < line.length) {
      if (line[i] !== ' ') return null;
      i += 1;
    }
  }
  return words;
}

// The argv a launcher written by `launcherScript` execs, read back from its
// text; null for any script that is not in that form. The form is recognised by
// its header rather than by the running platform, so either can be read anywhere.
export function parseLauncher(script: string): string[] | null {
  if (script.startsWith(POSIX_HEADER)) {
    const body = script.slice(POSIX_HEADER.length);
    const match = /^exec (.+) "\$@"\n$/.exec(body);
    const argv = match?.[1] === undefined ? null : parsePosixWords(match[1]);
    return argv === null || argv.length === 0 ? null : argv;
  }
  if (script.startsWith(CMD_HEADER)) {
    const body = script.slice(CMD_HEADER.length);
    const match = /^(.+) %\*\r\n$/.exec(body);
    const argv = match?.[1] === undefined ? null : parseCmdWords(match[1]);
    return argv === null || argv.length === 0 ? null : argv;
  }
  return null;
}
