import type { ChildProcess, SpawnOptions } from 'node:child_process';
import { spawn } from 'node:child_process';

/** The opener program and its argv for one platform. */
export interface OpenerCommand {
  readonly command: string;
  readonly args: readonly string[];
}

// Which program opens a URL, per platform. Pure and platform-taking rather than
// inlined in openUrl, so each branch is assertable without spawning anything —
// running the darwin branch for real means a browser window on the developer's
// machine, and the win32 branch cannot run off Windows at all.
//
// The win32 empty string is load-bearing: `start` reads a first quoted argument
// as the new console's TITLE, so `cmd /c start "<url>"` opens an empty window
// titled with the URL rather than opening the URL. The '' takes that slot.
//
// The win32 branch also carries a CONSTRAINT on the url it is given: cmd re-parses
// the command line, and node quotes a spawn argument only when it holds a space,
// a tab or a quote. So a cmd metacharacter — `&` above all, but also `|^<>` —
// arrives unquoted and SPLITS the command: `start "" http://h/p?a=1&b=2` opens
// `?a=1` and then runs `b=2`. Every caller today passes a url this repo built
// (`http://localhost:<port>/security`), which carries none of them. A caller that
// wants a query string has to escape for cmd here first.
export function openUrlCommand(platform: NodeJS.Platform, url: string): OpenerCommand {
  if (platform === 'darwin') return { command: 'open', args: [url] };
  if (platform === 'win32') return { command: 'cmd', args: ['/c', 'start', '', url] };
  return { command: 'xdg-open', args: [url] };
}

// Detached and stdio-free: the opener outlives `aka dashboard` (which is itself
// waiting on a server child), and it must not hold or write to the CLI's
// stdio — the caller is printing to the same terminal.
//
// Frozen because this one object is handed to every call: a spawn that mutated
// what it was given would otherwise change the options of every later openUrl
// in the process, silently dropping `detached` or letting the opener take over
// the CLI's stdio.
const DETACHED: SpawnOptions = Object.freeze({ stdio: 'ignore', detached: true });

/** Seams for the platform and the spawn, so the wiring is assertable off-host. */
export interface OpenUrlDeps {
  readonly platform?: NodeJS.Platform;
  readonly spawn?: (
    command: string,
    args: readonly string[],
    options: SpawnOptions,
  ) => ChildProcess;
}

// Open a URL in the user's default browser, cross-platform. Best-effort: a
// headless/SSH environment has no opener, so failures are swallowed (the URL is
// always printed too).
//
// Both failure modes are handled, and they arrive by different routes. A spawn
// that fails its argument checks throws synchronously and the try/catch takes
// it. A spawn whose PROGRAM does not exist — the headless case above, and the
// common one — does not throw at all: it returns a child that reports ENOENT as
// an asynchronous 'error' event, and an 'error' event with no listener is an
// uncaught exception. That would take down the whole command, which for
// `aka dashboard` means killing the parent from a live stdout handler with the
// server already up. The listener below is what makes "swallowed" true of the
// missing-opener case rather than only of the argument-error one.
export function openUrl(url: string, deps: OpenUrlDeps = {}): void {
  const { command, args } = openUrlCommand(deps.platform ?? process.platform, url);
  try {
    const child = (deps.spawn ?? spawn)(command, [...args], DETACHED);
    child.on('error', () => {
      // No opener available — the caller has already printed the URL.
    });
    child.unref();
  } catch {
    // No opener available — the caller has already printed the URL.
  }
}
