import { createRequire } from 'node:module';

// Re-invoking the running `aka` executable. A Node Single Executable Application
// (SEA) runs its EMBEDDED main and ignores argv[1] as a script path, so a
// self-spawn must pass a hidden subcommand — never the entry script — as the first
// argument. Under a plain `node dist/cli.js` launch the entry script is still
// required, so this returns the argv shape appropriate to the current runtime; the
// plain-node shape is byte-identical to the historical hand-built one.

const require = createRequire(import.meta.url);

// Whether this process is a Single Executable Application. `node:sea` exists on
// Node 21.7+; the import is guarded so a runtime without it (or a bundler that
// drops it) reports "not a SEA" rather than throwing at module load.
export function isSea(): boolean {
  try {
    const sea = require('node:sea') as { isSea?: () => boolean };
    return typeof sea.isSea === 'function' ? sea.isSea() : false;
  } catch {
    return false;
  }
}

export interface Reinvocation {
  command: string;
  args: string[];
}

// Pure argv builder — kept separate from the global reads so it is exhaustively
// testable across both runtimes without spawning or mocking `node:sea`.
export function buildReinvocation(
  sea: boolean,
  execPath: string,
  entry: string | undefined,
  subcommand: string,
  extraArgs: string[],
): Reinvocation | null {
  if (sea) return { command: execPath, args: [subcommand, ...extraArgs] };
  // Plain node: re-run the entry script, then the subcommand. Missing argv[1]
  // means we cannot self-spawn — callers treat null as "skip", exactly as before.
  if (entry === undefined) return null;
  return { command: execPath, args: [entry, subcommand, ...extraArgs] };
}

// Build the command + argv to re-invoke THIS executable at a hidden subcommand.
export function reinvokeArgv(subcommand: string, extraArgs: string[] = []): Reinvocation | null {
  return buildReinvocation(isSea(), process.execPath, process.argv[1], subcommand, extraArgs);
}
