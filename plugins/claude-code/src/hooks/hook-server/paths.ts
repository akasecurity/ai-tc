// Where the hook server's files live, free of the server's own side effects.
import { join } from 'node:path';

/** Owner-only, the mode the rest of ~/.aka is created with. */
export const RUN_DIR_MODE = 0o700;

/** The directory holding the socket, the log and the start lock. */
export function runDir(home: string): string {
  return join(home, '.aka', 'run');
}

/** One socket per plugin version, so an upgrade never talks to the old version's server. */
export function socketPath(home: string, pluginVersion: string): string {
  return join(runDir(home), `hook-${pluginVersion}.sock`);
}

export function logPath(home: string): string {
  return join(runDir(home), 'hook-server.log');
}

/** The start lock the client takes with `mkdir` so a burst of hooks starts one server. */
export function startLockPath(home: string, pluginVersion: string): string {
  return join(runDir(home), `hook-${pluginVersion}.starting`);
}
