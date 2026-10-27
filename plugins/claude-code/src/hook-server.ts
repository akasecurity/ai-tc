/**
 * The hook server: one long-lived process that runs hooks for the hook client
 * script (scripts/hook-client.sh) so each call does not start node and load the
 * hook bundle. The client starts it on demand and falls back to running the node
 * hook itself whenever it is not there, so a missing, crashed or stale server
 * costs only the speed. See hook-server/server.ts for the protocol and limits.
 *
 * Exits when idle, when the plugin files it runs are replaced, and after a long
 * run; the next hook call starts a fresh one.
 */
import { spawn } from 'node:child_process';
import { appendFileSync, mkdirSync, rmdirSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';

import { reuseScanners } from '@akasecurity/plugin-sdk';

import { version as PLUGIN_VERSION } from '../package.json';
import { postToolUseHandler, preToolUseHandler } from './hooks/hook-server/handlers.ts';
import {
  logPath,
  RUN_DIR_MODE,
  runDir,
  socketPath,
  startLockPath,
} from './hooks/hook-server/paths.ts';
import { scrubPresenceOnlyEnv } from './hooks/hook-server/request-env.ts';
import type { HookHandler } from './hooks/hook-server/server.ts';
import { startHookServer } from './hooks/hook-server/server.ts';
import { countFailOpen } from './hooks/shared.ts';
import { dropHeldGateway, reuseGateways } from './hooks/store-health.ts';

const IDLE_MS = 10 * 60_000;
const MAX_AGE_MS = 6 * 60 * 60_000;
const HANDLER_TIMEOUT_MS = 8_000;
const MAX_QUEUED = 16;
const READ_TIMEOUT_MS = 2_000;
const MAX_LOG_BYTES = 256 * 1024;

const home = homedir();
const log = (line: string): void => {
  try {
    const file = logPath(home);
    let size = 0;
    try {
      size = statSync(file).size;
    } catch {
      // No log yet.
    }
    const text = `${new Date().toISOString()} ${line.trim()}\n`;
    if (size > MAX_LOG_BYTES) writeFileSync(file, text, { mode: 0o600 });
    else appendFileSync(file, text, { mode: 0o600 });
  } catch {
    // A log that cannot be written is not a reason to stop serving.
  }
};

// The file this server is running from, to notice it being replaced in place.
const ownFile = fileURLToPath(import.meta.url);
const ownMtime = ((): number => {
  try {
    return statSync(ownFile).mtimeMs;
  } catch {
    return 0;
  }
})();
const isStale = (): boolean => {
  try {
    return statSync(ownFile).mtimeMs !== ownMtime;
  } catch {
    return true;
  }
};

const releaseStartLock = (): void => {
  try {
    rmdirSync(startLockPath(home, PLUGIN_VERSION));
  } catch {
    // Not taken, or already released.
  }
};

if (process.argv.includes('--daemonize')) {
  // Started from a hook's shell: run the server in a session of its own, so it
  // does not share the hook's process group.
  spawn(process.execPath, [ownFile], { detached: true, stdio: 'ignore' }).unref();
  process.exit(0);
}

process.on('uncaughtException', (error) => {
  log(`uncaught: ${error.message}`);
  process.exit(0);
});

try {
  mkdirSync(runDir(home), { recursive: true, mode: RUN_DIR_MODE });
  // The server starts from a hook's shell; keep that call's credential values out of its environment.
  scrubPresenceOnlyEnv();
  await reuseGateways(true);
  await reuseScanners(true);
  const handlers = new Map<string, HookHandler>([
    ['pre-tool-use', preToolUseHandler(log)],
    ['post-tool-use', postToolUseHandler(log)],
  ]);
  const running = await startHookServer({
    socketPath: socketPath(home, PLUGIN_VERSION),
    handlers,
    idleMs: IDLE_MS,
    maxAgeMs: MAX_AGE_MS,
    handlerTimeoutMs: HANDLER_TIMEOUT_MS,
    maxQueued: MAX_QUEUED,
    onFailOpen: countFailOpen,
    readTimeoutMs: READ_TIMEOUT_MS,
    isStale,
    dirMode: RUN_DIR_MODE,
    onExit: (reason) => {
      log(`exit: ${reason}`);
      releaseStartLock();
      void reuseScanners(false)
        .then(dropHeldGateway)
        .finally(() => {
          process.exit(0);
        });
    },
    log,
  });
  releaseStartLock();
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP'] as const) {
    process.on(signal, () => {
      void running.stop(signal);
    });
  }
} catch (error) {
  // Another server owns the socket, or the directory is not ours: nothing to serve.
  log(`not started: ${error instanceof Error ? error.message : 'error'}`);
  releaseStartLock();
  process.exit(0);
}
