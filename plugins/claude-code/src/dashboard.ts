/**
 * /aka:dashboard — launch the AKA web dashboard, mirroring the `aka dashboard`
 * CLI command.
 *
 *   node scripts/dashboard.js [--port N] [--no-open]
 *
 * The plugin ships as self-contained bundled scripts (no node_modules on the
 * user's machine), so it can't host the Next.js web-ui itself — that server is
 * bundled inside @akasecurity/cli. This launcher therefore delegates to the
 * `aka` CLI: it spawns `aka dashboard` DETACHED (a long-running server) so the
 * slash command returns immediately, then prints the local URL. Flags are
 * forwarded untouched, so `/aka:dashboard --port 5000` reaches the CLI.
 *
 * Fail-open: if the CLI isn't installed (or anything throws) it prints how to
 * get it and exits 0 — a slash command should never surface a stack trace.
 */
import { spawn, spawnSync } from 'node:child_process';

import { dashboardUrl, INSTALL_HINT, parsePort, startMessage } from './dashboard-launch.ts';

const args = process.argv.slice(2);

// Is the `aka` CLI reachable? Probe synchronously so we pick the right message
// before spawning the long-running server. ENOENT ⇒ it isn't on PATH.
function akaMissing(): boolean {
  const probe = spawnSync('aka', ['--help'], { stdio: 'ignore' });
  return probe.error !== undefined && (probe.error as NodeJS.ErrnoException).code === 'ENOENT';
}

try {
  if (akaMissing()) {
    process.stdout.write(`${INSTALL_HINT}\n`);
    process.exit(0);
  }

  // Detached + unref so the dashboard server outlives this short-lived launcher
  // (and the slash command returns at once). The CLI opens the browser when ready.
  const child = spawn('aka', ['dashboard', ...args], { detached: true, stdio: 'ignore' });
  // Swallow a late spawn failure rather than crashing with an unhandled 'error'
  // after we've already reported the URL — stay fail-open.
  child.on('error', () => {
    /* already probed for ENOENT; ignore any late failure */
  });
  child.unref();

  process.stdout.write(`${startMessage(dashboardUrl(parsePort(args)))}\n`);
  // No process.exit here: the unref'd child no longer holds the event loop open,
  // so this launcher drains and exits 0 on its own without killing the server.
} catch {
  process.stdout.write(`${INSTALL_HINT}\n`);
  process.exit(0);
}
