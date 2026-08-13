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

import { isBareCommandUnsupported, planBareCommand } from '@akasecurity/plugin-sdk/bare-command';

import {
  akaMissing,
  dashboardUrl,
  INSTALL_HINT,
  parsePort,
  startMessage,
  unsupportedArgvMessage,
} from './dashboard-launch.ts';

const args = process.argv.slice(2);

try {
  // Built before the probe and reused by it. The Windows half of this plan
  // resolves the bare name and picks the interpreter; doing that twice would let
  // the probe answer about a spawn the launch does not make.
  const plan = planBareCommand('aka', ['dashboard', ...args]);

  if (akaMissing(plan, (file, probeArgs, options) => spawnSync(file, [...probeArgs], options))) {
    process.stdout.write(`${INSTALL_HINT}\n`);
    process.exit(0);
  }

  // Detached + unref so the dashboard server outlives this short-lived launcher
  // (and the slash command returns at once). The CLI opens the browser when ready.
  const child = spawn(plan.file, [...plan.args], {
    detached: true,
    stdio: 'ignore',
    ...plan.options,
  });
  // Swallow a late spawn failure rather than crashing with an unhandled 'error'
  // after we've already reported the URL — stay fail-open.
  child.on('error', () => {
    /* already probed for ENOENT; ignore any late failure */
  });
  child.unref();

  process.stdout.write(`${startMessage(dashboardUrl(parsePort(args)))}\n`);
  // No process.exit here: the unref'd child no longer holds the event loop open,
  // so this launcher drains and exits 0 on its own without killing the server.
} catch (err) {
  // A forwarded flag the command interpreter cannot carry is not a missing CLI,
  // and INSTALL_HINT would send the user to install something they already have.
  // Every other failure stays fail-open on INSTALL_HINT, exactly as before.
  process.stdout.write(
    `${isBareCommandUnsupported(err) ? unsupportedArgvMessage(err.reason) : INSTALL_HINT}\n`,
  );
  process.exit(0);
}
