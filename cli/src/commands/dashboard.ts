import { type ChildProcess, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { cliRecordedBy } from '@akasecurity/local-ops';
import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, dataDir } from '@akasecurity/plugin-sdk';

import { openUrl } from '../lib/open-url.ts';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));

// Is the port free to bind? Lets us print a friendly message instead of forwarding
// Next's raw EADDRINUSE (after which the readiness regex never fires and the
// command appears to hang).
function isPortFree(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = createServer();
    probe.once('error', () => {
      resolve(false);
    });
    probe.once('listening', () => {
      probe.close(() => {
        resolve(true);
      });
    });
    probe.listen(port, '127.0.0.1');
  });
}

// Refresh the available mirror from THIS binary's inventory before the server
// spawns — opening the dashboard IS the update check. Same rationale as
// `aka detections`: each read surface must self-record, or a machine where
// only the dashboard runs never learns what its binaries ship and the
// Detections page renders an honest-but-empty "update status unknown".
// recordInventory is signature-gated (steady state: one SELECT) and never
// modifies an installed pack. Best-effort BY CONTRACT: a locked or corrupt
// store must never block the dashboard launch (the web-ui reads what's there)
// — that fail-open branch is exactly what dashboard.test.ts pins, which is why
// this is an exported function rather than inline command code. The cause is
// surfaced so a persistent non-lock failure (corruption, a programming error)
// is debuggable instead of silently mislabeled as contention on every launch.
export function refreshUpdateMirror(dir: string): void {
  try {
    const db = openLocalDatabase(dir);
    try {
      db.installedPacks.recordInventory(bundledDetections(), cliRecordedBy());
    } finally {
      db.close();
    }
  } catch (err) {
    const cause = err instanceof Error && err.message !== '' ? `: ${err.message}` : '';
    process.stderr.write(
      `aka dashboard: could not refresh the detection-update mirror${cause} — launching anyway.\n`,
    );
  }
}

// `aka dashboard [--port N] [--no-open]` — launch the OSS web-ui against the local
// store and open the browser. The web-ui reads ~/.aka/data directly (no backend).
//
// Two paths:
//  - PUBLISHED CLI: a prebuilt Next "standalone" server is shipped inside the
//    package (web-ui/server.js, produced by release-cli.yml). Run it
//    directly; no build, no node_modules.
//  - DEV / from a checkout: resolve the @akasecurity/web-ui workspace
//    package and `next start` (building first if needed).
export async function runDashboard(argv: string[]): Promise<void> {
  const { values } = parseArgs({
    args: argv,
    // allowNegative so the documented `--no-open` flag parses (sets open=false)
    // instead of crashing with "Unknown option".
    options: { port: { type: 'string' }, open: { type: 'boolean' } },
    allowNegative: true,
  });
  const port = values.port ?? '4319';
  const shouldOpen = values.open !== false;
  const url = `http://localhost:${port}/security`;

  if (!(await isPortFree(Number(port)))) {
    process.stderr.write(
      `aka dashboard: port ${port} is already in use — pass a free one with --port <N>.\n`,
    );
    process.exitCode = 1;
    return;
  }

  // NOTE: `dashboard` has no --home flag today, so the default dataDir() is
  // correct — but `aka detections` threads --home through dataDir(home); if
  // dashboard ever grows the flag, this refresh must honor it too.
  refreshUpdateMirror(dataDir());

  // Bundled standalone server ships under <package>/web-ui/ (dist/ is one level
  // under the package root). Next's monorepo standalone keeps the app nested
  // (web-ui/server.js) alongside a bundled node_modules, so check both.
  const bundledServer = [
    join(here, '..', 'web-ui', 'server.js'),
    join(here, '..', 'web-ui', 'web-ui', 'server.js'),
  ].find((p) => existsSync(p));
  if (bundledServer) {
    launchStandalone(bundledServer, port, shouldOpen, url);
    return;
  }

  // Dev path: build (if needed) + start the workspace web-ui via Next.
  const webUiDir = dirname(require.resolve('@akasecurity/web-ui/package.json'));
  const nextBin = require.resolve('next/dist/bin/next', { paths: [webUiDir] });

  const startNext = (): void => {
    // Loopback-only, matching the standalone path's HOSTNAME pin — the web-ui
    // carries mutating server actions, so it must never bind all interfaces.
    const child = spawn(
      process.execPath,
      [nextBin, 'start', '--port', port, '--hostname', '127.0.0.1'],
      {
        cwd: webUiDir,
        stdio: ['inherit', 'pipe', 'inherit'],
      },
    );
    onReadyOpen(child, shouldOpen, url, `Starting the AKA dashboard at ${url}\n`);
  };

  if (existsSync(join(webUiDir, '.next', 'BUILD_ID'))) {
    startNext();
    return;
  }
  process.stdout.write('Building the web-ui (first run — this can take a minute)…\n');
  const build = spawn(process.execPath, [nextBin, 'build'], { cwd: webUiDir, stdio: 'inherit' });
  build.on('exit', (code) => {
    if (code !== 0) {
      process.stderr.write('aka dashboard: web-ui build failed\n');
      process.exitCode = code ?? 1;
      return;
    }
    startNext();
  });
}

// Run the prebuilt Next standalone server (a plain Node server that reads PORT
// from the environment). Inheriting the parent env is required so the child sees
// PATH etc.; PORT/HOSTNAME are overridden for this launch.
function launchStandalone(serverJs: string, port: string, shouldOpen: boolean, url: string): void {
  const child = spawn(process.execPath, [serverJs], {
    cwd: dirname(serverJs),
    stdio: ['inherit', 'pipe', 'inherit'],
    // Inherit the parent env so the child server sees PATH etc.; PORT/HOSTNAME tell
    // Next's standalone server where to bind (its only port input).
    // eslint-disable-next-line n/no-process-env
    env: { ...process.env, PORT: port, HOSTNAME: '127.0.0.1' },
  });
  onReadyOpen(child, shouldOpen, url, `Starting the AKA dashboard at ${url}\n`);
}

// Pipe a child server's stdout through, open the browser once it reports ready,
// and forward termination signals for a clean shutdown.
function onReadyOpen(child: ChildProcess, shouldOpen: boolean, url: string, banner: string): void {
  process.stdout.write(banner);
  let opened = false;
  child.stdout?.on('data', (chunk: Buffer) => {
    const text = chunk.toString();
    process.stdout.write(text);
    if (!opened && shouldOpen && /\bReady\b|started server|Listening|Local:/i.test(text)) {
      opened = true;
      openUrl(url);
    }
  });
  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, () => {
      child.kill(signal);
    });
  }
  child.on('exit', (code) => {
    process.exitCode = code ?? 0;
  });
}
