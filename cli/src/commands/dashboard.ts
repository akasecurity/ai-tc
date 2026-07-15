import { type ChildProcess, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createServer } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

import { cliRecordedBy, isSea, reinvokeArgv } from '@akasecurity/local-ops';
import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, dataDir } from '@akasecurity/plugin-sdk';

import { openUrl } from '../lib/open-url.ts';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));

// The package root that ships the bundled web-ui. Under a plain-node launch it is
// one level above dist/ (this module's dir). A SEA binary has no source dir, so it
// is the directory holding the executable, where release packaging places web-ui/.
function pkgBase(): string {
  return isSea() ? dirname(process.execPath) : join(here, '..');
}

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
  const base = pkgBase();
  const bundledServer = [
    join(base, 'web-ui', 'server.js'),
    join(base, 'web-ui', 'web-ui', 'server.js'),
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
// from the environment). A SEA binary cannot spawn `server.js` as a script — it
// would re-run the embedded CLI main — so route through the hidden
// `__dashboard-server` subcommand, which requires the server IN-PROCESS in the
// child. On plain node the effect is identical: a child process serving the
// dashboard, with browser-open + signal forwarding handled by onReadyOpen.
function launchStandalone(serverJs: string, port: string, shouldOpen: boolean, url: string): void {
  const reinvoke = reinvokeArgv('__dashboard-server', ['--server-js', serverJs]);
  if (!reinvoke) {
    process.stderr.write('aka dashboard: cannot resolve the CLI entry to launch the server.\n');
    process.exitCode = 1;
    return;
  }
  const child = spawn(reinvoke.command, reinvoke.args, {
    cwd: dirname(serverJs),
    stdio: ['inherit', 'pipe', 'inherit'],
    // Inherit the parent env so the child server sees PATH etc.; PORT/HOSTNAME tell
    // Next's standalone server where to bind (its only port input).
    // eslint-disable-next-line n/no-process-env
    env: { ...process.env, PORT: port, HOSTNAME: '127.0.0.1' },
  });
  onReadyOpen(child, shouldOpen, url, `Starting the AKA dashboard at ${url}\n`);
}

// The hidden `__dashboard-server` command: boot the prebuilt Next standalone server
// IN-PROCESS. Spawned by launchStandalone with cwd = the server's dir and PORT/HOSTNAME
// already in the env (the server's only bind inputs). Loading it in-process — rather
// than running it as a child script — is what lets a SEA binary (which cannot exec an
// arbitrary script) serve the dashboard; on plain node the behavior is unchanged.
// Next's standalone server.js is an ESM module with no `require.main` guard: importing
// it evaluates its top level, which starts the server (kept alive by its listen socket).
// A dynamic import by file URL resolves without relying on this module's on-disk
// location — which a SEA does not have.
export async function runDashboardServer(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: { 'server-js': { type: 'string' } } });
  const serverJs = values['server-js'];
  if (serverJs === undefined || serverJs === '') {
    process.stderr.write('aka __dashboard-server: --server-js <path> is required\n');
    process.exitCode = 1;
    return;
  }
  await import(pathToFileURL(serverJs).href);
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
